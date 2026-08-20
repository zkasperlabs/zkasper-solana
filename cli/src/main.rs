//! Command-line client for the zkasper Solana verifier.
//!
//! Drives a real cluster (usually `solana-test-validator`) with the fixture
//! proofs. See `scripts/demo.sh`.
//!
//! ```text
//! zkasper-cli <rpc-url> <keypair.json> init             <wrap.json>
//! zkasper-cli <rpc-url> <keypair.json> stage            <wrap.json>
//! zkasper-cli <rpc-url> <keypair.json> submit           <wrap.json>
//! zkasper-cli <rpc-url> <keypair.json> close-buffer
//! zkasper-cli <rpc-url> <keypair.json> show
//! zkasper-cli <rpc-url> <keypair.json> assert-finalized <epoch> <root-hex>
//! zkasper-cli <rpc-url> <keypair.json> assert-anchored  <state-root-hex>
//! ```
//!
//! A submission is `stage` then `submit`: the proof is 768 bytes and does not
//! fit a packet beside the output it attests to.
//!
//! `submit` also writes a *posting record* — the object `docs/api-v1.md` in the
//! zkasper repository calls `posting` — to stdout, and appends it to the file
//! named by `ZKASPER_POSTINGS` when that is set. That file is how the daemon
//! learns a proof reached a chain, so the website can show the transaction
//! rather than assert it.

use std::process::exit;

use solana_client::rpc_client::RpcClient;
use solana_client::rpc_request::RpcRequest;
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::Transaction;

use serde_json::{json, Value};

use zkasper_solana_program::instruction as ix;
use zkasper_solana_program::plonk::PROOF_LEN;
use zkasper_solana_program::state::{light_client_address, LightClientState};
use zkasper_solana_program::wire::{FinalizationOutput, FINALIZATION_PUBLIC_BYTES};

/// A submission measures 481,004 units for the whole transaction; this leaves
/// headroom without overpaying for a limit the runtime reserves block space
/// against. Staging costs 4,872 and rides the same limit.
const COMPUTE_UNIT_LIMIT: u32 = 700_000;

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    exit(1)
}

fn read_keypair(path: &str) -> Keypair {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
    let bytes: Vec<u8> = text
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|s| {
            s.trim()
                .parse()
                .unwrap_or_else(|_| die("malformed keypair file"))
        })
        .collect();
    Keypair::try_from(bytes.as_slice()).unwrap_or_else(|_| die("keypair must be 64 bytes"))
}

/// One hex field of a `cargo-zisk wrap --plonk` artifact.
fn wrap_field(raw: &str, name: &str) -> Vec<u8> {
    let at = raw
        .find(name)
        .unwrap_or_else(|| die(&format!("no {name} in the wrap artifact")))
        + name.len();
    let rest = &raw[at..];
    let start = rest.find("0x").unwrap_or_else(|| die("expected hex")) + 2;
    let end = rest[start..]
        .find('"')
        .unwrap_or_else(|| die("unterminated hex"))
        + start;
    hex::decode(&rest[start..end]).unwrap_or_else(|e| die(&e.to_string()))
}

struct Wrap {
    program_vk: [u8; 32],
    proof: [u8; PROOF_LEN],
    output: FinalizationOutput,
}

fn read_wrap(path: &str) -> Wrap {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
    let publics = wrap_field(&raw, "publicValues");
    let head: [u8; FINALIZATION_PUBLIC_BYTES] = publics
        .get(..FINALIZATION_PUBLIC_BYTES)
        .and_then(|s| s.try_into().ok())
        .unwrap_or_else(|| die("publicValues is shorter than one finalization output"));
    Wrap {
        program_vk: wrap_field(&raw, "programVK")
            .try_into()
            .unwrap_or_else(|_| die("programVK must be 32 bytes")),
        proof: wrap_field(&raw, "proofBytes")
            .try_into()
            .unwrap_or_else(|_| die("proofBytes must be 768 bytes")),
        output: FinalizationOutput::from_public_bytes(&head),
    }
}

fn parse_root(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s.trim_start_matches("0x")).unwrap_or_else(|e| die(&e.to_string()));
    bytes
        .try_into()
        .unwrap_or_else(|_| die("expected 32 bytes"))
}

fn send(client: &RpcClient, payer: &Keypair, instruction: Instruction) -> String {
    let blockhash = client
        .get_latest_blockhash()
        .unwrap_or_else(|e| die(&e.to_string()));
    let tx = Transaction::new_signed_with_payer(
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(COMPUTE_UNIT_LIMIT),
            instruction,
        ],
        Some(&payer.pubkey()),
        &[payer],
        blockhash,
    );
    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => {
            println!("ok {sig}");
            sig.to_string()
        }
        Err(e) => die(&e.to_string()),
    }
}

/// Which Solana cluster the RPC is on, taken from its genesis hash rather than
/// from the URL, so a posting cannot claim a chain it did not land on.
fn cluster(client: &RpcClient) -> &'static str {
    match client.get_genesis_hash().map(|h| h.to_string()).as_deref() {
        Ok("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d") => "mainnet-beta",
        Ok("EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG") => "devnet",
        Ok("4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY") => "testnet",
        _ => "localnet",
    }
}

/// The confirmed transaction, once the RPC will serve it. `send_and_confirm`
/// returns before the ledger is queryable, so this polls.
fn receipt(client: &RpcClient, signature: &str) -> Value {
    for _ in 0..30 {
        let result: Result<Value, _> = client.send(
            RpcRequest::GetTransaction,
            json!([
                signature,
                { "encoding": "json", "commitment": "confirmed", "maxSupportedTransactionVersion": 0 }
            ]),
        );
        match result {
            Ok(Value::Null) | Err(_) => std::thread::sleep(std::time::Duration::from_secs(1)),
            Ok(value) => return value,
        }
    }
    die(&format!("{signature} never became queryable"))
}

fn u64_at(value: &Value, path: &[&str]) -> u64 {
    let mut node = value;
    for key in path {
        node = &node[key];
    }
    node.as_u64().unwrap_or_default()
}

/// What the submission cost and where it landed, as one line of JSON.
///
/// `fee_lamports` is the transaction fee. `rent_lamports` is what the payer
/// left behind as the rent-exempt balance of the finalization and anchor
/// records, which is the larger number and is not refundable. The staging
/// buffer's rent is refundable — `close-buffer` — and is not counted here, but
/// the staging transaction's own fee is not part of this number either.
/// Reporting only the fee would make the posting cheaper than it is.
fn posting(client: &RpcClient, signature: &str, output: &FinalizationOutput) -> String {
    let tx = receipt(client, signature);
    let meta = &tx["meta"];
    let fee = u64_at(meta, &["fee"]);
    let spent = match (
        meta["preBalances"][0].as_u64(),
        meta["postBalances"][0].as_u64(),
    ) {
        (Some(pre), Some(post)) => pre.saturating_sub(post),
        _ => fee,
    };
    let cluster = cluster(client);
    let query = if cluster == "mainnet-beta" {
        String::new()
    } else {
        format!("?cluster={cluster}")
    };
    json!({
        "chain": format!("solana-{cluster}"),
        "cluster": cluster,
        "program": zkasper_solana_program::id().to_string(),
        "epoch": output.finalized_epoch,
        "finalized_root": format!("0x{}", hex::encode(output.finalized_root)),
        "finalized_state_root": format!("0x{}", hex::encode(output.finalized_state_root)),
        "signature": signature,
        "slot": u64_at(&tx, &["slot"]),
        "compute_units": u64_at(meta, &["computeUnitsConsumed"]),
        "fee_lamports": fee,
        "rent_lamports": spent.saturating_sub(fee),
        "lamports_spent": spent,
        "status": if meta["err"].is_null() { "confirmed" } else { "failed" },
        "explorer": format!("https://explorer.solana.com/tx/{signature}{query}"),
        "unix_millis": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or_default(),
    })
    .to_string()
}

/// Prints the posting record, and appends it to `$ZKASPER_POSTINGS` when set.
fn record_posting(line: &str) {
    println!("{line}");
    let Ok(path) = std::env::var("ZKASPER_POSTINGS") else {
        return;
    };
    let appended = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, format!("{line}\n").as_bytes()));
    if let Err(e) = appended {
        die(&format!("{path}: {e}"));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 {
        die("usage: zkasper-cli <rpc-url> <keypair.json> <command> [args...]");
    }
    let client = RpcClient::new_with_commitment(args[0].clone(), CommitmentConfig::confirmed());
    let payer = read_keypair(&args[1]);
    let program_id = zkasper_solana_program::id();
    let authority = payer.pubkey();

    match args[2].as_str() {
        "init" => {
            let path = args
                .get(3)
                .map(String::as_str)
                .unwrap_or("fixtures/wrap-469426.json");
            let wrap = read_wrap(path);
            // Bootstrap one epoch below the proof, on the accumulator it starts
            // from, so the demo has something the proof can advance. A real
            // deployment takes these from a checkpoint the operator trusts.
            send(
                &client,
                &payer,
                ix::initialize(
                    &program_id,
                    &authority,
                    &wrap.output.accumulator_commitment,
                    &[0u8; 32],
                    wrap.output.finalized_epoch - 1,
                    &[0u8; 32],
                    &wrap.program_vk,
                ),
            );
        }
        "stage" => {
            let path = args
                .get(3)
                .map(String::as_str)
                .unwrap_or("fixtures/wrap-469426.json");
            let wrap = read_wrap(path);
            send(
                &client,
                &payer,
                ix::stage_proof(&program_id, &payer.pubkey(), &wrap.proof),
            );
        }
        "submit" => {
            let path = args
                .get(3)
                .map(String::as_str)
                .unwrap_or("fixtures/wrap-469426.json");
            let wrap = read_wrap(path);
            println!("submitting epoch {}", wrap.output.finalized_epoch);
            let signature = send(
                &client,
                &payer,
                ix::submit_finalization(&program_id, &authority, &payer.pubkey(), &wrap.output),
            );
            record_posting(&posting(&client, &signature, &wrap.output));
        }
        "close-buffer" => {
            send(
                &client,
                &payer,
                ix::close_proof_buffer(&program_id, &payer.pubkey()),
            );
        }
        "show" => {
            let (address, _) = light_client_address(&program_id, &authority);
            let data = client
                .get_account_data(&address)
                .unwrap_or_else(|e| die(&format!("{address}: {e}")));
            let state = LightClientState::unpack(&data).unwrap_or_else(|e| die(&format!("{e:?}")));
            println!("light client   {address}");
            println!("authority      {}", state.authority);
            println!("finalized      epoch {}", state.finalized_epoch);
            println!("  block root   0x{}", hex::encode(state.finalized_root));
            println!("  state root   0x{}", hex::encode(state.latest_state_root));
            println!(
                "accumulator    0x{}",
                hex::encode(state.accumulator_commitment)
            );
            println!(
                "  of epoch     {} (the next proof must finalize it)",
                state.accumulator_epoch
            );
            println!("guest vk       0x{}", hex::encode(state.program_vk));
            println!("submissions    {}", state.submission_count);
        }
        "assert-finalized" => {
            let epoch: u64 = args
                .get(3)
                .unwrap_or_else(|| die("expected <epoch>"))
                .parse()
                .unwrap_or_else(|_| die("epoch must be a number"));
            let root = parse_root(args.get(4).unwrap_or_else(|| die("expected <root-hex>")));
            send(
                &client,
                &payer,
                ix::assert_finalized(&program_id, &authority, epoch, &root),
            );
        }
        "assert-anchored" => {
            let root = parse_root(
                args.get(3)
                    .unwrap_or_else(|| die("expected <state-root-hex>")),
            );
            send(
                &client,
                &payer,
                ix::assert_anchored(&program_id, &authority, &root),
            );
        }
        "address" => {
            let (address, bump) = light_client_address(&program_id, &authority);
            println!("program  {program_id}");
            println!("state    {address} (bump {bump})");
        }
        other => die(&format!("unknown command: {other}")),
    }
}
