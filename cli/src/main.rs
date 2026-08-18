//! Command-line client for the zkasper Solana verifier.
//!
//! Drives a real cluster (usually `solana-test-validator`) with the fixture
//! proofs. See `scripts/demo.sh`.
//!
//! ```text
//! zkasper-cli <rpc-url> <keypair.json> init             <fixtures-dir>
//! zkasper-cli <rpc-url> <keypair.json> submit           <fixtures-dir> <index>
//! zkasper-cli <rpc-url> <keypair.json> show
//! zkasper-cli <rpc-url> <keypair.json> assert-finalized <epoch> <root-hex>
//! zkasper-cli <rpc-url> <keypair.json> assert-anchored  <state-root-hex>
//! ```

use std::process::exit;

use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::Transaction;

use zkasper_solana_program::instruction as ix;
use zkasper_solana_program::state::{light_client_address, LightClientState, VK_LEN};
use zkasper_solana_program::wire::FinalizationOutput;

/// Measured at 99,033 units for the whole transaction; this leaves headroom
/// without overpaying for priority.
const COMPUTE_UNIT_LIMIT: u32 = 130_000;

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

fn a32(buf: &[u8], off: usize) -> [u8; 32] {
    buf[off..off + 32].try_into().unwrap()
}

fn parse_root(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s.trim_start_matches("0x")).unwrap_or_else(|e| die(&e.to_string()));
    bytes
        .try_into()
        .unwrap_or_else(|_| die("expected 32 bytes"))
}

fn send(client: &RpcClient, payer: &Keypair, instruction: Instruction) {
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
        Ok(sig) => println!("ok {sig}"),
        Err(e) => die(&e.to_string()),
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
            let dir = args.get(3).map(String::as_str).unwrap_or("fixtures");
            let blob = std::fs::read(format!("{dir}/bootstrap.bin"))
                .unwrap_or_else(|e| die(&format!("{dir}/bootstrap.bin: {e}")));
            let vk: [u8; VK_LEN] = blob[136..136 + VK_LEN].try_into().unwrap();
            send(
                &client,
                &payer,
                ix::initialize(
                    &program_id,
                    &authority,
                    &a32(&blob, 0),
                    &a32(&blob, 32),
                    u64::from_le_bytes(blob[64..72].try_into().unwrap()),
                    &a32(&blob, 72),
                    &a32(&blob, 104),
                    &vk,
                ),
            );
        }
        "submit" => {
            let dir = args.get(3).map(String::as_str).unwrap_or("fixtures");
            let index = args.get(4).map(String::as_str).unwrap_or("0");
            let path = format!("{dir}/finalization_{index}.bin");
            let blob = std::fs::read(&path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
            let output = FinalizationOutput {
                accumulator_commitment: a32(&blob, 256),
                finalized_epoch: u64::from_le_bytes(blob[288..296].try_into().unwrap()),
                finalized_root: a32(&blob, 296),
                finalized_state_root: a32(&blob, 328),
            };
            println!("submitting epoch {}", output.finalized_epoch);
            send(
                &client,
                &payer,
                ix::submit_finalization(
                    &program_id,
                    &authority,
                    &payer.pubkey(),
                    blob[0..64].try_into().unwrap(),
                    blob[64..192].try_into().unwrap(),
                    blob[192..256].try_into().unwrap(),
                    &output,
                ),
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
            println!("  last changed epoch {}", state.accumulator_epoch);
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
