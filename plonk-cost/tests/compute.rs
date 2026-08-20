//! What a Zisk PLONK wrap costs on Solana, measured in LiteSVM.
//!
//! Run with `--nocapture` to see the table. The numbers are whole-transaction
//! totals, so each includes 150 units for the `ComputeBudget` instruction and
//! the entrypoint's own deserialization; [`Mode::BASELINE`] carries all of that
//! and nothing else, and every line below it is quoted net of it.

use litesvm::LiteSVM;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

const SO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/deploy/zkasper_plonk_cost.so"
);

const BASELINE: u8 = 0;
const VERIFY: u8 = 1;
const G1_MUL: u8 = 2;
const G1_ADD: u8 = 3;
const PAIRING: u8 = 4;
const FR_MUL: u8 = 5;
const FR_INV: u8 = 6;
const TRANSCRIPT: u8 = 7;
const WELL_FORMED: u8 = 8;
const PUBLIC_INPUT: u8 = 9;
const VERIFY_NO_MEMBERSHIP: u8 = 10;

fn fixture() -> (Vec<u8>, Vec<u8>) {
    let raw = include_str!("wrap-469426.json");
    let field = |name: &str| -> Vec<u8> {
        let at = raw.find(name).expect("field") + name.len();
        let rest = &raw[at..];
        let start = rest.find("0x").expect("hex") + 2;
        let end = rest[start..].find('"').expect("close") + start;
        hex::decode(&rest[start..end]).expect("hex")
    };
    let public_values = field("publicValues");
    (field("proofBytes"), public_values[..176].to_vec())
}

struct Harness {
    svm: LiteSVM,
    payer: Keypair,
    program_id: Pubkey,
    payload: Vec<u8>,
}

impl Harness {
    fn new() -> Self {
        let so = std::fs::read(SO).unwrap_or_else(|e| {
            panic!("{SO}: {e}\nbuild it with cargo-build-sbf --manifest-path plonk-cost/Cargo.toml --arch v3")
        });
        let program_id = Pubkey::new_from_array([9u8; 32]);
        // Mainnet's feature set, not LiteSVM's default (which activates none):
        // `sol_big_mod_exp` is feature-gated and unregistered without it.
        let mut svm = LiteSVM::new().with_mainnet_features();
        svm.add_program(program_id, &so).unwrap();
        let payer = Keypair::new_from_array([7u8; 32]);
        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
        let (proof, publics) = fixture();
        let mut payload = publics;
        payload.extend_from_slice(&proof);
        Self {
            svm,
            payer,
            program_id,
            payload,
        }
    }

    fn transaction(&self, mode: u8, count: u16) -> Transaction {
        let mut data = vec![mode];
        data.extend_from_slice(&count.to_le_bytes());
        data.extend_from_slice(&self.payload);
        let ixs = [
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            Instruction {
                program_id: self.program_id,
                accounts: vec![],
                data,
            },
        ];
        let msg = Message::new_with_blockhash(
            &ixs,
            Some(&self.payer.pubkey()),
            &self.svm.latest_blockhash(),
        );
        Transaction::new(&[&self.payer], msg, self.svm.latest_blockhash())
    }

    fn run(&mut self, mode: u8, count: u16) -> u64 {
        let tx = self.transaction(mode, count);
        let meta = self.svm.send_transaction(tx).unwrap_or_else(|e| {
            panic!(
                "mode {mode} count {count}: {:?}\n{}",
                e.err,
                e.meta.logs.join("\n")
            )
        });
        self.svm.expire_blockhash();
        meta.compute_units_consumed
    }
}

#[test]
fn what_a_plonk_wrap_costs_to_verify() {
    let mut h = Harness::new();

    let baseline = h.run(BASELINE, 0);
    let verify = h.run(VERIFY, 0);
    let verify_lean = h.run(VERIFY_NO_MEMBERSHIP, 0);

    // Marginal costs: two loop counts, so the loop's own overhead cancels.
    let mul_1 = h.run(G1_MUL, 1);
    let mul_11 = h.run(G1_MUL, 11);
    let add_1 = h.run(G1_ADD, 1);
    let add_11 = h.run(G1_ADD, 11);
    let pairing = h.run(PAIRING, 0);
    let fr_mul_10 = h.run(FR_MUL, 10);
    let fr_mul_110 = h.run(FR_MUL, 110);
    let fr_inv_1 = h.run(FR_INV, 1);
    let fr_inv_11 = h.run(FR_INV, 11);
    let transcript = h.run(TRANSCRIPT, 0);
    let well_formed = h.run(WELL_FORMED, 0);
    let public_input = h.run(PUBLIC_INPUT, 0);

    let per_mul = (mul_11 - mul_1) / 10;
    let per_add = (add_11 - add_1) / 10;
    let per_fr_mul = (fr_mul_110 - fr_mul_10) / 100;
    let per_fr_inv = (fr_inv_11 - fr_inv_1) / 10;

    println!("\ncompute units, whole transaction");
    println!("  baseline (parse only)      {baseline:>9}");
    println!("  FULL PLONK VERIFY          {verify:>9}");
    println!("  without checkProofData     {verify_lean:>9}");
    println!("\nnet of baseline");
    println!("  full verify                {:>9}", verify - baseline);
    println!("  transcript, 6 keccaks      {:>9}", transcript - baseline);
    println!("  checkProofData             {:>9}", well_formed - baseline);
    println!(
        "  public input, 1 sha256     {:>9}",
        public_input - baseline
    );
    println!("  one 2-pair pairing         {:>9}", pairing - baseline);
    println!("\nmarginal, per operation");
    println!("  alt_bn128 G1 mul           {per_mul:>9}   (table: 3840)");
    println!("  alt_bn128 G1 add           {per_add:>9}   (table:  334)");
    println!("  Fr mul, software           {per_fr_mul:>9}");
    println!("  Fr inversion, software     {per_fr_inv:>9}");

    const SYSCALL_FLOOR: u64 = 18 * 3_840 + 18 * 334 + 36_364 + 12_121;
    println!("\n  BN254 syscall floor        {SYSCALL_FLOOR:>9}");
    println!(
        "  everything else            {:>9}",
        verify.saturating_sub(SYSCALL_FLOOR)
    );

    let size = bincode::serialized_size(&h.transaction(VERIFY, 0)).unwrap();
    println!("\n  serialized transaction     {size:>9} bytes (packet limit 1232)");

    assert!(
        verify > baseline,
        "the verification did no work: {verify} vs {baseline}"
    );
    assert!(
        verify < 1_400_000,
        "a PLONK verification does not fit one transaction: {verify}"
    );
}

/// Whether a PLONK submission fits the 200,000-unit default, the way the
/// Groth16 one does at 86,699.
#[test]
fn behaviour_under_the_default_compute_budget() {
    let mut h = Harness::new();
    let tx = {
        let mut data = vec![VERIFY, 0, 0];
        data.extend_from_slice(&h.payload);
        let ix = Instruction {
            program_id: h.program_id,
            accounts: vec![],
            data,
        };
        let msg =
            Message::new_with_blockhash(&[ix], Some(&h.payer.pubkey()), &h.svm.latest_blockhash());
        Transaction::new(&[&h.payer], msg, h.svm.latest_blockhash())
    };
    match h.svm.send_transaction(tx) {
        Ok(meta) => println!(
            "a PLONK verification fits the 200,000-unit default: {} units",
            meta.compute_units_consumed
        ),
        Err(e) => println!(
            "a PLONK verification exceeds the 200,000-unit default, so every \
             submitter must raise it: {:?}",
            e.err
        ),
    }
}

/// Whether a PLONK submission fits a legacy transaction.
///
/// `submit_finalization` names five accounts — payer, light-client state, the
/// finalization record, the anchor record and the system program — and with the
/// program and `ComputeBudget` that is seven keys in the message. Only the
/// instruction data changes between proof systems, so the envelope is measured
/// once and the three data lengths are priced against it.
#[test]
fn what_a_submission_would_weigh() {
    let payer = Keypair::new_from_array([7u8; 32]);
    let program_id = Pubkey::new_from_array([9u8; 32]);
    let size_of = |data_len: usize| -> u64 {
        let ix = Instruction {
            program_id,
            accounts: vec![
                solana_instruction::AccountMeta::new(payer.pubkey(), true),
                solana_instruction::AccountMeta::new(Pubkey::new_from_array([1u8; 32]), false),
                solana_instruction::AccountMeta::new(Pubkey::new_from_array([2u8; 32]), false),
                solana_instruction::AccountMeta::new(Pubkey::new_from_array([3u8; 32]), false),
                solana_instruction::AccountMeta::new_readonly(
                    Pubkey::new_from_array([4u8; 32]),
                    false,
                ),
            ],
            data: vec![0u8; data_len],
        };
        let msg = Message::new_with_blockhash(
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                ix,
            ],
            Some(&payer.pubkey()),
            &Default::default(),
        );
        bincode::serialized_size(&Transaction::new(&[&payer], msg, Default::default())).unwrap()
    };

    let envelope = size_of(0);
    println!("\n  transaction envelope, 7 keys and a CU limit  {envelope:>5} bytes");
    for (what, data) in [
        ("Groth16, 136-byte output   ", 393usize),
        ("Groth16, 176-byte output   ", 433),
        ("PLONK,   176-byte output   ", 1 + 768 + 176),
    ] {
        let total = size_of(data);
        println!(
            "  {what}{data:>5} bytes of data -> {total:>5} bytes  {}",
            if total <= 1232 { "fits" } else { "OVER 1232" }
        );
    }

    assert!(
        size_of(433) <= 1232,
        "the Groth16 submission stopped fitting"
    );
    assert!(
        size_of(1 + 768 + 176) > 1232,
        "a PLONK submission now fits a legacy transaction; the blocker is gone"
    );
}
