//! What a Zisk PLONK wrap costs to verify on Solana, measured in LiteSVM.
//!
//! Run with `--nocapture` to see the table. The numbers are whole-transaction
//! totals, so each includes 150 units for the `ComputeBudget` instruction and
//! the entrypoint's own deserialization; `BASELINE` carries all of that and
//! nothing else, and every line below it is quoted net of it.
//!
//! The verifier under measurement is the one the program runs — this crate
//! depends on it rather than copying it — so `VERIFY` here and
//! `submit_finalization` in `zkasper-program-tests` differ only by the account
//! bookkeeping.

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
const VERIFY_WITH_MEMBERSHIP: u8 = 10;
const G1_DECOMPRESS: u8 = 11;

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
        // Mainnet's feature set, not LiteSVM's default (which activates none).
        let mut svm = LiteSVM::new().with_mainnet_features();
        svm.add_program(program_id, &so).unwrap();
        let payer = Keypair::new_from_array([7u8; 32]);
        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();

        let f = zkasper_program_tests::fixture();
        let mut payload = f.program_vk.to_vec();
        payload.extend_from_slice(&f.output.public_bytes());
        payload.extend_from_slice(&f.proof);
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
    let verify_guarded = h.run(VERIFY_WITH_MEMBERSHIP, 0);

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
    let decompress_1 = h.run(G1_DECOMPRESS, 1);
    let decompress_11 = h.run(G1_DECOMPRESS, 11);

    let per_mul = (mul_11 - mul_1) / 10;
    let per_add = (add_11 - add_1) / 10;
    let per_fr_mul = (fr_mul_110 - fr_mul_10) / 100;
    let per_fr_inv = (fr_inv_11 - fr_inv_1) / 10;
    let per_decompress = (decompress_11 - decompress_1) / 10;

    println!("\ncompute units, whole transaction");
    println!("  baseline (parse only)      {baseline:>9}");
    println!("  PLONK VERIFY, as shipped   {verify:>9}");
    println!("  with checkProofData        {verify_guarded:>9}");
    println!("\nnet of baseline");
    println!("  verify, as shipped         {:>9}", verify - baseline);
    println!("  transcript, 6 keccaks      {:>9}", transcript - baseline);
    println!("  checkProofData (not run)   {:>9}", well_formed - baseline);
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
    println!("  alt_bn128 G1 decompress    {per_decompress:>9}   (table:  398 + 100 base)");
    println!("  nine of them, a submission {:>9}", per_decompress * 9);

    const SYSCALL_FLOOR: u64 = 18 * 3_840 + 18 * 334 + 36_364 + 2 * 12_121;
    println!("\n  BN254 syscall floor        {SYSCALL_FLOOR:>9}");
    println!(
        "  everything else            {:>9}",
        verify.saturating_sub(SYSCALL_FLOOR)
    );

    assert!(
        verify > baseline,
        "the verification did no work: {verify} vs {baseline}"
    );
    assert!(
        verify < 1_400_000,
        "a PLONK verification does not fit one transaction: {verify}"
    );
    assert!(
        per_decompress < 1_000,
        "G1 decompression regressed; it is what makes a submission one transaction \
         rather than two: {per_decompress}"
    );
    assert!(
        verify_guarded > verify,
        "checkProofData is meant to be the more expensive path: {verify_guarded} vs {verify}"
    );
}
