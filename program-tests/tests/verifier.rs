//! End-to-end tests against the compiled SBF program, under LiteSVM.
//!
//! The proofs are the placeholder fixtures described in `fixtures/README.md`:
//! real Groth16 over a circuit that says nothing about Ethereum. Every BN254
//! operation the program performs is real, so the compute-unit numbers these
//! tests print are the numbers a real proof will cost.
//!
//! Run `scripts/build.sh` first; the tests load `target/deploy/*.so`.

use litesvm::types::TransactionMetadata;
use litesvm::LiteSVM;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

use zkasper_solana_program::error::ZkasperError;
use zkasper_solana_program::instruction as ix;
use zkasper_solana_program::state::{
    anchor_record_address, finalization_record_address, light_client_address, AnchorRecord,
    FinalizationRecord, LightClientState, VK_LEN,
};
use zkasper_solana_program::wire::FinalizationOutput;

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

const BOOTSTRAP: &[u8] = include_bytes!("../../fixtures/bootstrap.bin");
const FINALIZATIONS: [&[u8]; 3] = [
    include_bytes!("../../fixtures/finalization_0.bin"),
    include_bytes!("../../fixtures/finalization_1.bin"),
    include_bytes!("../../fixtures/finalization_2.bin"),
];

fn a32(buf: &[u8], off: usize) -> [u8; 32] {
    buf[off..off + 32].try_into().unwrap()
}

struct Bootstrap {
    accumulator_commitment: [u8; 32],
    latest_state_root: [u8; 32],
    finalized_epoch: u64,
    finalized_root: [u8; 32],
    program_vk: [u8; 32],
    vk: [u8; VK_LEN],
}

fn bootstrap() -> Bootstrap {
    Bootstrap {
        accumulator_commitment: a32(BOOTSTRAP, 0),
        latest_state_root: a32(BOOTSTRAP, 32),
        finalized_epoch: u64::from_le_bytes(BOOTSTRAP[64..72].try_into().unwrap()),
        finalized_root: a32(BOOTSTRAP, 72),
        program_vk: a32(BOOTSTRAP, 104),
        vk: BOOTSTRAP[136..136 + VK_LEN].try_into().unwrap(),
    }
}

struct Finalization {
    a: [u8; 64],
    b: [u8; 128],
    c: [u8; 64],
    output: FinalizationOutput,
}

fn finalization(i: usize) -> Finalization {
    let buf = FINALIZATIONS[i];
    Finalization {
        a: buf[0..64].try_into().unwrap(),
        b: buf[64..192].try_into().unwrap(),
        c: buf[192..256].try_into().unwrap(),
        output: FinalizationOutput {
            accumulator_commitment: a32(buf, 256),
            next_accumulator_commitment: a32(buf, 288),
            finalized_epoch: u64::from_le_bytes(buf[320..328].try_into().unwrap()),
            finalized_root: a32(buf, 328),
            finalized_state_root: a32(buf, 360),
        },
    }
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

const SO_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/deploy/zkasper_solana_program.so"
);

struct Harness {
    svm: LiteSVM,
    payer: Keypair,
    program_id: Pubkey,
}

impl Harness {
    fn new() -> Self {
        let so = std::fs::read(SO_PATH)
            .unwrap_or_else(|e| panic!("{SO_PATH}: {e}\nrun scripts/build.sh first"));
        let program_id = zkasper_solana_program::id();
        let mut svm = LiteSVM::new();
        svm.add_program(program_id, &so).unwrap();
        // Fixed, so every PDA lands on the same bump and the compute-unit
        // numbers below are reproducible. `find_program_address` walks bumps
        // downwards from 255, and each attempt costs a hash.
        let payer = Keypair::new_from_array([7u8; 32]);
        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
        Self {
            svm,
            payer,
            program_id,
        }
    }

    /// Sends `ixs` with an explicit compute-unit limit.
    #[allow(clippy::result_large_err)]
    fn send_with_limit(
        &mut self,
        limit: u32,
        ixs: &[Instruction],
    ) -> litesvm::types::TransactionResult {
        let mut all = vec![ComputeBudgetInstruction::set_compute_unit_limit(limit)];
        all.extend_from_slice(ixs);
        self.send_raw(&all)
    }

    /// Sends `ixs` with no compute-budget instruction, so the runtime applies
    /// the 200,000-unit default.
    #[allow(clippy::result_large_err)]
    fn send_raw(&mut self, ixs: &[Instruction]) -> litesvm::types::TransactionResult {
        let msg = Message::new_with_blockhash(
            ixs,
            Some(&self.payer.pubkey()),
            &self.svm.latest_blockhash(),
        );
        let tx = Transaction::new(&[&self.payer], msg, self.svm.latest_blockhash());
        let result = self.svm.send_transaction(tx);
        self.svm.expire_blockhash();
        result
    }

    fn ok(&mut self, ixs: &[Instruction]) -> TransactionMetadata {
        self.send_with_limit(400_000, ixs)
            .unwrap_or_else(|e| panic!("{:?}\n{}", e.err, e.meta.pretty_logs()))
    }

    fn initialize(&mut self) -> TransactionMetadata {
        let b = bootstrap();
        let instruction = ix::initialize(
            &self.program_id,
            &self.payer.pubkey(),
            &b.accumulator_commitment,
            &b.latest_state_root,
            b.finalized_epoch,
            &b.finalized_root,
            &b.program_vk,
            &b.vk,
        );
        self.ok(&[instruction])
    }

    #[allow(clippy::result_large_err)]
    fn submit(&mut self, f: &Finalization) -> litesvm::types::TransactionResult {
        let instruction = ix::submit_finalization(
            &self.program_id,
            &self.payer.pubkey(),
            &self.payer.pubkey(),
            &f.a,
            &f.b,
            &f.c,
            &f.output,
        );
        self.send_with_limit(400_000, &[instruction])
    }

    fn state(&self) -> LightClientState {
        let (address, _) = light_client_address(&self.program_id, &self.payer.pubkey());
        LightClientState::unpack(&self.svm.get_account(&address).expect("state account").data)
            .expect("unpack state")
    }
}

fn custom_error(result: &litesvm::types::TransactionResult, expected: ZkasperError) {
    let Err(failure) = result else {
        panic!("expected {expected:?}, transaction succeeded");
    };
    let err = format!("{:?}", failure.err);
    let code = expected as u32;
    assert!(
        err.contains(&format!("Custom({code})")),
        "expected {expected:?} (Custom({code})), got {err}"
    );
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[test]
fn bootstrap_writes_the_trusted_checkpoint() {
    let mut h = Harness::new();
    h.initialize();

    let b = bootstrap();
    let state = h.state();
    assert_eq!(state.accumulator_commitment, b.accumulator_commitment);
    assert_eq!(state.latest_state_root, b.latest_state_root);
    assert_eq!(state.finalized_epoch, b.finalized_epoch);
    assert_eq!(state.finalized_root, b.finalized_root);
    assert_eq!(state.program_vk, b.program_vk);
    assert_eq!(state.submission_count, 0);
    assert_eq!(state.authority, h.payer.pubkey());
}

#[test]
fn rejects_a_second_bootstrap() {
    let mut h = Harness::new();
    h.initialize();

    let b = bootstrap();
    let instruction = ix::initialize(
        &h.program_id,
        &h.payer.pubkey(),
        &b.accumulator_commitment,
        &b.latest_state_root,
        b.finalized_epoch,
        &b.finalized_root,
        &b.program_vk,
        &b.vk,
    );
    let result = h.send_with_limit(400_000, &[instruction]);
    custom_error(&result, ZkasperError::AccountAlreadyInitialized);
}

#[test]
fn advances_through_three_finalizations() {
    let mut h = Harness::new();
    h.initialize();
    let bootstrap_acc = bootstrap().accumulator_commitment;

    for i in 0..3 {
        let f = finalization(i);
        h.submit(&f).unwrap_or_else(|e| {
            panic!(
                "epoch {}: {:?}\n{}",
                f.output.finalized_epoch,
                e.err,
                e.meta.pretty_logs()
            )
        });

        let state = h.state();
        assert_eq!(state.finalized_epoch, f.output.finalized_epoch);
        assert_eq!(state.finalized_root, f.output.finalized_root);
        assert_eq!(state.latest_state_root, f.output.finalized_state_root);
        // Strict chaining: the state advances to the END of the proven
        // transition, so the next finalization must start from here.
        assert_eq!(
            state.accumulator_commitment,
            f.output.next_accumulator_commitment
        );
        assert_eq!(state.submission_count as usize, i + 1);

        let (record_key, _) =
            finalization_record_address(&h.program_id, &h.payer.pubkey(), f.output.finalized_epoch);
        let record =
            FinalizationRecord::unpack(&h.svm.get_account(&record_key).unwrap().data).unwrap();
        assert_eq!(record.finalized_root, f.output.finalized_root);
        assert_eq!(record.finalized_state_root, f.output.finalized_state_root);

        let (anchor_key, _) = anchor_record_address(
            &h.program_id,
            &h.payer.pubkey(),
            &f.output.finalized_state_root,
        );
        let anchor = AnchorRecord::unpack(&h.svm.get_account(&anchor_key).unwrap().data).unwrap();
        assert_eq!(anchor.finalized_epoch, f.output.finalized_epoch);
    }

    // The fixtures form a chain: each finalization starts where the previous
    // one ended. After three, the accumulator sits at the end of the third
    // transition, one epoch past the last finalized epoch.
    assert_eq!(
        h.state().accumulator_epoch,
        finalization(2).output.finalized_epoch + 1
    );
    assert_eq!(
        h.state().accumulator_commitment,
        finalization(2).output.next_accumulator_commitment
    );
    assert_ne!(h.state().accumulator_commitment, bootstrap_acc);
}

#[test]
fn rejects_a_tampered_finalized_root() {
    let mut h = Harness::new();
    h.initialize();

    let mut f = finalization(0);
    f.output.finalized_root[0] ^= 1;
    custom_error(&h.submit(&f), ZkasperError::ProofVerificationFailed);
}

#[test]
fn rejects_a_tampered_accumulator_commitment() {
    let mut h = Harness::new();
    h.initialize();

    let mut f = finalization(0);
    f.output.accumulator_commitment[31] ^= 1;
    custom_error(&h.submit(&f), ZkasperError::ProofVerificationFailed);
}

#[test]
fn rejects_a_mangled_proof() {
    let mut h = Harness::new();
    h.initialize();

    let mut f = finalization(0);
    f.c[0] ^= 1;
    custom_error(&h.submit(&f), ZkasperError::ProofVerificationFailed);
}

#[test]
fn rejects_a_replayed_epoch() {
    let mut h = Harness::new();
    h.initialize();

    let f = finalization(0);
    h.submit(&f).unwrap();
    custom_error(&h.submit(&f), ZkasperError::EpochNotAdvancing);
}

#[test]
fn rejects_a_proof_bound_to_a_different_guest() {
    let mut h = Harness::new();
    let b = bootstrap();
    let mut program_vk = b.program_vk;
    program_vk[0] ^= 1;

    let instruction = ix::initialize(
        &h.program_id,
        &h.payer.pubkey(),
        &b.accumulator_commitment,
        &b.latest_state_root,
        b.finalized_epoch,
        &b.finalized_root,
        &program_vk,
        &b.vk,
    );
    h.ok(&[instruction]);

    // The proof commits to the real guest key, so the first public input no
    // longer matches and the pairing fails.
    custom_error(
        &h.submit(&finalization(0)),
        ZkasperError::ProofVerificationFailed,
    );
}

#[test]
fn read_path_answers_finalization_queries() {
    let mut h = Harness::new();
    h.initialize();
    let f = finalization(0);
    h.submit(&f).unwrap();

    h.ok(&[ix::assert_finalized(
        &h.program_id,
        &h.payer.pubkey(),
        f.output.finalized_epoch,
        &f.output.finalized_root,
    )]);

    let mut wrong_root = f.output.finalized_root;
    wrong_root[0] ^= 1;
    custom_error(
        &h.send_with_limit(
            400_000,
            &[ix::assert_finalized(
                &h.program_id,
                &h.payer.pubkey(),
                f.output.finalized_epoch,
                &wrong_root,
            )],
        ),
        ZkasperError::CheckpointNotFinalized,
    );

    // An epoch nobody proved has no record account at all.
    custom_error(
        &h.send_with_limit(
            400_000,
            &[ix::assert_finalized(
                &h.program_id,
                &h.payer.pubkey(),
                999_999,
                &f.output.finalized_root,
            )],
        ),
        ZkasperError::InvalidRecordAccount,
    );
}

#[test]
fn read_path_answers_anchor_queries() {
    let mut h = Harness::new();
    h.initialize();
    let f = finalization(0);
    h.submit(&f).unwrap();

    h.ok(&[ix::assert_anchored(
        &h.program_id,
        &h.payer.pubkey(),
        &f.output.finalized_state_root,
    )]);

    // The bootstrap state root was trusted, not proved, so it is not anchored.
    custom_error(
        &h.send_with_limit(
            400_000,
            &[ix::assert_anchored(
                &h.program_id,
                &h.payer.pubkey(),
                &bootstrap().latest_state_root,
            )],
        ),
        ZkasperError::StateRootNotAnchored,
    );
}

// ---------------------------------------------------------------------------
// compute units
// ---------------------------------------------------------------------------

/// Prints the measured cost of every path, and pins the numbers so a regression
/// in the verifier or the account layout shows up as a test failure.
#[test]
fn measures_compute_units() {
    let mut h = Harness::new();
    let init = h.initialize();
    let f = finalization(0);

    let verify_only = h
        .send_with_limit(
            400_000,
            &[ix::verify_only(
                &h.program_id,
                &h.payer.pubkey(),
                &f.a,
                &f.b,
                &f.c,
                &f.output,
            )],
        )
        .unwrap()
        .compute_units_consumed;

    let submit = h.submit(&f).unwrap().compute_units_consumed;
    let read = h
        .send_with_limit(
            400_000,
            &[ix::assert_finalized(
                &h.program_id,
                &h.payer.pubkey(),
                f.output.finalized_epoch,
                &f.output.finalized_root,
            )],
        )
        .unwrap()
        .compute_units_consumed;

    // Each transaction also runs one ComputeBudget instruction, which the
    // runtime charges 150 units for.
    println!("compute units (whole transaction, includes 150 for ComputeBudget)");
    println!("  initialize          {:>7}", init.compute_units_consumed);
    println!("  verify_only         {:>7}", verify_only);
    println!("  submit_finalization {:>7}", submit);
    println!("  assert_finalized    {:>7}", read);
    // Solana's published syscall prices: one pairing of four pairs, plus one
    // scalar multiplication and one point addition per public input.
    const SYSCALL_FLOOR: u64 = 36_364 + 3 * 12_121 + 2 * 3_840 + 2 * 334;
    println!("  BN254 syscall floor {SYSCALL_FLOOR:>7}");
    println!(
        "  everything else     {:>7}",
        submit.saturating_sub(SYSCALL_FLOOR)
    );

    assert!(
        verify_only < 200_000,
        "verification cost regressed: {verify_only}"
    );
    assert!(submit < 300_000, "submission cost regressed: {submit}");
    assert!(read < 10_000, "read path cost regressed: {read}");
}

/// A transaction with no `ComputeBudgetProgram` instruction gets 200,000 units.
/// Whether that is enough decides if submitters must raise the limit explicitly.
#[test]
fn behaviour_under_the_default_compute_budget() {
    let mut h = Harness::new();
    h.initialize();
    let f = finalization(0);
    let instruction = ix::submit_finalization(
        &h.program_id,
        &h.payer.pubkey(),
        &h.payer.pubkey(),
        &f.a,
        &f.b,
        &f.c,
        &f.output,
    );

    match h.send_raw(&[instruction]) {
        Ok(meta) => println!(
            "submit_finalization fits the 200,000-unit default: {} units",
            meta.compute_units_consumed
        ),
        Err(e) => panic!(
            "submit_finalization exceeds the default budget; clients must call \
             ComputeBudgetInstruction::set_compute_unit_limit. err: {:?}",
            e.err
        ),
    }
}

/// A finalization that does not start from the accumulator the client holds is
/// a branch, and must be rejected rather than silently adopted.
#[test]
fn rejects_a_finalization_from_a_branched_accumulator() {
    let mut h = Harness::new();
    h.initialize();

    let mut f = finalization(0);
    // Same valid proof, but claim it starts somewhere the client has never been.
    f.output.accumulator_commitment = [0xAB; 32];

    let err = h
        .submit(&f)
        .expect_err("a finalization from an unknown accumulator must be rejected");
    let logs = err.meta.pretty_logs();
    assert!(
        logs.contains("does not hold") || format!("{:?}", err.err).contains("Custom"),
        "expected an accumulator mismatch, got: {}",
        logs
    );

    // State must be untouched.
    let state = h.state();
    assert_eq!(state.submission_count, 0);
}
