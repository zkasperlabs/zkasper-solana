//! End-to-end tests against the compiled SBF program, under LiteSVM.
//!
//! The proof is the real one: `fixtures/wrap-469426.json`, produced by
//! `cargo-zisk wrap --plonk`. Every BN254 operation the program performs runs
//! for real inside the SVM, so the compute-unit and transaction-size numbers
//! these tests print are the numbers a submission costs.
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

use zkasper_program_tests::{fixture, Fixture};
use zkasper_solana_program::error::ZkasperError;
use zkasper_solana_program::instruction as ix;
use zkasper_solana_program::plonk::PROOF_LEN;
use zkasper_solana_program::state::{
    anchor_record_address, finalization_record_address, light_client_address, AnchorRecord,
    FinalizationRecord, LightClientState,
};
use zkasper_solana_program::wire::{FinalizationOutput, FINALIZATION_PUBLIC_BYTES};

/// A whole submission measures 484,908 units; this leaves headroom without
/// overpaying for a limit the runtime reserves block space against.
const COMPUTE_UNIT_LIMIT: u32 = 700_000;

/// Solana's packet limit. Nothing larger than this reaches a leader.
const PACKET_LIMIT: u64 = 1232;

const SO_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/deploy/zkasper_solana_program.so"
);

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

struct Harness {
    svm: LiteSVM,
    payer: Keypair,
    program_id: Pubkey,
    f: Fixture,
}

impl Harness {
    fn new() -> Self {
        let so = std::fs::read(SO_PATH)
            .unwrap_or_else(|e| panic!("{SO_PATH}: {e}\nrun scripts/build.sh first"));
        let program_id = zkasper_solana_program::id();
        // Mainnet's feature set rather than LiteSVM's default, which activates
        // none: the `alt_bn128` syscalls this program lives on are gated.
        let mut svm = LiteSVM::new().with_mainnet_features();
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
            f: fixture(),
        }
    }

    /// The transaction a submitter actually sends: a compute-budget raise, then
    /// the instruction.
    fn transaction(&self, ixs: &[Instruction], limit: Option<u32>) -> Transaction {
        let mut all = Vec::new();
        if let Some(limit) = limit {
            all.push(ComputeBudgetInstruction::set_compute_unit_limit(limit));
        }
        all.extend_from_slice(ixs);
        let msg = Message::new_with_blockhash(
            &all,
            Some(&self.payer.pubkey()),
            &self.svm.latest_blockhash(),
        );
        Transaction::new(&[&self.payer], msg, self.svm.latest_blockhash())
    }

    #[allow(clippy::result_large_err)]
    fn send(
        &mut self,
        ixs: &[Instruction],
        limit: Option<u32>,
    ) -> litesvm::types::TransactionResult {
        let tx = self.transaction(ixs, limit);
        let result = self.svm.send_transaction(tx);
        self.svm.expire_blockhash();
        result
    }

    fn ok(&mut self, ixs: &[Instruction]) -> TransactionMetadata {
        self.send(ixs, Some(COMPUTE_UNIT_LIMIT))
            .unwrap_or_else(|e| panic!("{:?}\n{}", e.err, e.meta.pretty_logs()))
    }

    /// Bootstrap one epoch below the proof, on the accumulator it starts from.
    fn initialize(&mut self) -> TransactionMetadata {
        let program_vk = self.f.program_vk;
        self.initialize_with(&program_vk)
    }

    fn initialize_with(&mut self, program_vk: &[u8; 32]) -> TransactionMetadata {
        let out = self.f.output;
        let instruction = ix::initialize(
            &self.program_id,
            &self.payer.pubkey(),
            &out.accumulator_commitment,
            &[0u8; 32],
            out.finalized_epoch - 1,
            &[0u8; 32],
            program_vk,
        );
        self.ok(&[instruction])
    }

    #[allow(clippy::result_large_err)]
    fn submit(&mut self, output: &FinalizationOutput) -> litesvm::types::TransactionResult {
        let compressed = self.f.compressed;
        let instruction = ix::submit_finalization(
            &self.program_id,
            &self.payer.pubkey(),
            &self.payer.pubkey(),
            &compressed,
            output,
        );
        self.send(&[instruction], Some(COMPUTE_UNIT_LIMIT))
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
// bootstrap
// ---------------------------------------------------------------------------

#[test]
fn bootstrap_writes_the_trusted_checkpoint() {
    let mut h = Harness::new();
    h.initialize();
    let state = h.state();
    assert_eq!(state.authority, h.payer.pubkey());
    assert_eq!(state.program_vk, h.f.program_vk);
    assert_eq!(
        state.accumulator_commitment,
        h.f.output.accumulator_commitment
    );
    assert_eq!(state.finalized_epoch, h.f.output.finalized_epoch - 1);
    assert_eq!(state.submission_count, 0);
    // The bootstrap accumulator belongs to the epoch above the trusted
    // checkpoint, so it is labelled with that epoch -- which is exactly the
    // `finalized_epoch` the first accepted proof must carry.
    assert_eq!(state.accumulator_epoch, h.f.output.finalized_epoch);
}

#[test]
fn rejects_a_second_bootstrap() {
    let mut h = Harness::new();
    h.initialize();
    let out = h.f.output;
    let program_vk = h.f.program_vk;
    let instruction = ix::initialize(
        &h.program_id,
        &h.payer.pubkey(),
        &out.accumulator_commitment,
        &[0u8; 32],
        out.finalized_epoch - 1,
        &[0u8; 32],
        &program_vk,
    );
    let result = h.send(&[instruction], Some(COMPUTE_UNIT_LIMIT));
    custom_error(&result, ZkasperError::AccountAlreadyInitialized);
}

// ---------------------------------------------------------------------------
// the submission path
// ---------------------------------------------------------------------------

#[test]
fn a_wrapped_proof_advances_the_light_client() {
    let mut h = Harness::new();
    h.initialize();
    let out = h.f.output;
    h.submit(&out)
        .expect("the real proof was rejected on chain");

    let state = h.state();
    assert_eq!(state.finalized_epoch, out.finalized_epoch);
    assert_eq!(state.finalized_root, out.finalized_root);
    assert_eq!(state.latest_state_root, out.finalized_state_root);
    assert_eq!(state.submission_count, 1);
    // The accumulator moved to the far end of the transition the proof covers,
    // and the epoch that end belongs to is the one the proof justified.
    assert_eq!(
        state.accumulator_commitment,
        out.next_accumulator_commitment
    );
    assert_eq!(state.accumulator_epoch, out.justified_epoch);

    let (record_address, _) =
        finalization_record_address(&h.program_id, &h.payer.pubkey(), out.finalized_epoch);
    let record =
        FinalizationRecord::unpack(&h.svm.get_account(&record_address).unwrap().data).unwrap();
    assert_eq!(record.finalized_epoch, out.finalized_epoch);
    assert_eq!(record.finalized_root, out.finalized_root);
    assert_eq!(record.accumulator_commitment, out.accumulator_commitment);

    let (anchor_address, _) =
        anchor_record_address(&h.program_id, &h.payer.pubkey(), &out.finalized_state_root);
    let anchor = AnchorRecord::unpack(&h.svm.get_account(&anchor_address).unwrap().data).unwrap();
    assert_eq!(anchor.finalized_state_root, out.finalized_state_root);
    assert_eq!(anchor.finalized_epoch, out.finalized_epoch);
}

#[test]
fn rejects_a_replayed_epoch() {
    let mut h = Harness::new();
    h.initialize();
    let out = h.f.output;
    h.submit(&out).unwrap();
    let result = h.submit(&out);
    custom_error(&result, ZkasperError::EpochNotAdvancing);
}

#[test]
fn rejects_a_tampered_finalized_root() {
    let mut h = Harness::new();
    h.initialize();
    let mut out = h.f.output;
    out.finalized_root[0] ^= 1;
    let result = h.submit(&out);
    custom_error(&result, ZkasperError::ProofVerificationFailed);
}

#[test]
fn rejects_a_tampered_justified_root() {
    let mut h = Harness::new();
    h.initialize();
    let mut out = h.f.output;
    out.justified_root[31] ^= 1;
    let result = h.submit(&out);
    custom_error(&result, ZkasperError::ProofVerificationFailed);
}

/// A finalization that does not start from the accumulator the client holds is
/// a branch, and is rejected rather than silently adopted.
#[test]
fn rejects_a_finalization_from_a_branched_accumulator() {
    let mut h = Harness::new();
    h.initialize();
    let mut out = h.f.output;
    out.accumulator_commitment[0] ^= 1;
    let result = h.submit(&out);
    custom_error(&result, ZkasperError::AccumulatorMismatch);
}

/// A genuine proof, starting from exactly the accumulator this client holds,
/// that still finalizes the wrong epoch.
///
/// This is the case the commitment check provably cannot see. An accumulator
/// commitment binds a validator-set root and a total active balance and no
/// epoch, so a client sitting one epoch further back than it thinks holds bytes
/// that match a proof it should not accept. Bootstrapping two epochs below the
/// proof builds that state directly: the client is missing
/// `finalized_epoch - 1`, and adopting this proof would leave a hole.
///
/// Bootstrapping wrong is how the case is reached, because the proof itself
/// cannot be edited into it -- `finalized_epoch` is bound by the public-input
/// hash, so mutating it fails verification first, with a different error.
///
/// Consecutiveness is the safety property: zkasper never proves the FFG link,
/// so a consumer holds only the double-vote clause, and that clause binds only
/// while every epoch in the sequence carries a supermajority vote.
#[test]
fn rejects_a_finalization_that_skips_an_epoch() {
    let mut h = Harness::new();
    let out = h.f.output;
    let program_vk = h.f.program_vk;
    h.ok(&[ix::initialize(
        &h.program_id,
        &h.payer.pubkey(),
        &out.accumulator_commitment,
        &[0u8; 32],
        out.finalized_epoch - 2,
        &[0u8; 32],
        &program_vk,
    )]);
    // The state that makes this a real test: the accumulator matches the proof
    // byte for byte, and only the epoch label disagrees. Neither of the two
    // checks that came before this one can fire.
    let before = h.state();
    assert_eq!(before.accumulator_commitment, out.accumulator_commitment);
    assert_eq!(before.accumulator_epoch, out.finalized_epoch - 1);
    assert!(out.finalized_epoch > before.finalized_epoch);

    let result = h.submit(&out);
    custom_error(&result, ZkasperError::AccumulatorEpochMismatch);

    // Rejected, not adopted: no hole was opened at `finalized_epoch - 1`.
    let after = h.state();
    assert_eq!(after.finalized_epoch, out.finalized_epoch - 2);
    assert_eq!(after.accumulator_epoch, out.finalized_epoch - 1);
    assert_eq!(after.submission_count, 0);
    assert!(h
        .svm
        .get_account(
            &finalization_record_address(&h.program_id, &h.payer.pubkey(), out.finalized_epoch).0
        )
        .is_none_or(|a| a.data.is_empty()));
}

/// The same proof, under a light client that pins a different guest key. The
/// proof is genuine; it is a proof of something this client did not ask for.
#[test]
fn rejects_a_proof_bound_to_a_different_guest() {
    let mut h = Harness::new();
    let mut other = h.f.program_vk;
    other[0] ^= 1;
    h.initialize_with(&other);
    let out = h.f.output;
    let result = h.submit(&out);
    custom_error(&result, ZkasperError::ProofVerificationFailed);
}

/// A commitment that is not the compression of any curve point never reaches
/// the transcript: decompression is the parse, and it fails first.
#[test]
fn rejects_a_commitment_that_does_not_decompress() {
    let mut h = Harness::new();
    h.initialize();
    let out = h.f.output;
    let payer = h.payer.pubkey();
    let mut proof = h.f.compressed;
    proof[..32].copy_from_slice(&[0xff; 32]);
    let result = h.send(
        &[ix::submit_finalization(
            &h.program_id,
            &payer,
            &payer,
            &proof,
            &out,
        )],
        Some(COMPUTE_UNIT_LIMIT),
    );
    custom_error(&result, ZkasperError::ProofVerificationFailed);
}

/// A commitment that decompresses to a different point than the prover meant
/// is rejected too, and by the algebra rather than by the parse.
#[test]
fn rejects_a_commitment_with_the_sign_bit_flipped() {
    let mut h = Harness::new();
    h.initialize();
    let out = h.f.output;
    let payer = h.payer.pubkey();
    let mut proof = h.f.compressed;
    proof[0] ^= 0x80;
    let result = h.send(
        &[ix::submit_finalization(
            &h.program_id,
            &payer,
            &payer,
            &proof,
            &out,
        )],
        Some(COMPUTE_UNIT_LIMIT),
    );
    custom_error(&result, ZkasperError::ProofVerificationFailed);
}

/// Every address this program creates is derivable in advance, and
/// `create_account` refuses an address that already holds lamports. Funding one
/// ahead of a submission must not be able to block it.
///
/// The runtime will not let a transaction leave an account rent-paying, so the
/// cheapest such grief is the rent-exempt minimum of an empty account —
/// 890,880 lamports, and it has to be spent per address. With the allocate path
/// below it buys nothing at all: the lamports are absorbed into the account the
/// program then creates, so the griefer pays part of the submitter's rent.
#[test]
fn survives_addresses_funded_in_advance() {
    let mut h = Harness::new();
    h.initialize();
    let out = h.f.output;
    let payer = h.payer.pubkey();
    for address in [
        finalization_record_address(&h.program_id, &payer, out.finalized_epoch).0,
        anchor_record_address(&h.program_id, &payer, &out.finalized_state_root).0,
    ] {
        h.svm.airdrop(&address, 890_880).unwrap();
    }
    h.submit(&out)
        .expect("a funded address blocked the submission");
    assert_eq!(h.state().finalized_epoch, out.finalized_epoch);
}

// ---------------------------------------------------------------------------
// read path
// ---------------------------------------------------------------------------

#[test]
fn read_path_answers_finalization_and_anchor_queries() {
    let mut h = Harness::new();
    h.initialize();
    let out = h.f.output;
    h.submit(&out).unwrap();

    let authority = h.payer.pubkey();
    h.ok(&[ix::assert_finalized(
        &h.program_id,
        &authority,
        out.finalized_epoch,
        &out.finalized_root,
    )]);
    h.ok(&[ix::assert_anchored(
        &h.program_id,
        &authority,
        &out.finalized_state_root,
    )]);

    let mut wrong = out.finalized_root;
    wrong[0] ^= 1;
    let result = h.send(
        &[ix::assert_finalized(
            &h.program_id,
            &authority,
            out.finalized_epoch,
            &wrong,
        )],
        Some(COMPUTE_UNIT_LIMIT),
    );
    custom_error(&result, ZkasperError::CheckpointNotFinalized);

    let mut unknown = out.finalized_state_root;
    unknown[0] ^= 1;
    // The PDA for a state root nothing anchored does not exist, so the runtime
    // hands the program an empty account the system program owns.
    let result = h.send(
        &[ix::assert_anchored(&h.program_id, &authority, &unknown)],
        Some(COMPUTE_UNIT_LIMIT),
    );
    custom_error(&result, ZkasperError::StateRootNotAnchored);
}

// ---------------------------------------------------------------------------
// what it costs
// ---------------------------------------------------------------------------

#[test]
fn measures_compute_units() {
    let mut h = Harness::new();
    let init = h.initialize().compute_units_consumed;

    let out = h.f.output;
    let compressed = h.f.compressed;
    let verify_only = h
        .send(
            &[ix::verify_only(
                &h.program_id,
                &h.payer.pubkey(),
                &compressed,
                &out,
            )],
            Some(COMPUTE_UNIT_LIMIT),
        )
        .unwrap()
        .compute_units_consumed;
    let submit = h.submit(&out).unwrap().compute_units_consumed;
    let read = h
        .send(
            &[ix::assert_finalized(
                &h.program_id,
                &h.payer.pubkey(),
                out.finalized_epoch,
                &out.finalized_root,
            )],
            Some(COMPUTE_UNIT_LIMIT),
        )
        .unwrap()
        .compute_units_consumed;

    // Each transaction also runs one ComputeBudget instruction, which the
    // runtime charges 150 units for.
    println!("compute units (whole transaction, includes 150 for ComputeBudget)");
    println!("  initialize            {init:>7}");
    println!("  verify_only           {verify_only:>7}");
    println!("  submit_finalization   {submit:>7}");
    println!("  assert_finalized      {read:>7}");
    // Solana's published syscall prices: eighteen scalar multiplications,
    // eighteen point additions, one pairing of two pairs, and the nine G1
    // decompressions the compressed proof adds, each 398 over the 100-unit
    // syscall base.
    const SYSCALL_FLOOR: u64 = 18 * 3_840 + 18 * 334 + 36_364 + 2 * 12_121 + 9 * (100 + 398);
    println!("  BN254 syscall floor   {SYSCALL_FLOOR:>7}");
    println!(
        "  everything else       {:>7}",
        submit.saturating_sub(SYSCALL_FLOOR)
    );
    println!("  budget requested      {COMPUTE_UNIT_LIMIT:>7}");

    assert!(
        submit < COMPUTE_UNIT_LIMIT as u64,
        "a submission no longer fits the budget it asks for: {submit}"
    );
    assert!(read < 10_000, "read path cost regressed: {read}");
}

/// What a submission leaves behind, in lamports.
///
/// Compute units are not the bill. Rent is, and all of it is permanent now that
/// nothing is staged: the two records are what a submitter pays for.
#[test]
fn measures_lamports() {
    let mut h = Harness::new();
    let before_init = h.svm.get_account(&h.payer.pubkey()).unwrap().lamports;
    h.initialize();
    let after_init = h.svm.get_account(&h.payer.pubkey()).unwrap().lamports;

    let out = h.f.output;
    h.submit(&out).unwrap();
    let after_submit = h.svm.get_account(&h.payer.pubkey()).unwrap().lamports;
    let record = h
        .svm
        .get_account(
            &finalization_record_address(&h.program_id, &h.payer.pubkey(), out.finalized_epoch).0,
        )
        .unwrap()
        .lamports;
    let anchor = h
        .svm
        .get_account(
            &anchor_record_address(&h.program_id, &h.payer.pubkey(), &out.finalized_state_root).0,
        )
        .unwrap()
        .lamports;

    println!("\nlamports");
    println!(
        "  initialize, once          {:>10}",
        before_init - after_init
    );
    println!(
        "  submit_finalization       {:>10}",
        after_init - after_submit
    );
    println!("    finalization record     {record:>10}");
    println!("    anchor record           {anchor:>10}");
}

/// A transaction with no `ComputeBudgetProgram` instruction gets 200,000 units.
#[test]
fn behaviour_under_the_default_compute_budget() {
    let mut h = Harness::new();
    h.initialize();
    let out = h.f.output;
    let compressed = h.f.compressed;
    let instruction = ix::submit_finalization(
        &h.program_id,
        &h.payer.pubkey(),
        &h.payer.pubkey(),
        &compressed,
        &out,
    );
    match h.send(&[instruction], None) {
        Ok(meta) => panic!(
            "a PLONK submission now fits the 200,000-unit default at {} units; the \
             ComputeBudget instruction is no longer needed",
            meta.compute_units_consumed
        ),
        Err(e) => println!(
            "a PLONK submission exceeds the 200,000-unit default, so every submitter \
             must raise it: {:?}",
            e.err
        ),
    }
}

// ---------------------------------------------------------------------------
// what it weighs
// ---------------------------------------------------------------------------

fn size(tx: &Transaction) -> u64 {
    bincode::serialized_size(tx).unwrap()
}

/// The one transaction a submission takes, and the uncompressed encoding that
/// does not fit.
///
/// A PLONK proof is 768 bytes and a Solana packet is 1,232. Carried whole beside
/// the 176-byte output and the accounts the instruction names, a submission
/// overruns the packet. Each of the nine G1 commitments is an `(x, y)` pair that
/// `x` and one sign bit determine, so sending only `x` takes 288 bytes off and
/// brings the whole thing inside the limit with room to spare.
#[test]
fn what_a_submission_weighs() {
    let mut h = Harness::new();
    h.initialize();

    let out = h.f.output;
    let payer = h.payer.pubkey();
    let instruction = ix::submit_finalization(&h.program_id, &payer, &payer, &h.f.compressed, &out);
    let submit = h.transaction(std::slice::from_ref(&instruction), Some(COMPUTE_UNIT_LIMIT));

    // The size is of a transaction that already carries the budget raise: the
    // limit is not something a submitter adds afterwards and re-measures.
    assert_eq!(submit.message.instructions.len(), 2);
    assert_eq!(
        submit.message.account_keys[submit.message.instructions[0].program_id_index as usize],
        solana_compute_budget_interface::id(),
    );

    // The counterfactual: the same transaction with the proof sent whole.
    let mut inline = instruction.clone();
    inline.data = {
        let mut data = Vec::with_capacity(1 + PROOF_LEN + FINALIZATION_PUBLIC_BYTES);
        data.push(ix::IX_SUBMIT_FINALIZATION);
        data.extend_from_slice(&h.f.proof);
        data.extend_from_slice(&out.public_bytes());
        data
    };
    let uncompressed = h.transaction(std::slice::from_ref(&inline), Some(COMPUTE_UNIT_LIMIT));

    println!("\nserialized transaction bytes (packet limit {PACKET_LIMIT})");
    println!(
        "  submit_finalization        {:>5}  {}",
        size(&submit),
        verdict(size(&submit))
    );
    println!(
        "  the same, proof uncompressed  {:>5}  {}",
        size(&uncompressed),
        verdict(size(&uncompressed))
    );
    println!("  instruction data           {:>5}", instruction.data.len());
    println!(
        "  headroom                   {:>5}",
        PACKET_LIMIT - size(&submit)
    );

    assert!(
        size(&submit) <= PACKET_LIMIT,
        "a submission no longer fits one packet: {}",
        size(&submit)
    );
    assert!(
        size(&uncompressed) > PACKET_LIMIT,
        "an uncompressed proof now fits a packet; compression is no longer what makes \
         this one transaction"
    );
}

fn verdict(bytes: u64) -> &'static str {
    if bytes <= PACKET_LIMIT {
        "fits"
    } else {
        "OVER"
    }
}
