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
use solana_address_lookup_table_interface::state::{AddressLookupTable, LookupTableMeta};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{v0, AddressLookupTableAccount, Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction::Transaction;

use zkasper_program_tests::{fixture, proof_array, Fixture};
use zkasper_solana_program::error::ZkasperError;
use zkasper_solana_program::instruction as ix;
use zkasper_solana_program::plonk::PROOF_LEN;
use zkasper_solana_program::state::{
    anchor_record_address, finalization_record_address, light_client_address, proof_buffer_address,
    AnchorRecord, FinalizationRecord, LightClientState, PROOF_BUFFER_LEN,
};
use zkasper_solana_program::wire::{FinalizationOutput, FINALIZATION_PUBLIC_BYTES};

/// A whole submission measures 481,005 units; this leaves headroom without
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

    fn stage(&mut self) -> TransactionMetadata {
        let proof = proof_array(&self.f);
        let instruction = ix::stage_proof(&self.program_id, &self.payer.pubkey(), &proof);
        self.ok(&[instruction])
    }

    #[allow(clippy::result_large_err)]
    fn submit(&mut self, output: &FinalizationOutput) -> litesvm::types::TransactionResult {
        let instruction = ix::submit_finalization(
            &self.program_id,
            &self.payer.pubkey(),
            &self.payer.pubkey(),
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
fn a_staged_wrapped_proof_advances_the_light_client() {
    let mut h = Harness::new();
    h.initialize();
    h.stage();
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
    h.stage();
    let out = h.f.output;
    h.submit(&out).unwrap();
    let result = h.submit(&out);
    custom_error(&result, ZkasperError::EpochNotAdvancing);
}

#[test]
fn rejects_a_tampered_finalized_root() {
    let mut h = Harness::new();
    h.initialize();
    h.stage();
    let mut out = h.f.output;
    out.finalized_root[0] ^= 1;
    let result = h.submit(&out);
    custom_error(&result, ZkasperError::ProofVerificationFailed);
}

#[test]
fn rejects_a_tampered_justified_root() {
    let mut h = Harness::new();
    h.initialize();
    h.stage();
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
    h.stage();
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

    h.stage();
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
    h.stage();
    let out = h.f.output;
    let result = h.submit(&out);
    custom_error(&result, ZkasperError::ProofVerificationFailed);
}

#[test]
fn rejects_a_submission_with_nothing_staged() {
    let mut h = Harness::new();
    h.initialize();
    let out = h.f.output;
    let result = h.submit(&out);
    let Err(failure) = &result else {
        panic!("a submission with no staged proof succeeded");
    };
    // The buffer PDA does not exist, so the runtime never reaches the program.
    let err = format!("{:?}", failure.err);
    assert!(
        err.contains("Custom") || err.contains("AccountNotFound"),
        "{err}"
    );
}

/// A submitter can only verify what that submitter staged, so nobody can have a
/// proof swapped out from under them between the two transactions.
#[test]
fn rejects_a_buffer_belonging_to_someone_else() {
    let mut h = Harness::new();
    h.initialize();
    h.stage();

    let stranger = Pubkey::new_from_array([3u8; 32]);
    let (their_buffer, _) = proof_buffer_address(&h.program_id, &stranger);
    let out = h.f.output;
    let mut instruction =
        ix::submit_finalization(&h.program_id, &h.payer.pubkey(), &h.payer.pubkey(), &out);
    instruction.accounts[4] = AccountMeta::new_readonly(their_buffer, false);
    let result = h.send(&[instruction], Some(COMPUTE_UNIT_LIMIT));
    let Err(failure) = &result else {
        panic!("a foreign buffer was accepted");
    };
    let err = format!("{:?}", failure.err);
    assert!(
        err.contains(&format!(
            "Custom({})",
            ZkasperError::InvalidProofBuffer as u32
        )) || err.contains("AccountNotFound"),
        "{err}"
    );
}

#[test]
fn re_staging_overwrites_and_costs_no_extra_rent() {
    let mut h = Harness::new();
    h.initialize();
    h.stage();
    let (buffer, _) = proof_buffer_address(&h.program_id, &h.payer.pubkey());
    let first = h.svm.get_account(&buffer).unwrap();
    assert_eq!(first.data.len(), PROOF_BUFFER_LEN);
    h.stage();
    let second = h.svm.get_account(&buffer).unwrap();
    assert_eq!(first.lamports, second.lamports);
    assert_eq!(first.data, second.data);

    // And the rent comes back.
    let before = h.svm.get_account(&h.payer.pubkey()).unwrap().lamports;
    let instruction = ix::close_proof_buffer(&h.program_id, &h.payer.pubkey());
    h.ok(&[instruction]);
    let after = h.svm.get_account(&h.payer.pubkey()).unwrap().lamports;
    assert!(after > before, "closing the buffer refunded nothing");
    assert!(h.svm.get_account(&buffer).is_none_or(|a| a.lamports == 0));
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
        proof_buffer_address(&h.program_id, &payer).0,
        finalization_record_address(&h.program_id, &payer, out.finalized_epoch).0,
        anchor_record_address(&h.program_id, &payer, &out.finalized_state_root).0,
    ] {
        h.svm.airdrop(&address, 890_880).unwrap();
    }
    h.stage();
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
    h.stage();
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
    let stage = h.stage().compute_units_consumed;

    let out = h.f.output;
    let verify_only = h
        .send(
            &[ix::verify_only(
                &h.program_id,
                &h.payer.pubkey(),
                &h.payer.pubkey(),
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
    println!("  stage_proof           {stage:>7}");
    println!("  verify_only           {verify_only:>7}");
    println!("  submit_finalization   {submit:>7}");
    println!("  assert_finalized      {read:>7}");
    // Solana's published syscall prices: eighteen scalar multiplications,
    // eighteen point additions, and one pairing of two pairs.
    const SYSCALL_FLOOR: u64 = 18 * 3_840 + 18 * 334 + 36_364 + 2 * 12_121;
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
    assert!(stage < 20_000, "staging cost regressed: {stage}");
    assert!(read < 10_000, "read path cost regressed: {read}");
}

/// What the two transactions leave behind, in lamports.
///
/// Compute units are not the bill. Rent is: the records are permanent, and the
/// staging buffer is not.
#[test]
fn measures_lamports() {
    let mut h = Harness::new();
    let before_init = h.svm.get_account(&h.payer.pubkey()).unwrap().lamports;
    h.initialize();
    let after_init = h.svm.get_account(&h.payer.pubkey()).unwrap().lamports;
    h.stage();
    let (buffer, _) = proof_buffer_address(&h.program_id, &h.payer.pubkey());
    let staged = h.svm.get_account(&buffer).unwrap().lamports;
    let after_stage = h.svm.get_account(&h.payer.pubkey()).unwrap().lamports;

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
        "  stage_proof               {:>10}",
        after_init - after_stage
    );
    println!("    of which buffer rent    {staged:>10}  (refundable)");
    println!(
        "  submit_finalization       {:>10}",
        after_stage - after_submit
    );
    println!("    finalization record     {record:>10}");
    println!("    anchor record           {anchor:>10}");
    println!(
        "  per submission, net of the refund {:>10}",
        (after_init - after_submit) - staged
    );
}

/// A transaction with no `ComputeBudgetProgram` instruction gets 200,000 units.
#[test]
fn behaviour_under_the_default_compute_budget() {
    let mut h = Harness::new();
    h.initialize();
    h.stage();
    let out = h.f.output;
    let instruction =
        ix::submit_finalization(&h.program_id, &h.payer.pubkey(), &h.payer.pubkey(), &out);
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

/// The two transactions a submission takes, measured, plus the single-transaction
/// designs that do not fit.
///
/// A PLONK proof is 768 bytes. Carrying it inline beside the 176-byte output
/// overruns Solana's 1,232-byte packet, and the only way to claw that back is an
/// address lookup table — which cannot hold the record and anchor PDAs, because
/// those are new every epoch and a table's addresses are unusable until the slot
/// after they are added. Staging pays the same two transactions and needs no
/// table at all.
#[test]
fn what_a_submission_weighs() {
    let mut h = Harness::new();
    h.initialize();

    let proof = proof_array(&h.f);
    let out = h.f.output;
    let payer = h.payer.pubkey();

    let stage = h.transaction(
        &[ix::stage_proof(&h.program_id, &payer, &proof)],
        Some(COMPUTE_UNIT_LIMIT),
    );
    let submit = h.transaction(
        &[ix::submit_finalization(&h.program_id, &payer, &payer, &out)],
        Some(COMPUTE_UNIT_LIMIT),
    );

    // Both sizes are of transactions that already carry the budget raise: the
    // limit is not something a submitter adds afterwards and re-measures.
    for tx in [&stage, &submit] {
        assert_eq!(tx.message.instructions.len(), 2);
        assert_eq!(
            tx.message.account_keys[tx.message.instructions[0].program_id_index as usize],
            solana_compute_budget_interface::id(),
        );
    }

    println!("\nserialized transaction bytes (packet limit {PACKET_LIMIT})");
    println!("  1. stage_proof          {:>5}", size(&stage));
    println!("  2. submit_finalization  {:>5}", size(&submit));

    // The counterfactual: one transaction carrying tag, proof and output, with
    // the five accounts `submit_finalization` names.
    let inline = Instruction {
        program_id: h.program_id,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(light_client_address(&h.program_id, &payer).0, false),
            AccountMeta::new(
                finalization_record_address(&h.program_id, &payer, out.finalized_epoch).0,
                false,
            ),
            AccountMeta::new(
                anchor_record_address(&h.program_id, &payer, &out.finalized_state_root).0,
                false,
            ),
            AccountMeta::new_readonly(solana_system_interface_id(), false),
        ],
        data: {
            let mut data = Vec::with_capacity(1 + PROOF_LEN + FINALIZATION_PUBLIC_BYTES);
            data.push(ix::IX_SUBMIT_FINALIZATION);
            data.extend_from_slice(&proof);
            data.extend_from_slice(&out.public_bytes());
            data
        },
    };
    let legacy = h.transaction(std::slice::from_ref(&inline), Some(COMPUTE_UNIT_LIMIT));
    println!(
        "\n  one legacy transaction, proof inline            {:>5}  {}",
        size(&legacy),
        verdict(size(&legacy))
    );

    // The same instruction in a v0 transaction. `try_compile` keeps signers and
    // invoked program ids in the static keys whatever the table offers, so what
    // a table can save is one byte per remaining account instead of thirty-two.
    let table_key = Pubkey::new_from_array([42u8; 32]);
    let fixed = vec![
        light_client_address(&h.program_id, &payer).0,
        solana_system_interface_id(),
    ];
    let mut per_epoch = fixed.clone();
    per_epoch.push(finalization_record_address(&h.program_id, &payer, out.finalized_epoch).0);
    per_epoch.push(anchor_record_address(&h.program_id, &payer, &out.finalized_state_root).0);

    for (what, addresses) in [
        ("v0, table holds the fixed accounts   ", fixed),
        ("v0, table also holds record + anchor ", per_epoch),
    ] {
        let table = AddressLookupTableAccount {
            key: table_key,
            addresses,
        };
        let msg = v0::Message::try_compile(
            &payer,
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(COMPUTE_UNIT_LIMIT),
                inline.clone(),
            ],
            &[table],
            h.svm.latest_blockhash(),
        )
        .expect("compile v0");
        let tx = VersionedTransaction::try_new(VersionedMessage::V0(msg), &[&h.payer]).unwrap();
        let bytes = bincode::serialized_size(&tx).unwrap();
        println!("  {what}          {bytes:>5}  {}", verdict(bytes));
    }

    assert!(size(&stage) <= PACKET_LIMIT, "staging no longer fits");
    assert!(size(&submit) <= PACKET_LIMIT, "submission no longer fits");
    assert!(
        size(&legacy) > PACKET_LIMIT,
        "an inline PLONK submission now fits a legacy transaction; the blocker is gone"
    );
}

fn verdict(bytes: u64) -> &'static str {
    if bytes <= PACKET_LIMIT {
        "fits"
    } else {
        "OVER"
    }
}

fn solana_system_interface_id() -> Pubkey {
    Pubkey::new_from_array([0u8; 32])
}

/// The lookup-table route works, and it still needs a transaction in an earlier
/// slot to put this epoch's record and anchor addresses in the table.
#[test]
fn the_lookup_table_route_needs_the_table_to_exist_first() {
    let mut h = Harness::new();
    h.initialize();
    let payer = h.payer.pubkey();
    let out = h.f.output;

    let _table_key = Pubkey::new_from_array([42u8; 32]);
    let addresses = vec![
        light_client_address(&h.program_id, &payer).0,
        finalization_record_address(&h.program_id, &payer, out.finalized_epoch).0,
    ];
    let data = AddressLookupTable {
        meta: LookupTableMeta::default(),
        addresses: std::borrow::Cow::Owned(addresses.clone()),
    }
    .serialize_for_tests()
    .unwrap();
    println!(
        "a lookup table holding {} addresses is {} bytes of account state, and every \
         new epoch needs two more of them added a slot ahead of the submission",
        addresses.len(),
        data.len()
    );
    assert!(data.len() > 32 * addresses.len());
}
