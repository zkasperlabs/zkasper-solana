//! Instruction handlers.

use solana_program::account_info::{next_account_info, AccountInfo};
use solana_program::clock::Clock;
use solana_program::entrypoint::ProgramResult;
use solana_program::msg;
use solana_program::program::{invoke, invoke_signed};
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;
use solana_program::rent::Rent;
use solana_program::sysvar::Sysvar;
use solana_system_interface::instruction as system_instruction;
use solana_system_interface::program as system_program;

use crate::error::ZkasperError;
use crate::instruction::ZkasperInstruction;
use crate::plonk::PROOF_LEN;
use crate::state::{
    staged_proof, write_proof, AnchorRecord, FinalizationRecord, LightClientState,
    ANCHOR_RECORD_LEN, FINALIZATION_RECORD_LEN, LIGHT_CLIENT_LEN, PROOF_BUFFER_LEN, SEED_ANCHOR,
    SEED_FINALIZATION, SEED_PROOF, SEED_STATE,
};
use crate::wire::{public_values, FinalizationOutput};

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    match ZkasperInstruction::unpack(data)? {
        ZkasperInstruction::Initialize {
            accumulator_commitment,
            latest_state_root,
            finalized_epoch,
            finalized_root,
            program_vk,
        } => initialize(
            program_id,
            accounts,
            accumulator_commitment,
            latest_state_root,
            finalized_epoch,
            finalized_root,
            program_vk,
        ),
        ZkasperInstruction::StageProof { proof } => stage_proof(program_id, accounts, proof),
        ZkasperInstruction::SubmitFinalization { output } => {
            submit_finalization(program_id, accounts, &output)
        }
        ZkasperInstruction::AssertFinalized {
            authority,
            epoch,
            root,
        } => assert_finalized(program_id, accounts, &authority, epoch, &root),
        ZkasperInstruction::AssertAnchored {
            authority,
            state_root,
        } => assert_anchored(program_id, accounts, &authority, &state_root),
        ZkasperInstruction::VerifyOnly { output } => verify_only(program_id, accounts, &output),
        ZkasperInstruction::CloseProofBuffer => close_proof_buffer(program_id, accounts),
    }
}

// ---------------------------------------------------------------------------
// initialize
// ---------------------------------------------------------------------------

/// Trusted bootstrap.
///
/// The checkpoint written here is believed, not proved. It is the subjective
/// starting point every light client needs, and it is the operator's job to pick
/// a finalized checkpoint that is old enough to be beyond weak subjectivity.
///
/// `finalized_epoch` is the last epoch the operator claims is final; the first
/// proof this client accepts is therefore the one finalizing `finalized_epoch +
/// 1`, and `accumulator_commitment` has to be the accumulator *that* proof
/// starts from — the one the epoch above the checkpoint was justified against,
/// not the one the checkpoint itself was. The two parameters name adjacent
/// epochs, which is why [`LightClientState::accumulator_epoch`] is set one
/// above `finalized_epoch` rather than equal to it. Getting this pair wrong
/// costs the operator their first submission and nothing else: it is caught,
/// not adopted.
///
/// `program_vk` is the other half of what this instruction fixes, and it is not
/// subjective at all: it decides *which guest's* proofs this light client will
/// accept. See [`LightClientState::program_vk`].
#[allow(clippy::too_many_arguments)]
fn initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    accumulator_commitment: &[u8; 32],
    latest_state_root: &[u8; 32],
    finalized_epoch: u64,
    finalized_root: &[u8; 32],
    program_vk: &[u8; 32],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let authority = next_account_info(iter)?;
    let state_info = next_account_info(iter)?;
    let system = next_account_info(iter)?;

    if !authority.is_signer {
        return Err(ZkasperError::MissingSigner.into());
    }
    if !system_program::check_id(system.key) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let bump = expect_pda(
        program_id,
        state_info,
        &[SEED_STATE, authority.key.as_ref()],
        ZkasperError::InvalidStateAccount,
    )?;
    if !state_info.data_is_empty() {
        return Err(ZkasperError::AccountAlreadyInitialized.into());
    }

    create_pda(
        program_id,
        authority,
        state_info,
        system,
        LIGHT_CLIENT_LEN,
        &[SEED_STATE, authority.key.as_ref(), &[bump]],
    )?;

    LightClientState {
        bump,
        authority: *authority.key,
        accumulator_commitment: *accumulator_commitment,
        latest_state_root: *latest_state_root,
        finalized_epoch,
        finalized_root: *finalized_root,
        program_vk: *program_vk,
        submission_count: 0,
        // Overflowing here would mean a bootstrap at epoch `u64::MAX`, which no
        // proof could ever extend. `overflow-checks` is on in release, so that
        // bootstrap is refused rather than wrapped to zero.
        accumulator_epoch: finalized_epoch + 1,
    }
    .pack_into(&mut state_info.try_borrow_mut_data()?)?;

    msg!("zkasper bootstrap epoch {}", finalized_epoch);
    Ok(())
}

// ---------------------------------------------------------------------------
// staging
// ---------------------------------------------------------------------------

/// Park a PLONK proof in the submitter's buffer, creating the buffer on first
/// use.
///
/// This is the first of the two transactions a submission takes. It runs no
/// cryptography, so it needs no compute-budget raise, and it is safe to repeat:
/// re-staging overwrites.
fn stage_proof(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    proof: &[u8; PROOF_LEN],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let payer = next_account_info(iter)?;
    let buffer_info = next_account_info(iter)?;
    let system = next_account_info(iter)?;

    if !payer.is_signer {
        return Err(ZkasperError::MissingSigner.into());
    }
    if !system_program::check_id(system.key) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let bump = expect_buffer(program_id, payer, buffer_info)?;
    if buffer_info.data_is_empty() {
        create_pda(
            program_id,
            payer,
            buffer_info,
            system,
            PROOF_BUFFER_LEN,
            &[SEED_PROOF, payer.key.as_ref(), &[bump]],
        )?;
    } else if buffer_info.owner != program_id {
        return Err(ZkasperError::InvalidProofBuffer.into());
    }

    write_proof(&mut buffer_info.try_borrow_mut_data()?, bump, proof)?;
    Ok(())
}

/// Give the buffer's rent back and hand the account to the system program.
fn close_proof_buffer(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let payer = next_account_info(iter)?;
    let buffer_info = next_account_info(iter)?;

    if !payer.is_signer {
        return Err(ZkasperError::MissingSigner.into());
    }
    expect_buffer(program_id, payer, buffer_info)?;
    if buffer_info.owner != program_id {
        return Err(ZkasperError::InvalidProofBuffer.into());
    }

    let refund = buffer_info.lamports();
    **buffer_info.try_borrow_mut_lamports()? = 0;
    **payer.try_borrow_mut_lamports()? += refund;
    buffer_info.resize(0)?;
    buffer_info.assign(&system_program::id());
    Ok(())
}

// ---------------------------------------------------------------------------
// submit_finalization
// ---------------------------------------------------------------------------

fn submit_finalization(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    output: &FinalizationOutput,
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let payer = next_account_info(iter)?;
    let state_info = next_account_info(iter)?;
    let record_info = next_account_info(iter)?;
    let anchor_info = next_account_info(iter)?;
    let buffer_info = next_account_info(iter)?;
    let system = next_account_info(iter)?;

    if !payer.is_signer {
        return Err(ZkasperError::MissingSigner.into());
    }
    if !system_program::check_id(system.key) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if state_info.owner != program_id {
        return Err(ZkasperError::InvalidStateAccount.into());
    }

    let mut state = LightClientState::unpack(&state_info.try_borrow_data()?)?;
    let authority = state.authority;

    // The account names its own authority and bump, so confirming it is the PDA
    // for that authority is one hash rather than the eight-attempt walk
    // `find_program_address` would run. Without it, the safety of everything
    // below would rest on no other account type this program owns ever carrying
    // `TAG_LIGHT_CLIENT` at offset zero -- true today, and an invariant spread
    // across two modules and enforced by one byte constant.
    if Pubkey::create_program_address(&[SEED_STATE, authority.as_ref(), &[state.bump]], program_id)
        .map_err(|_| ZkasperError::InvalidStateAccount)?
        != *state_info.key
    {
        return Err(ZkasperError::InvalidStateAccount.into());
    }

    // Cheap rejections before the verification, so a replayed, stale or
    // off-chain proof costs the submitter a few hundred units rather than the
    // six hundred thousand a PLONK check runs to.
    if output.finalized_epoch <= state.finalized_epoch {
        return Err(ZkasperError::EpochNotAdvancing.into());
    }

    // Chain the accumulator strictly. Each finalization names BOTH ends of one
    // proven transition: `accumulator_commitment` is what the finalized epoch
    // was justified against, and `next_accumulator_commitment` is what the
    // epoch above it was justified against, proven inside the circuit to be the
    // first advanced by exactly that epoch diff.
    //
    // So the program never needs to see an epoch-diff proof to keep the chain
    // unbroken: it requires the incoming start to equal the accumulator it holds,
    // and stores the end. A prover who branched the accumulator cannot rejoin,
    // because the branch's commitment will not match what is stored here.
    //
    // This replaces the earlier optimistic acceptance, which took any new
    // commitment on trust and left detection to the consumer.
    if state.accumulator_commitment != output.accumulator_commitment {
        msg!("zkasper: finalization starts from an accumulator this client does not hold");
        return Err(ZkasperError::AccumulatorMismatch.into());
    }

    // Same accumulator, but is it the same *epoch*? A commitment binds a
    // validator-set root and a total active balance and nothing else, so two
    // epochs that left the set untouched are byte-identical here and the check
    // above would wave a skipped epoch through. On mainnet the set moves every
    // epoch, which is why no gap has slipped past -- an accident of the network,
    // not a guarantee of the format.
    //
    // The gap matters because zkasper proves the supermajority target vote and
    // the ancestry of the finalized root, never the FFG link. A consumer is left
    // with Casper's double-vote clause, and that clause only bites while every
    // epoch in the sequence carries a supermajority vote. So consecutiveness is
    // the safety property, and it is checked here rather than inferred from the
    // validator set happening to churn.
    if state.accumulator_epoch != output.finalized_epoch {
        msg!("zkasper: finalization does not start at the epoch this client holds");
        return Err(ZkasperError::AccumulatorEpochMismatch.into());
    }

    let epoch_seed = output.finalized_epoch.to_le_bytes();
    let record_bump = expect_pda(
        program_id,
        record_info,
        &[SEED_FINALIZATION, authority.as_ref(), &epoch_seed],
        ZkasperError::InvalidRecordAccount,
    )?;
    let anchor_bump = expect_pda(
        program_id,
        anchor_info,
        &[
            SEED_ANCHOR,
            authority.as_ref(),
            &output.finalized_state_root,
        ],
        ZkasperError::InvalidAnchorAccount,
    )?;
    if !record_info.data_is_empty() {
        return Err(ZkasperError::AccountAlreadyInitialized.into());
    }

    verify_staged(program_id, payer, buffer_info, &state.program_vk, output)?;

    // Both halves of one accumulator move together: the far end of the
    // transition, and the epoch that end belongs to. The guest asserts the two
    // epochs are adjacent, so this is the check above rearmed for the next
    // submission.
    state.accumulator_commitment = output.next_accumulator_commitment;
    state.accumulator_epoch = output.justified_epoch;

    state.latest_state_root = output.finalized_state_root;
    state.finalized_epoch = output.finalized_epoch;
    state.finalized_root = output.finalized_root;
    state.submission_count += 1;
    state.pack_into(&mut state_info.try_borrow_mut_data()?)?;

    let slot = Clock::get()?.slot;
    create_pda(
        program_id,
        payer,
        record_info,
        system,
        FINALIZATION_RECORD_LEN,
        &[
            SEED_FINALIZATION,
            authority.as_ref(),
            &epoch_seed,
            &[record_bump],
        ],
    )?;
    FinalizationRecord {
        bump: record_bump,
        finalized_epoch: output.finalized_epoch,
        finalized_root: output.finalized_root,
        finalized_state_root: output.finalized_state_root,
        accumulator_commitment: output.accumulator_commitment,
        submitted_slot: slot,
    }
    .pack_into(&mut record_info.try_borrow_mut_data()?)?;

    // Two epochs cannot share a beacon state root, so an existing anchor means
    // this state root was already recorded. Leave the earlier one in place.
    if anchor_info.data_is_empty() {
        create_pda(
            program_id,
            payer,
            anchor_info,
            system,
            ANCHOR_RECORD_LEN,
            &[
                SEED_ANCHOR,
                authority.as_ref(),
                &output.finalized_state_root,
                &[anchor_bump],
            ],
        )?;
        AnchorRecord {
            bump: anchor_bump,
            finalized_epoch: output.finalized_epoch,
            finalized_state_root: output.finalized_state_root,
        }
        .pack_into(&mut anchor_info.try_borrow_mut_data()?)?;
    }

    msg!("zkasper finalized epoch {}", output.finalized_epoch);
    Ok(())
}

/// Verify a proof against the bound key and change nothing.
fn verify_only(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    output: &FinalizationOutput,
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let state_info = next_account_info(iter)?;
    let buffer_info = next_account_info(iter)?;
    if state_info.owner != program_id {
        return Err(ZkasperError::InvalidStateAccount.into());
    }
    let program_vk = LightClientState::unpack(&state_info.try_borrow_data()?)?.program_vk;
    // The buffer is named rather than derived: `verify_only` writes nothing, so
    // anyone may point it at anyone's staged proof.
    if buffer_info.owner != program_id {
        return Err(ZkasperError::InvalidProofBuffer.into());
    }
    let data = buffer_info.try_borrow_data()?;
    crate::plonk::verify(
        staged_proof(&data)?,
        &program_vk,
        &public_values(output, &program_vk),
    )
    .map_err(Into::into)
}

/// The one place a proof is checked.
///
/// Both halves of the statement — the guest key and the public window — come
/// from the light client and from `output`; the submission carries neither the
/// key nor the padded window, so neither can be chosen to fit a proof.
fn verify_staged(
    program_id: &Pubkey,
    payer: &AccountInfo,
    buffer_info: &AccountInfo,
    program_vk: &[u8; 32],
    output: &FinalizationOutput,
) -> Result<(), ZkasperError> {
    expect_buffer(program_id, payer, buffer_info)?;
    if buffer_info.owner != program_id {
        return Err(ZkasperError::InvalidProofBuffer);
    }
    let data = buffer_info
        .try_borrow_data()
        .map_err(|_| ZkasperError::InvalidProofBuffer)?;
    crate::plonk::verify(
        staged_proof(&data)?,
        program_vk,
        &public_values(output, program_vk),
    )
}

// ---------------------------------------------------------------------------
// read path
// ---------------------------------------------------------------------------

fn assert_finalized(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    authority: &Pubkey,
    epoch: u64,
    root: &[u8; 32],
) -> ProgramResult {
    let record_info = next_account_info(&mut accounts.iter())?;
    if record_info.owner != program_id {
        return Err(ZkasperError::InvalidRecordAccount.into());
    }
    expect_pda(
        program_id,
        record_info,
        &[SEED_FINALIZATION, authority.as_ref(), &epoch.to_le_bytes()],
        ZkasperError::InvalidRecordAccount,
    )?;

    let record = FinalizationRecord::unpack(&record_info.try_borrow_data()?)?;
    if record.finalized_epoch != epoch || record.finalized_root != *root {
        return Err(ZkasperError::CheckpointNotFinalized.into());
    }
    Ok(())
}

fn assert_anchored(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    authority: &Pubkey,
    state_root: &[u8; 32],
) -> ProgramResult {
    let anchor_info = next_account_info(&mut accounts.iter())?;
    if anchor_info.owner != program_id {
        return Err(ZkasperError::StateRootNotAnchored.into());
    }
    expect_pda(
        program_id,
        anchor_info,
        &[SEED_ANCHOR, authority.as_ref(), state_root],
        ZkasperError::InvalidAnchorAccount,
    )?;

    let anchor = AnchorRecord::unpack(&anchor_info.try_borrow_data()?)?;
    if anchor.finalized_state_root != *state_root {
        return Err(ZkasperError::StateRootNotAnchored.into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn expect_pda(
    program_id: &Pubkey,
    account: &AccountInfo,
    seeds: &[&[u8]],
    err: ZkasperError,
) -> Result<u8, ZkasperError> {
    let (expected, bump) = Pubkey::find_program_address(seeds, program_id);
    if *account.key != expected {
        return Err(err);
    }
    Ok(bump)
}

/// The buffer belongs to the signer, so a submission can only ever verify a
/// proof that signer staged.
fn expect_buffer(
    program_id: &Pubkey,
    payer: &AccountInfo,
    buffer_info: &AccountInfo,
) -> Result<u8, ZkasperError> {
    expect_pda(
        program_id,
        buffer_info,
        &[SEED_PROOF, payer.key.as_ref()],
        ZkasperError::InvalidProofBuffer,
    )
}

fn create_pda<'a>(
    program_id: &Pubkey,
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    space: usize,
    seeds: &[&[u8]],
) -> ProgramResult {
    let rent = Rent::get()?.minimum_balance(space);
    if target.lamports() == 0 {
        return invoke_signed(
            &system_instruction::create_account(
                payer.key,
                target.key,
                rent,
                space as u64,
                program_id,
            ),
            &[payer.clone(), target.clone(), system.clone()],
            &[seeds],
        );
    }

    // `create_account` refuses an address that already holds lamports, and every
    // address this program creates is derivable years in advance — so one
    // lamport sent to a future epoch's finalization record would block that
    // epoch for good. Allocate and assign instead, which is what
    // `create_account` does internally and which does not care about the
    // balance. Nobody but this program can allocate at a PDA, so an address
    // funded in advance is still empty and still ours.
    let top_up = rent.saturating_sub(target.lamports());
    if top_up > 0 {
        invoke(
            &system_instruction::transfer(payer.key, target.key, top_up),
            &[payer.clone(), target.clone(), system.clone()],
        )?;
    }
    invoke_signed(
        &system_instruction::allocate(target.key, space as u64),
        &[target.clone(), system.clone()],
        &[seeds],
    )?;
    invoke_signed(
        &system_instruction::assign(target.key, program_id),
        &[target.clone(), system.clone()],
        &[seeds],
    )
}
