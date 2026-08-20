//! Instruction handlers.

use solana_program::account_info::{next_account_info, AccountInfo};
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
use crate::plonk::COMPRESSED_PROOF_LEN;
use crate::state::{
    FinalizationEntry, FinalizationRing, LightClientState, LIGHT_CLIENT_LEN, RING_LEN, SEED_RING,
    SEED_STATE,
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
        ZkasperInstruction::SubmitFinalization { proof, output } => {
            submit_finalization(program_id, accounts, proof, &output)
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
        ZkasperInstruction::VerifyOnly { proof, output } => {
            verify_only(program_id, accounts, proof, &output)
        }
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
    let ring_info = next_account_info(iter)?;
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
    let ring_bump = expect_pda(
        program_id,
        ring_info,
        &[SEED_RING, authority.key.as_ref()],
        ZkasperError::InvalidRingAccount,
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

    // The whole of what history costs, paid once. Every submission after this
    // writes into these bytes and leaves nothing behind.
    create_pda(
        program_id,
        authority,
        ring_info,
        system,
        RING_LEN,
        &[SEED_RING, authority.key.as_ref(), &[ring_bump]],
    )?;
    FinalizationRing::init(&mut ring_info.try_borrow_mut_data()?, ring_bump)?;

    msg!("zkasper bootstrap epoch {}", finalized_epoch);
    Ok(())
}

// ---------------------------------------------------------------------------
// submit_finalization
// ---------------------------------------------------------------------------

fn submit_finalization(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    proof: &[u8; COMPRESSED_PROOF_LEN],
    output: &FinalizationOutput,
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let state_info = next_account_info(iter)?;
    let ring_info = next_account_info(iter)?;

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

    expect_ring(program_id, ring_info, &authority)?;

    verify(proof, &state.program_vk, output)?;

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

    // Written in place, over whatever epoch held this slot 128 epochs ago. No
    // account is created, so a submission costs the transaction fee and nothing
    // else.
    FinalizationRing::write(
        &mut ring_info.try_borrow_mut_data()?,
        &FinalizationEntry {
            finalized_epoch: output.finalized_epoch,
            finalized_root: output.finalized_root,
            finalized_state_root: output.finalized_state_root,
        },
    )?;

    msg!("zkasper finalized epoch {}", output.finalized_epoch);
    Ok(())
}

/// Verify a proof against the bound key and change nothing.
fn verify_only(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    proof: &[u8; COMPRESSED_PROOF_LEN],
    output: &FinalizationOutput,
) -> ProgramResult {
    let state_info = next_account_info(&mut accounts.iter())?;
    if state_info.owner != program_id {
        return Err(ZkasperError::InvalidStateAccount.into());
    }
    let program_vk = LightClientState::unpack(&state_info.try_borrow_data()?)?.program_vk;
    verify(proof, &program_vk, output).map_err(Into::into)
}

/// The one place a proof is checked.
///
/// Both halves of the statement — the guest key and the public window — come
/// from the light client and from `output`; the submission carries neither the
/// key nor the padded window, so neither can be chosen to fit a proof.
///
/// The proof is expanded before anything reads it, so the transcript is built
/// over the same 768 bytes an uncompressed submission would have carried.
fn verify(
    proof: &[u8; COMPRESSED_PROOF_LEN],
    program_vk: &[u8; 32],
    output: &FinalizationOutput,
) -> Result<(), ZkasperError> {
    let proof = crate::plonk::decompress_proof(proof)?;
    crate::plonk::verify(&proof, program_vk, &public_values(output, program_vk))
}

// ---------------------------------------------------------------------------
// read path
// ---------------------------------------------------------------------------

/// Fails with [`ZkasperError::EpochNotInRing`] when `epoch` is older than the
/// ring's 128-epoch window, which is a different statement from
/// [`ZkasperError::CheckpointNotFinalized`] and must not be collapsed into it.
fn assert_finalized(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    authority: &Pubkey,
    epoch: u64,
    root: &[u8; 32],
) -> ProgramResult {
    let ring_info = next_account_info(&mut accounts.iter())?;
    expect_ring(program_id, ring_info, authority)?;

    // `entry` compares the stored epoch itself, so what comes back is this
    // epoch's entry or nothing.
    if FinalizationRing::entry(&ring_info.try_borrow_data()?, epoch)?.finalized_root != *root {
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
    let ring_info = next_account_info(&mut accounts.iter())?;
    expect_ring(program_id, ring_info, authority)?;

    FinalizationRing::entry_by_state_root(&ring_info.try_borrow_data()?, state_root)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// The ring account for `authority`, or a refusal.
///
/// The ring names the bump it was created under, so this is one hash rather than
/// the walk `find_program_address` would run — and it is the derivation, not the
/// tag, that proves the account is this authority's ring: nobody but this
/// program can hold an account at that address, and only ring bytes are ever
/// written there.
fn expect_ring(
    program_id: &Pubkey,
    ring_info: &AccountInfo,
    authority: &Pubkey,
) -> Result<(), ZkasperError> {
    if ring_info.owner != program_id {
        return Err(ZkasperError::InvalidRingAccount);
    }
    let data = ring_info
        .try_borrow_data()
        .map_err(|_| ZkasperError::InvalidRingAccount)?;
    let bump = FinalizationRing::bump(&data)?;
    if Pubkey::create_program_address(&[SEED_RING, authority.as_ref(), &[bump]], program_id)
        .map_err(|_| ZkasperError::InvalidRingAccount)?
        != *ring_info.key
    {
        return Err(ZkasperError::InvalidRingAccount);
    }
    Ok(())
}

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

    // `create_account` refuses an address that already holds lamports, and both
    // addresses this program creates are derivable before anyone has run
    // `initialize` — so one lamport sent to an authority's ring would block that
    // light client for good. Allocate and assign instead, which is what
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
