//! Account layouts.
//!
//! Every account is fixed size and is read and written by explicit offset. No
//! Borsh, no discriminator hashing: the layouts never contain a variable-length
//! field, and hand-rolled slicing keeps the compute cost of the non-cryptographic
//! part of `submit_finalization` in the low hundreds of units.

use solana_program::pubkey::Pubkey;

use crate::error::ZkasperError;
use crate::wire::{AccumulatorCommitment, ProgramVk};

pub const TAG_LIGHT_CLIENT: u8 = 1;
pub const TAG_FINALIZATION_RECORD: u8 = 2;
pub const TAG_ANCHOR_RECORD: u8 = 3;

pub const SEED_STATE: &[u8] = b"zkasper-state";
pub const SEED_FINALIZATION: &[u8] = b"zkasper-fin";
pub const SEED_ANCHOR: &[u8] = b"zkasper-anchor";

// ---------------------------------------------------------------------------
// LightClientState
// ---------------------------------------------------------------------------

const OFF_TAG: usize = 0;
const OFF_BUMP: usize = 1;
const OFF_AUTHORITY: usize = 2;
const OFF_ACC_COMMITMENT: usize = 34;
const OFF_LATEST_STATE_ROOT: usize = 66;
const OFF_FINALIZED_EPOCH: usize = 98;
const OFF_FINALIZED_ROOT: usize = 106;
const OFF_PROGRAM_VK: usize = 138;
const OFF_SUBMISSION_COUNT: usize = 170;
const OFF_ACC_EPOCH: usize = 178;

pub const LIGHT_CLIENT_LEN: usize = 186;

/// The light-client state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LightClientState {
    pub bump: u8,
    /// Allowed to run `initialize`. Anyone may submit proofs.
    pub authority: Pubkey,
    pub accumulator_commitment: AccumulatorCommitment,
    /// Beacon state root of the most recently finalized block.
    pub latest_state_root: [u8; 32],
    pub finalized_epoch: u64,
    pub finalized_root: [u8; 32],
    /// Zisk verification key of the finalization guest, bound at bootstrap and
    /// never mutable.
    ///
    /// This is one of the two halves of the statement the wrap proves — see
    /// [`crate::plonk::public_input`]. It is deployment configuration rather
    /// than a compile-time constant because the guest is zkasper's and changes
    /// on zkasper's schedule, while the circuit constants in
    /// [`crate::plonk::vk`] are Zisk's. Scoping the state account by authority
    /// means "which guest do you trust" is answered by naming an authority.
    pub program_vk: ProgramVk,
    pub submission_count: u64,
    /// The epoch [`Self::accumulator_commitment`] belongs to: the epoch whose
    /// justification that accumulator was proven against.
    ///
    /// Equivalently, and this is how `submit_finalization` reads it: the
    /// `finalized_epoch` the next accepted proof must carry. A finalization
    /// starts from the accumulator its own finalized epoch was justified
    /// against, so a proof may extend this client only if it finalizes exactly
    /// this epoch.
    ///
    /// Checking it is what makes the chain consecutive rather than merely
    /// unbranched. The commitment alone cannot: [`AccumulatorCommitment`] binds
    /// a validator-set root and a total active balance and no epoch, so two
    /// epochs that left the set untouched commit to identical bytes and a
    /// skipped epoch would pass. That the set moves every epoch on mainnet is
    /// an observation about mainnet, not a property of the format.
    ///
    /// Consecutiveness is load-bearing because zkasper proves the supermajority
    /// vote and the ancestry of the finalized root but never the FFG link, which
    /// leaves a consumer only Casper's double-vote clause — and that clause
    /// binds only while every epoch in the sequence carries a supermajority
    /// vote. See `docs/finality/assumptions.md` in the zkasper repository.
    ///
    /// Always `finalized_epoch + 1`: bootstrap sets it so, and thereafter it is
    /// the accepted proof's `justified_epoch`, which the guest asserts is its
    /// `finalized_epoch + 1` ("justification epochs not consecutive",
    /// `crates/stream-final-guest/src/lib.rs`). It is stored rather than derived
    /// because it labels the accumulator, which is the value being matched.
    pub accumulator_epoch: u64,
}

fn u64_at(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

fn a32(data: &[u8], off: usize) -> [u8; 32] {
    data[off..off + 32].try_into().unwrap()
}

impl LightClientState {
    pub fn unpack(data: &[u8]) -> Result<Self, ZkasperError> {
        if data.len() < LIGHT_CLIENT_LEN {
            return Err(ZkasperError::AccountDataTooSmall);
        }
        if data[OFF_TAG] != TAG_LIGHT_CLIENT {
            return Err(ZkasperError::WrongAccountTag);
        }
        Ok(Self {
            bump: data[OFF_BUMP],
            authority: Pubkey::new_from_array(a32(data, OFF_AUTHORITY)),
            accumulator_commitment: a32(data, OFF_ACC_COMMITMENT),
            latest_state_root: a32(data, OFF_LATEST_STATE_ROOT),
            finalized_epoch: u64_at(data, OFF_FINALIZED_EPOCH),
            finalized_root: a32(data, OFF_FINALIZED_ROOT),
            program_vk: a32(data, OFF_PROGRAM_VK),
            submission_count: u64_at(data, OFF_SUBMISSION_COUNT),
            accumulator_epoch: u64_at(data, OFF_ACC_EPOCH),
        })
    }

    pub fn pack_into(&self, data: &mut [u8]) -> Result<(), ZkasperError> {
        if data.len() < LIGHT_CLIENT_LEN {
            return Err(ZkasperError::AccountDataTooSmall);
        }
        data[OFF_TAG] = TAG_LIGHT_CLIENT;
        data[OFF_BUMP] = self.bump;
        data[OFF_AUTHORITY..OFF_AUTHORITY + 32].copy_from_slice(self.authority.as_ref());
        data[OFF_ACC_COMMITMENT..OFF_ACC_COMMITMENT + 32]
            .copy_from_slice(&self.accumulator_commitment);
        data[OFF_LATEST_STATE_ROOT..OFF_LATEST_STATE_ROOT + 32]
            .copy_from_slice(&self.latest_state_root);
        data[OFF_FINALIZED_EPOCH..OFF_FINALIZED_EPOCH + 8]
            .copy_from_slice(&self.finalized_epoch.to_le_bytes());
        data[OFF_FINALIZED_ROOT..OFF_FINALIZED_ROOT + 32].copy_from_slice(&self.finalized_root);
        data[OFF_PROGRAM_VK..OFF_PROGRAM_VK + 32].copy_from_slice(&self.program_vk);
        data[OFF_SUBMISSION_COUNT..OFF_SUBMISSION_COUNT + 8]
            .copy_from_slice(&self.submission_count.to_le_bytes());
        data[OFF_ACC_EPOCH..OFF_ACC_EPOCH + 8]
            .copy_from_slice(&self.accumulator_epoch.to_le_bytes());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FinalizationRecord
// ---------------------------------------------------------------------------

const REC_OFF_TAG: usize = 0;
const REC_OFF_BUMP: usize = 1;
const REC_OFF_EPOCH: usize = 2;
const REC_OFF_ROOT: usize = 10;
const REC_OFF_STATE_ROOT: usize = 42;
const REC_OFF_ACC: usize = 74;
const REC_OFF_SLOT: usize = 106;

pub const FINALIZATION_RECORD_LEN: usize = 114;

/// One accepted finalization, addressed by epoch and never rewritten.
///
/// This is the read path: a consumer derives
/// `[SEED_FINALIZATION, authority, epoch.to_le_bytes()]` and reads the account,
/// or CPIs
/// [`crate::instruction::ZkasperInstruction::AssertFinalized`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizationRecord {
    pub bump: u8,
    pub finalized_epoch: u64,
    pub finalized_root: [u8; 32],
    pub finalized_state_root: [u8; 32],
    pub accumulator_commitment: AccumulatorCommitment,
    /// Solana slot the proof landed in.
    pub submitted_slot: u64,
}

impl FinalizationRecord {
    pub fn unpack(data: &[u8]) -> Result<Self, ZkasperError> {
        if data.len() < FINALIZATION_RECORD_LEN {
            return Err(ZkasperError::AccountDataTooSmall);
        }
        if data[REC_OFF_TAG] != TAG_FINALIZATION_RECORD {
            return Err(ZkasperError::WrongAccountTag);
        }
        Ok(Self {
            bump: data[REC_OFF_BUMP],
            finalized_epoch: u64_at(data, REC_OFF_EPOCH),
            finalized_root: a32(data, REC_OFF_ROOT),
            finalized_state_root: a32(data, REC_OFF_STATE_ROOT),
            accumulator_commitment: a32(data, REC_OFF_ACC),
            submitted_slot: u64_at(data, REC_OFF_SLOT),
        })
    }

    pub fn pack_into(&self, data: &mut [u8]) -> Result<(), ZkasperError> {
        if data.len() < FINALIZATION_RECORD_LEN {
            return Err(ZkasperError::AccountDataTooSmall);
        }
        data[REC_OFF_TAG] = TAG_FINALIZATION_RECORD;
        data[REC_OFF_BUMP] = self.bump;
        data[REC_OFF_EPOCH..REC_OFF_EPOCH + 8].copy_from_slice(&self.finalized_epoch.to_le_bytes());
        data[REC_OFF_ROOT..REC_OFF_ROOT + 32].copy_from_slice(&self.finalized_root);
        data[REC_OFF_STATE_ROOT..REC_OFF_STATE_ROOT + 32]
            .copy_from_slice(&self.finalized_state_root);
        data[REC_OFF_ACC..REC_OFF_ACC + 32].copy_from_slice(&self.accumulator_commitment);
        data[REC_OFF_SLOT..REC_OFF_SLOT + 8].copy_from_slice(&self.submitted_slot.to_le_bytes());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AnchorRecord
// ---------------------------------------------------------------------------

const ANC_OFF_TAG: usize = 0;
const ANC_OFF_BUMP: usize = 1;
const ANC_OFF_EPOCH: usize = 2;
const ANC_OFF_STATE_ROOT: usize = 10;

pub const ANCHOR_RECORD_LEN: usize = 42;

/// A beacon state root that some accepted finalization proof named.
///
/// This is the on-chain half of the mitigation for the `epoch-diff` successor
/// gap. A consumer that follows an off-chain accumulator chain checks that every
/// state root on that chain has an `AnchorRecord`; forging one needs 2/3 of the
/// real validator set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorRecord {
    pub bump: u8,
    pub finalized_epoch: u64,
    pub finalized_state_root: [u8; 32],
}

impl AnchorRecord {
    pub fn unpack(data: &[u8]) -> Result<Self, ZkasperError> {
        if data.len() < ANCHOR_RECORD_LEN {
            return Err(ZkasperError::AccountDataTooSmall);
        }
        if data[ANC_OFF_TAG] != TAG_ANCHOR_RECORD {
            return Err(ZkasperError::WrongAccountTag);
        }
        Ok(Self {
            bump: data[ANC_OFF_BUMP],
            finalized_epoch: u64_at(data, ANC_OFF_EPOCH),
            finalized_state_root: a32(data, ANC_OFF_STATE_ROOT),
        })
    }

    pub fn pack_into(&self, data: &mut [u8]) -> Result<(), ZkasperError> {
        if data.len() < ANCHOR_RECORD_LEN {
            return Err(ZkasperError::AccountDataTooSmall);
        }
        data[ANC_OFF_TAG] = TAG_ANCHOR_RECORD;
        data[ANC_OFF_BUMP] = self.bump;
        data[ANC_OFF_EPOCH..ANC_OFF_EPOCH + 8].copy_from_slice(&self.finalized_epoch.to_le_bytes());
        data[ANC_OFF_STATE_ROOT..ANC_OFF_STATE_ROOT + 32]
            .copy_from_slice(&self.finalized_state_root);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Address derivation
// ---------------------------------------------------------------------------

/// Every account is scoped to the authority that bootstrapped it.
///
/// A singleton state account would be first-come, so anyone could front-run the
/// deployer's `initialize` and pin the light client to a checkpoint of their
/// choosing. Scoping by authority removes that entirely: a consumer names the
/// authority it trusts, and an unwanted instance is just an account nobody
/// reads. It also lets one deployment serve several networks at once.
pub fn light_client_address(program_id: &Pubkey, authority: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_STATE, authority.as_ref()], program_id)
}

pub fn finalization_record_address(
    program_id: &Pubkey,
    authority: &Pubkey,
    epoch: u64,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[SEED_FINALIZATION, authority.as_ref(), &epoch.to_le_bytes()],
        program_id,
    )
}

pub fn anchor_record_address(
    program_id: &Pubkey,
    authority: &Pubkey,
    state_root: &[u8; 32],
) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_ANCHOR, authority.as_ref(), state_root], program_id)
}
