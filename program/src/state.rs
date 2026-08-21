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
pub const TAG_FINALIZATION_RING: u8 = 2;
/// Marks a ring slot as written.
///
/// A slot nothing has reached yet reads as zeros, and zero is a valid epoch and
/// a valid root, so this byte is the whole of what separates "never written"
/// from "epoch 0, root 0x00..00".
pub const TAG_RING_ENTRY: u8 = 3;

pub const SEED_STATE: &[u8] = b"zkasper-state";
pub const SEED_RING: &[u8] = b"zkasper-ring";

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
    /// an observation about mainnet, not a property of the format; on a chain
    /// whose set does not move it is the only thing ordering finalizations.
    ///
    /// What consecutiveness buys depends on the guest. Against one that leaves
    /// the FFG source unconstrained it is safety: a consumer holds only Casper's
    /// double-vote clause, and that clause binds while every epoch in the
    /// sequence carries a supermajority vote. Against one that constrains it the
    /// circuits prove the one-epoch rule, gaps become legitimate, and the
    /// equality survives for a different reason — the accumulator across a gap
    /// was produced by an epoch diff no proof this program can verify has ever
    /// covered, so the chain cannot be walked over it. See
    /// `docs/finality/assumptions.md` in the zkasper repository.
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
// FinalizationRing
// ---------------------------------------------------------------------------

/// How many finalizations the ring keeps.
///
/// An Ethereum epoch is 6.4 minutes, so this is **13.6 hours** of history. A
/// consumer that may be asked about a finalization older than that has to check
/// the window before relying on the ring; see the README.
pub const RING_ENTRIES: usize = 128;

const RING_OFF_TAG: usize = 0;
const RING_OFF_BUMP: usize = 1;
const RING_HEADER_LEN: usize = 2;

const ENT_OFF_TAG: usize = 0;
const ENT_OFF_EPOCH: usize = 1;
const ENT_OFF_ROOT: usize = 9;
const ENT_OFF_STATE_ROOT: usize = 41;

pub const RING_ENTRY_LEN: usize = 73;

/// 9,346 bytes.
///
/// The ceiling is 10,240: a program may grow an account by at most
/// `MAX_PERMITTED_DATA_INCREASE` in one instruction, and creating a PDA is a
/// growth from zero, so anything larger could not be allocated at bootstrap in
/// one go. That budget is why an entry carries exactly what the two read paths
/// need and nothing else — the retired record's `accumulator_commitment` and
/// `submitted_slot` would cost 40 bytes an entry, and 128 of those do not fit.
pub const RING_LEN: usize = RING_HEADER_LEN + RING_ENTRIES * RING_ENTRY_LEN;

/// One accepted finalization, as the ring holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizationEntry {
    pub finalized_epoch: u64,
    pub finalized_root: [u8; 32],
    /// Beacon state root of the finalized block. The reverse index a consumer
    /// walking an off-chain accumulator chain queries.
    pub finalized_state_root: [u8; 32],
}

/// The last [`RING_ENTRIES`] accepted finalizations, one account, written in
/// place at `epoch % RING_ENTRIES`.
///
/// This is the read path: a consumer derives `[SEED_RING, authority]` and reads
/// the account, or CPIs
/// [`crate::instruction::ZkasperInstruction::AssertFinalized`] or
/// [`crate::instruction::ZkasperInstruction::AssertAnchored`].
///
/// A ring replaces one non-closeable account per epoch — 412 billable bytes an
/// epoch, forever — with one account that is paid for once. What it costs is
/// depth: a finalization older than [`RING_ENTRIES`] epochs is no longer on
/// chain, and no read path can answer for it.
pub struct FinalizationRing;

impl FinalizationRing {
    /// Stamp the header of a freshly created, zeroed account. Every slot is
    /// empty until an epoch reaches it.
    pub fn init(data: &mut [u8], bump: u8) -> Result<(), ZkasperError> {
        if data.len() < RING_LEN {
            return Err(ZkasperError::AccountDataTooSmall);
        }
        data[RING_OFF_TAG] = TAG_FINALIZATION_RING;
        data[RING_OFF_BUMP] = bump;
        Ok(())
    }

    /// The bump the ring was created under, so a reader can confirm the account
    /// is the ring PDA with one hash rather than a `find_program_address` walk.
    pub fn bump(data: &[u8]) -> Result<u8, ZkasperError> {
        Self::header(data)?;
        Ok(data[RING_OFF_BUMP])
    }

    /// Overwrite the slot this epoch owns, retiring whatever epoch held it.
    ///
    /// The slot is derived from the entry rather than passed in, so no caller
    /// can write an epoch into a slot that will not be found again.
    pub fn write(data: &mut [u8], entry: &FinalizationEntry) -> Result<(), ZkasperError> {
        Self::header(data)?;
        let at = Self::offset(Self::index_of(entry.finalized_epoch));
        data[at + ENT_OFF_TAG] = TAG_RING_ENTRY;
        data[at + ENT_OFF_EPOCH..at + ENT_OFF_EPOCH + 8]
            .copy_from_slice(&entry.finalized_epoch.to_le_bytes());
        data[at + ENT_OFF_ROOT..at + ENT_OFF_ROOT + 32].copy_from_slice(&entry.finalized_root);
        data[at + ENT_OFF_STATE_ROOT..at + ENT_OFF_STATE_ROOT + 32]
            .copy_from_slice(&entry.finalized_state_root);
        Ok(())
    }

    /// The entry for `epoch`, or [`ZkasperError::EpochNotInRing`].
    ///
    /// The index alone proves nothing. Slot `epoch % RING_ENTRIES` holds
    /// whichever congruent epoch was written last, so 128 epochs later the same
    /// bytes answer for a different epoch. Comparing the stored epoch is the
    /// whole safety of the ring, and it is done here — the slot is never handed
    /// out — so no caller can index without it.
    pub fn entry(data: &[u8], epoch: u64) -> Result<FinalizationEntry, ZkasperError> {
        Self::header(data)?;
        Self::slot(data, Self::index_of(epoch))
            .filter(|entry| entry.finalized_epoch == epoch)
            .ok_or(ZkasperError::EpochNotInRing)
    }

    /// The entry some accepted proof named `state_root` in, by a linear pass
    /// over the ring.
    ///
    /// Two epochs cannot share a beacon state root, so at most one slot matches.
    /// This is what the separate anchor account used to be: a reverse index, at
    /// the cost of a scan rather than of an address.
    pub fn entry_by_state_root(
        data: &[u8],
        state_root: &[u8; 32],
    ) -> Result<FinalizationEntry, ZkasperError> {
        Self::header(data)?;
        // Compared in place. Unpacking each slot to compare it would copy 72
        // bytes 128 times and more than doubles what the pass costs.
        let index = (0..RING_ENTRIES)
            .find(|index| {
                let at = Self::offset(*index);
                data[at + ENT_OFF_TAG] == TAG_RING_ENTRY
                    && data[at + ENT_OFF_STATE_ROOT..at + ENT_OFF_STATE_ROOT + 32] == *state_root
            })
            .ok_or(ZkasperError::StateRootNotAnchored)?;
        Self::slot(data, index).ok_or(ZkasperError::StateRootNotAnchored)
    }

    fn header(data: &[u8]) -> Result<(), ZkasperError> {
        if data.len() < RING_LEN {
            return Err(ZkasperError::AccountDataTooSmall);
        }
        if data[RING_OFF_TAG] != TAG_FINALIZATION_RING {
            return Err(ZkasperError::WrongAccountTag);
        }
        Ok(())
    }

    /// The slot an epoch owns, and the only place it is ever written or looked
    /// for.
    fn index_of(epoch: u64) -> usize {
        (epoch % RING_ENTRIES as u64) as usize
    }

    fn offset(index: usize) -> usize {
        RING_HEADER_LEN + index * RING_ENTRY_LEN
    }

    /// `None` when nothing has been written to this slot yet.
    fn slot(data: &[u8], index: usize) -> Option<FinalizationEntry> {
        let at = Self::offset(index);
        if data[at + ENT_OFF_TAG] != TAG_RING_ENTRY {
            return None;
        }
        Some(FinalizationEntry {
            finalized_epoch: u64_at(data, at + ENT_OFF_EPOCH),
            finalized_root: a32(data, at + ENT_OFF_ROOT),
            finalized_state_root: a32(data, at + ENT_OFF_STATE_ROOT),
        })
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

pub fn finalization_ring_address(program_id: &Pubkey, authority: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[SEED_RING, authority.as_ref()], program_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(epoch: u64) -> FinalizationEntry {
        FinalizationEntry {
            finalized_epoch: epoch,
            finalized_root: [epoch as u8; 32],
            finalized_state_root: [!(epoch as u8); 32],
        }
    }

    fn ring() -> Vec<u8> {
        let mut data = vec![0u8; RING_LEN];
        FinalizationRing::init(&mut data, 254).unwrap();
        data
    }

    #[test]
    fn an_entry_round_trips() {
        let mut data = ring();
        FinalizationRing::write(&mut data, &entry(469_426)).unwrap();
        assert_eq!(FinalizationRing::bump(&data), Ok(254));
        assert_eq!(FinalizationRing::entry(&data, 469_426), Ok(entry(469_426)));
    }

    /// The check the whole design rests on: the slot an epoch lands in comes
    /// back 128 epochs later holding someone else.
    #[test]
    fn a_wrapped_slot_does_not_answer_for_the_epoch_it_replaced() {
        let mut data = ring();
        FinalizationRing::write(&mut data, &entry(1_000)).unwrap();
        FinalizationRing::write(&mut data, &entry(1_000 + RING_ENTRIES as u64)).unwrap();
        assert_eq!(
            FinalizationRing::entry(&data, 1_000),
            Err(ZkasperError::EpochNotInRing)
        );
        assert_eq!(
            FinalizationRing::entry(&data, 1_000 + RING_ENTRIES as u64),
            Ok(entry(1_000 + RING_ENTRIES as u64))
        );
    }

    /// A zeroed slot reads as epoch 0 with an all-zero root, and must not be
    /// mistaken for a finalization of it.
    #[test]
    fn an_untouched_slot_is_not_a_finalization_of_epoch_zero() {
        let data = ring();
        assert_eq!(
            FinalizationRing::entry(&data, 0),
            Err(ZkasperError::EpochNotInRing)
        );
        assert_eq!(
            FinalizationRing::entry_by_state_root(&data, &[0u8; 32]),
            Err(ZkasperError::StateRootNotAnchored)
        );
    }

    #[test]
    fn the_scan_finds_the_state_root_and_the_epoch_that_named_it() {
        let mut data = ring();
        for epoch in 1..=RING_ENTRIES as u64 {
            FinalizationRing::write(&mut data, &entry(epoch)).unwrap();
        }
        let wanted = entry(RING_ENTRIES as u64 - 1);
        assert_eq!(
            FinalizationRing::entry_by_state_root(&data, &wanted.finalized_state_root),
            Ok(wanted)
        );
        // Every state root written above is a uniform byte, so a root that is
        // not uniform is one no entry can hold.
        let mut unknown = [0u8; 32];
        unknown[0] = 1;
        assert_eq!(
            FinalizationRing::entry_by_state_root(&data, &unknown),
            Err(ZkasperError::StateRootNotAnchored)
        );
    }
}
