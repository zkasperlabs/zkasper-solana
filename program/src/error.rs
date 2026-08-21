//! Program errors.

use solana_program::program_error::ProgramError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ZkasperError {
    InvalidInstructionData = 0,
    AccountAlreadyInitialized = 1,
    WrongAccountTag = 3,
    InvalidStateAccount = 4,
    InvalidRingAccount = 5,
    MissingSigner = 7,
    /// The PLONK check failed: a malformed proof, a point off the curve, or a
    /// proof of a statement other than the one claimed.
    ProofVerificationFailed = 8,
    /// `finalized_epoch` did not strictly increase.
    EpochNotAdvancing = 9,
    /// The ring holds the epoch asked about, and it finalized a different root.
    CheckpointNotFinalized = 10,
    /// No finalization still in the ring named this beacon state root.
    ///
    /// Bounded by the window, like [`Self::EpochNotInRing`]: it means "not in
    /// the last 128 epochs", not "never".
    StateRootNotAnchored = 11,
    /// The ring does not carry that epoch — it aged out of the 128-epoch
    /// window, or this light client has not reached it.
    ///
    /// Deliberately not [`Self::CheckpointNotFinalized`]. That one is a claim
    /// about Ethereum; this one is a claim about how much history is on chain,
    /// and a consumer that treats "no longer stored" as "never finalized" would
    /// be reading a fact that was never asserted.
    EpochNotInRing = 12,
    AccountDataTooSmall = 14,
    /// The finalization starts from an accumulator this client does not hold,
    /// at the epoch it does hold.
    ///
    /// Each finalization names both ends of one proven epoch transition, so a
    /// mismatch here means the proof belongs to a different accumulator chain —
    /// a branch. Rejecting is what keeps the chain unbroken without the program
    /// ever seeing an epoch-diff proof.
    ///
    /// Checked after [`Self::AccumulatorEpochMismatch`], so it is a branch and
    /// never a skipped epoch: a gap moves the accumulator too, and reporting one
    /// as the other sends an operator hunting an attacker who is not there.
    AccumulatorMismatch = 15,
    /// The submission does not finalize the epoch this client's accumulator
    /// belongs to — it skips one, and a gap cannot be crossed.
    ///
    /// Against a guest that constrains the FFG source this is not a claim that
    /// the submission is false. Those circuits prove the specification's
    /// one-epoch rule exactly, so an epoch the chain finalized by the two-epoch
    /// rule is simply one no proof of this shape exists for, and
    /// `finalized_epoch` may legitimately jump. What cannot be done is the
    /// crossing: the accumulator on the far side differs from the one held here
    /// by an epoch diff no proof this program can verify has ever covered, and
    /// adopting it on the submitter's word would hand over the validator set.
    /// **A client that sees this is stranded rather than under attack, and has
    /// to be bootstrapped again above the gap.**
    ///
    /// [`Self::AccumulatorMismatch`] cannot catch this on its own: an
    /// accumulator commitment binds the validator-set root and the total active
    /// balance, and no epoch, so two epochs that did not change the set commit
    /// to the same 32 bytes.
    AccumulatorEpochMismatch = 17,
}

impl From<ZkasperError> for ProgramError {
    fn from(e: ZkasperError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
