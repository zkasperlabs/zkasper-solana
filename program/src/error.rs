//! Program errors.

use solana_program::program_error::ProgramError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ZkasperError {
    InvalidInstructionData = 0,
    AccountAlreadyInitialized = 1,
    WrongAccountTag = 3,
    InvalidStateAccount = 4,
    InvalidRecordAccount = 5,
    InvalidAnchorAccount = 6,
    MissingSigner = 7,
    /// The PLONK check failed: a malformed proof, a point off the curve, or a
    /// proof of a statement other than the one claimed.
    ProofVerificationFailed = 8,
    /// `finalized_epoch` did not strictly increase.
    EpochNotAdvancing = 9,
    /// The record does not name the checkpoint the caller asked about.
    CheckpointNotFinalized = 10,
    /// No finalization proof has ever named this beacon state root.
    StateRootNotAnchored = 11,
    AccountDataTooSmall = 14,
    /// The finalization starts from an accumulator this client does not hold.
    ///
    /// Each finalization names both ends of one proven epoch transition, so a
    /// mismatch here means the proof belongs to a different accumulator chain —
    /// a branch. Rejecting is what keeps the chain unbroken without the program
    /// ever seeing an epoch-diff proof.
    AccumulatorMismatch = 15,
    /// The staging account is not this submitter's proof buffer.
    InvalidProofBuffer = 16,
}

impl From<ZkasperError> for ProgramError {
    fn from(e: ZkasperError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
