//! Program errors.

use solana_program::program_error::ProgramError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ZkasperError {
    InvalidInstructionData = 0,
    AccountAlreadyInitialized = 1,
    AccountNotInitialized = 2,
    WrongAccountTag = 3,
    InvalidStateAccount = 4,
    InvalidRecordAccount = 5,
    InvalidAnchorAccount = 6,
    MissingSigner = 7,
    /// The Groth16 pairing check failed.
    ProofVerificationFailed = 8,
    /// `finalized_epoch` did not strictly increase.
    EpochNotAdvancing = 9,
    /// The record does not name the checkpoint the caller asked about.
    CheckpointNotFinalized = 10,
    /// No finalization proof has ever named this beacon state root.
    StateRootNotAnchored = 11,
    /// A public input was not a canonical BN254 scalar.
    InvalidPublicInput = 12,
    InvalidVerifyingKey = 13,
    AccountDataTooSmall = 14,
}

impl From<ZkasperError> for ProgramError {
    fn from(e: ZkasperError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
