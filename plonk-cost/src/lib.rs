//! What a Zisk PLONK wrap costs to verify on Solana, decomposed.
//!
//! This crate answers one question with a number rather than a guess, and it
//! answers it about the code that actually ships: every mode below calls into
//! [`zkasper_solana_program::plonk`], the verifier the on-chain program runs.
//! Nothing here reimplements it.
//!
//! The [`entrypoint`] dispatch exists so the total can be decomposed: each mode
//! is a separate transaction, and the difference between two of them is the cost
//! of what changed.

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint;

/// `[mode, count_le_u16, program_vk(32), publics(176), proof(768)]`.
pub const PAYLOAD_OFF_PROGRAM_VK: usize = 3;
pub const PAYLOAD_OFF_PUBLICS: usize = PAYLOAD_OFF_PROGRAM_VK + 32;
pub const PAYLOAD_OFF_PROOF: usize =
    PAYLOAD_OFF_PUBLICS + zkasper_solana_program::wire::FINALIZATION_PUBLIC_BYTES;
