//! On-chain verifier for zkasper Ethereum finality proofs.
//!
//! zkasper proves, in a Zisk zkVM, that an Ethereum beacon-chain checkpoint was
//! finalized under Casper FFG by at least two thirds of the *full* validator
//! set. This program holds a light-client state account, checks the PLONK wrap
//! of that proof with Solana's BN254 syscalls, and advances the state.
//!
//! A wrapped proof is 768 bytes, which does not fit a Solana packet beside the
//! output it attests to. Compressing the nine G1 commitments halves each of them
//! and brings the submission to 480 bytes of proof, so `SubmitFinalization`
//! carries it inline and a submission is one transaction.
//!
//! See the README for the trust model, and in particular for the `epoch-diff`
//! successor gap that makes the anchor records in [`state::AnchorRecord`] load
//! bearing.

pub mod error;
pub mod instruction;
pub mod plonk;
pub mod processor;
pub mod state;
pub mod wire;

solana_program::declare_id!("Cuarryex9DFpVm6HNdCFvpS3EEeArSuTXDMNTk9hpKja");

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(entry);

#[cfg(not(feature = "no-entrypoint"))]
fn entry(
    program_id: &solana_program::pubkey::Pubkey,
    accounts: &[solana_program::account_info::AccountInfo],
    data: &[u8],
) -> solana_program::entrypoint::ProgramResult {
    processor::process_instruction(program_id, accounts, data)
}
