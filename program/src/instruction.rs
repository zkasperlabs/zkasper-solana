//! Instruction encoding and client-side builders.
//!
//! Decoded instructions borrow from the input buffer. The verifying key alone is
//! 640 bytes and an SBF stack frame is 4 KiB, so nothing large is ever moved
//! onto the stack.

use solana_program::instruction::{AccountMeta, Instruction};
use solana_program::pubkey::Pubkey;
use solana_system_interface::program as system_program;

use crate::error::ZkasperError;
use crate::state::{
    anchor_record_address, finalization_record_address, light_client_address, VK_LEN,
};
use crate::wire::FinalizationOutput;

pub const IX_INITIALIZE: u8 = 0;
pub const IX_SUBMIT_FINALIZATION: u8 = 1;
pub const IX_ASSERT_FINALIZED: u8 = 2;
pub const IX_ASSERT_ANCHORED: u8 = 3;
pub const IX_VERIFY_ONLY: u8 = 4;

pub const INITIALIZE_LEN: usize = 1 + 32 + 32 + 8 + 32 + 32 + VK_LEN;
pub const SUBMIT_FINALIZATION_LEN: usize = 1 + 64 + 128 + 64 + 32 + 32 + 8 + 32 + 32;
pub const ASSERT_FINALIZED_LEN: usize = 1 + 32 + 8 + 32;
pub const ASSERT_ANCHORED_LEN: usize = 1 + 32 + 32;
pub const VERIFY_ONLY_LEN: usize = SUBMIT_FINALIZATION_LEN;

#[derive(Clone, Copy, Debug)]
pub enum ZkasperInstruction<'a> {
    /// Trusted bootstrap. Creates the light-client state from an operator-chosen
    /// checkpoint and binds the Groth16 verifying key.
    ///
    /// Accounts:
    /// 0. `[signer, writable]` authority and rent payer
    /// 1. `[writable]`         light-client state PDA
    /// 2. `[]`                 system program
    Initialize {
        accumulator_commitment: &'a [u8; 32],
        latest_state_root: &'a [u8; 32],
        finalized_epoch: u64,
        finalized_root: &'a [u8; 32],
        program_vk: &'a [u8; 32],
        vk: &'a [u8; VK_LEN],
    },
    /// Verify a finalization proof and advance the light client. Permissionless.
    ///
    /// Accounts:
    /// 0. `[signer, writable]` rent payer
    /// 1. `[writable]`         light-client state PDA
    /// 2. `[writable]`         finalization record PDA for `finalized_epoch`
    /// 3. `[writable]`         anchor record PDA for `finalized_state_root`
    /// 4. `[]`                 system program
    SubmitFinalization {
        proof_a: &'a [u8; 64],
        proof_b: &'a [u8; 128],
        proof_c: &'a [u8; 64],
        output: FinalizationOutput,
    },
    /// Fail unless the light client bootstrapped by `authority` finalized
    /// `root` at `epoch`. Intended for CPI.
    ///
    /// `authority` is part of the instruction, not read from the account, so the
    /// caller states which light client it trusts rather than accepting whatever
    /// record it was handed.
    ///
    /// Accounts:
    /// 0. `[]` finalization record PDA for (`authority`, `epoch`)
    AssertFinalized {
        authority: Pubkey,
        epoch: u64,
        root: [u8; 32],
    },
    /// Fail unless a proof accepted by `authority`'s light client named
    /// `state_root`. Intended for CPI.
    ///
    /// Accounts:
    /// 0. `[]` anchor record PDA for (`authority`, `state_root`)
    AssertAnchored {
        authority: Pubkey,
        state_root: [u8; 32],
    },
    /// Check a proof against the bound verifying key without touching state.
    ///
    /// Lets a submitter confirm a proof through `simulateTransaction` before
    /// paying for account creation, and isolates the cost of verification when
    /// measuring compute units.
    ///
    /// Accounts:
    /// 0. `[]` light-client state PDA
    VerifyOnly {
        proof_a: &'a [u8; 64],
        proof_b: &'a [u8; 128],
        proof_c: &'a [u8; 64],
        output: FinalizationOutput,
    },
}

fn split<const N: usize>(data: &[u8], off: usize) -> Result<&[u8; N], ZkasperError> {
    data.get(off..off + N)
        .and_then(|s| s.try_into().ok())
        .ok_or(ZkasperError::InvalidInstructionData)
}

impl<'a> ZkasperInstruction<'a> {
    pub fn unpack(data: &'a [u8]) -> Result<Self, ZkasperError> {
        let (tag, _) = data
            .split_first()
            .ok_or(ZkasperError::InvalidInstructionData)?;
        match *tag {
            IX_INITIALIZE => {
                if data.len() != INITIALIZE_LEN {
                    return Err(ZkasperError::InvalidInstructionData);
                }
                Ok(Self::Initialize {
                    accumulator_commitment: split(data, 1)?,
                    latest_state_root: split(data, 33)?,
                    finalized_epoch: u64::from_le_bytes(*split::<8>(data, 65)?),
                    finalized_root: split(data, 73)?,
                    program_vk: split(data, 105)?,
                    vk: split(data, 137)?,
                })
            }
            IX_SUBMIT_FINALIZATION | IX_VERIFY_ONLY => {
                if data.len() != SUBMIT_FINALIZATION_LEN {
                    return Err(ZkasperError::InvalidInstructionData);
                }
                let proof_a = split(data, 1)?;
                let proof_b = split(data, 65)?;
                let proof_c = split(data, 193)?;
                let output = FinalizationOutput {
                    accumulator_commitment: *split(data, 257)?,
                    next_accumulator_commitment: *split(data, 289)?,
                    finalized_epoch: u64::from_le_bytes(*split::<8>(data, 321)?),
                    finalized_root: *split(data, 329)?,
                    finalized_state_root: *split(data, 361)?,
                };
                if *tag == IX_VERIFY_ONLY {
                    return Ok(Self::VerifyOnly {
                        proof_a,
                        proof_b,
                        proof_c,
                        output,
                    });
                }
                Ok(Self::SubmitFinalization {
                    proof_a,
                    proof_b,
                    proof_c,
                    output,
                })
            }
            IX_ASSERT_FINALIZED => {
                if data.len() != ASSERT_FINALIZED_LEN {
                    return Err(ZkasperError::InvalidInstructionData);
                }
                Ok(Self::AssertFinalized {
                    authority: Pubkey::new_from_array(*split(data, 1)?),
                    epoch: u64::from_le_bytes(*split::<8>(data, 33)?),
                    root: *split(data, 41)?,
                })
            }
            IX_ASSERT_ANCHORED => {
                if data.len() != ASSERT_ANCHORED_LEN {
                    return Err(ZkasperError::InvalidInstructionData);
                }
                Ok(Self::AssertAnchored {
                    authority: Pubkey::new_from_array(*split(data, 1)?),
                    state_root: *split(data, 33)?,
                })
            }
            _ => Err(ZkasperError::InvalidInstructionData),
        }
    }
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn initialize(
    program_id: &Pubkey,
    authority: &Pubkey,
    accumulator_commitment: &[u8; 32],
    latest_state_root: &[u8; 32],
    finalized_epoch: u64,
    finalized_root: &[u8; 32],
    program_vk: &[u8; 32],
    vk: &[u8; VK_LEN],
) -> Instruction {
    let (state, _) = light_client_address(program_id, authority);
    let mut data = Vec::with_capacity(INITIALIZE_LEN);
    data.push(IX_INITIALIZE);
    data.extend_from_slice(accumulator_commitment);
    data.extend_from_slice(latest_state_root);
    data.extend_from_slice(&finalized_epoch.to_le_bytes());
    data.extend_from_slice(finalized_root);
    data.extend_from_slice(program_vk);
    data.extend_from_slice(vk);
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new(state, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

pub fn submit_finalization(
    program_id: &Pubkey,
    authority: &Pubkey,
    payer: &Pubkey,
    proof_a: &[u8; 64],
    proof_b: &[u8; 128],
    proof_c: &[u8; 64],
    output: &FinalizationOutput,
) -> Instruction {
    let (state, _) = light_client_address(program_id, authority);
    let (record, _) = finalization_record_address(program_id, authority, output.finalized_epoch);
    let (anchor, _) = anchor_record_address(program_id, authority, &output.finalized_state_root);
    let mut data = Vec::with_capacity(SUBMIT_FINALIZATION_LEN);
    data.push(IX_SUBMIT_FINALIZATION);
    data.extend_from_slice(proof_a);
    data.extend_from_slice(proof_b);
    data.extend_from_slice(proof_c);
    data.extend_from_slice(&output.accumulator_commitment);
    data.extend_from_slice(&output.next_accumulator_commitment);
    data.extend_from_slice(&output.finalized_epoch.to_le_bytes());
    data.extend_from_slice(&output.finalized_root);
    data.extend_from_slice(&output.finalized_state_root);
    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(state, false),
            AccountMeta::new(record, false),
            AccountMeta::new(anchor, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data,
    }
}

pub fn assert_finalized(
    program_id: &Pubkey,
    authority: &Pubkey,
    epoch: u64,
    root: &[u8; 32],
) -> Instruction {
    let (record, _) = finalization_record_address(program_id, authority, epoch);
    let mut data = Vec::with_capacity(ASSERT_FINALIZED_LEN);
    data.push(IX_ASSERT_FINALIZED);
    data.extend_from_slice(authority.as_ref());
    data.extend_from_slice(&epoch.to_le_bytes());
    data.extend_from_slice(root);
    Instruction {
        program_id: *program_id,
        accounts: vec![AccountMeta::new_readonly(record, false)],
        data,
    }
}

pub fn assert_anchored(
    program_id: &Pubkey,
    authority: &Pubkey,
    state_root: &[u8; 32],
) -> Instruction {
    let (anchor, _) = anchor_record_address(program_id, authority, state_root);
    let mut data = Vec::with_capacity(ASSERT_ANCHORED_LEN);
    data.push(IX_ASSERT_ANCHORED);
    data.extend_from_slice(authority.as_ref());
    data.extend_from_slice(state_root);
    Instruction {
        program_id: *program_id,
        accounts: vec![AccountMeta::new_readonly(anchor, false)],
        data,
    }
}

pub fn verify_only(
    program_id: &Pubkey,
    authority: &Pubkey,
    proof_a: &[u8; 64],
    proof_b: &[u8; 128],
    proof_c: &[u8; 64],
    output: &FinalizationOutput,
) -> Instruction {
    let (state, _) = light_client_address(program_id, authority);
    let mut ix = submit_finalization(
        program_id, authority, &state, proof_a, proof_b, proof_c, output,
    );
    ix.data[0] = IX_VERIFY_ONLY;
    ix.accounts = vec![AccountMeta::new_readonly(state, false)];
    ix
}
