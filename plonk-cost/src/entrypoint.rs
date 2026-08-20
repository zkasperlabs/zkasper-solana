//! One instruction, several modes, so the total decomposes.
//!
//! Every mode runs in its own transaction. The difference between a mode and
//! [`Mode::Baseline`] is what that mode's work cost; the difference between two
//! loop counts is the marginal cost of one operation, with the loop's own
//! overhead cancelled out.

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use solana_bn254::prelude::{
    alt_bn128_g1_addition_be, alt_bn128_g1_multiplication_be, alt_bn128_pairing_be,
};
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, keccak, program_error::ProgramError,
    pubkey::Pubkey,
};

use crate::{vk, Proof};

solana_program::entrypoint!(process_instruction);

/// `[mode, count_le_u16, payload..]`. The payload is the same for every mode:
/// 176 bytes of guest output then the 768-byte proof.
pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let (mode, rest) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let count = u16::from_le_bytes([rest[0], rest[1]]) as usize;
    let payload = &rest[2..];
    let publics = &payload[..crate::PUBLICS_LEN];
    let proof_bytes = &payload[crate::PUBLICS_LEN..];

    // Parsing is charged to the baseline, so no mode pays for it alone.
    let proof = Proof::parse(proof_bytes).ok_or(ProgramError::InvalidInstructionData)?;

    let ok = match mode {
        // Parse and return. Everything a submission costs before any
        // cryptography: the loader, the entrypoint, deserialization.
        0 => true,
        // The whole verification.
        1 => crate::verify(proof_bytes, publics),
        // The same without `checkProofData`, which the syscalls make redundant.
        10 => crate::verify_with(proof_bytes, publics, false),
        // `count` scalar multiplications, chained so none can be elided.
        2 => {
            let mut point = vk::G1_GEN;
            for i in 0..count {
                point = mul(&point, &Fr::from(i as u64 + 7));
            }
            point != [0u8; 64]
        }
        // `count` point additions.
        3 => {
            let mut point = proof.a;
            for _ in 0..count {
                point = add(&point, &vk::G1_GEN);
            }
            point != [0u8; 64]
        }
        // One pairing of two pairs, the check PLONK ends on.
        4 => {
            let mut input = [0u8; 384];
            input[..64].copy_from_slice(&vk::G1_GEN);
            input[64..192].copy_from_slice(&vk::X_2);
            input[192..256].copy_from_slice(&vk::G1_GEN);
            input[256..].copy_from_slice(&vk::G2_GEN);
            alt_bn128_pairing_be(&input).is_ok()
        }
        // `count` field multiplications, in software.
        5 => {
            let mut acc = proof.eval_a;
            for _ in 0..count {
                acc *= proof.eval_b;
            }
            acc != Fr::from(0u64)
        }
        // `count` field inversions.
        6 => {
            let mut acc = proof.eval_a;
            for _ in 0..count {
                acc = acc.inverse().unwrap() + proof.eval_b;
            }
            acc != Fr::from(0u64)
        }
        // The six-hash Fiat-Shamir transcript, 1,472 bytes in total.
        7 => {
            let mut acc = 0u8;
            for len in [736usize, 32, 128, 224, 224, 128] {
                let buf = vec![acc; len];
                acc ^= keccak::hash(&buf).as_ref()[0];
            }
            acc != 0xff
        }
        // `checkProofData`: nine curve-membership tests, thirty-four range
        // checks. No syscalls.
        8 => proof.well_formed(),
        // The public input: one SHA-256 over 320 bytes and a reduction.
        9 => crate::public_input(publics) != Fr::from(0u64),
        _ => return Err(ProgramError::InvalidInstructionData),
    };

    if !ok {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

fn mul(point: &vk::G1, scalar: &Fr) -> vk::G1 {
    let mut input = [0u8; 96];
    input[..64].copy_from_slice(point);
    input[64..].copy_from_slice(&scalar.into_bigint().to_bytes_be());
    let out = alt_bn128_g1_multiplication_be(&input).expect("mul");
    let mut r = [0u8; 64];
    r.copy_from_slice(&out);
    r
}

fn add(a: &vk::G1, b: &vk::G1) -> vk::G1 {
    let mut input = [0u8; 128];
    input[..64].copy_from_slice(a);
    input[64..].copy_from_slice(b);
    let out = alt_bn128_g1_addition_be(&input).expect("add");
    let mut r = [0u8; 64];
    r.copy_from_slice(&out);
    r
}
