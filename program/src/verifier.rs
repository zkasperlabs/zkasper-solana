//! Groth16 over BN254, through Solana's `alt_bn128` syscalls.
//!
//! The pairing itself is [`groth16_solana`] (Light Protocol), which is a thin
//! shell over `sol_alt_bn128_group_op` and `sol_alt_bn128_pairing`. Nothing here
//! reimplements curve arithmetic; the only field operation this module owns is
//! negating the y coordinate of `proof_a`, so that submitted proofs can stay in
//! the canonical serialization every other Groth16 tool emits.

use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};

use crate::error::ZkasperError;
use crate::state::{
    NUM_PUBLIC_INPUTS, VK_IC_LEN, VK_LEN, VK_OFF_ALPHA_G1, VK_OFF_BETA_G2, VK_OFF_DELTA_G2,
    VK_OFF_GAMMA_G2, VK_OFF_IC,
};

/// BN254 base field modulus, most significant limb first.
const FQ_MODULUS: [u64; 4] = [
    0x3064_4E72_E131_A029,
    0xB850_45B6_8181_585D,
    0x9781_6A91_6871_CA8D,
    0x3C20_8C16_D87C_FD47,
];

fn limbs_be(bytes: &[u8]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u64::from_be_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
    }
    out
}

/// `(x, y)` becomes `(x, -y)`, in the EIP-197 big-endian encoding.
///
/// [`Groth16Verifier`] checks `e(A, B) == e(alpha, beta) * e(PI, gamma) *
/// e(C, delta)` by asking for a single pairing product to equal one, which needs
/// `-A` rather than `A`. Doing that here rather than in the client means a proof
/// straight out of snarkjs, arkworks or gnark can be submitted unmodified.
fn negate_g1(point: &[u8; 64]) -> Result<[u8; 64], ZkasperError> {
    let y = limbs_be(&point[32..64]);
    if y >= FQ_MODULUS {
        return Err(ZkasperError::ProofVerificationFailed);
    }

    let mut out = *point;
    // The point at infinity is encoded (0, 0), and its negation is itself.
    if y == [0; 4] {
        return Ok(out);
    }

    let mut borrow = 0u64;
    for i in (0..4).rev() {
        let (d, b1) = FQ_MODULUS[i].overflowing_sub(y[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        out[32 + i * 8..40 + i * 8].copy_from_slice(&d.to_be_bytes());
        borrow = u64::from(b1) + u64::from(b2);
    }
    Ok(out)
}

fn g1(vk: &[u8], off: usize) -> [u8; 64] {
    vk[off..off + 64].try_into().unwrap()
}

fn g2(vk: &[u8], off: usize) -> [u8; 128] {
    vk[off..off + 128].try_into().unwrap()
}

/// Check a Groth16 proof against a verifying key held in account data.
pub fn verify(
    vk_bytes: &[u8],
    proof_a: &[u8; 64],
    proof_b: &[u8; 128],
    proof_c: &[u8; 64],
    public_inputs: &[[u8; 32]; NUM_PUBLIC_INPUTS],
) -> Result<(), ZkasperError> {
    if vk_bytes.len() < VK_LEN {
        return Err(ZkasperError::InvalidVerifyingKey);
    }

    let mut ic = [[0u8; 64]; VK_IC_LEN];
    for (i, slot) in ic.iter_mut().enumerate() {
        *slot = g1(vk_bytes, VK_OFF_IC + i * 64);
    }
    let vk = Groth16Verifyingkey {
        nr_pubinputs: NUM_PUBLIC_INPUTS,
        vk_alpha_g1: g1(vk_bytes, VK_OFF_ALPHA_G1),
        vk_beta_g2: g2(vk_bytes, VK_OFF_BETA_G2),
        vk_gamme_g2: g2(vk_bytes, VK_OFF_GAMMA_G2),
        vk_delta_g2: g2(vk_bytes, VK_OFF_DELTA_G2),
        vk_ic: &ic,
    };

    let neg_a = negate_g1(proof_a)?;
    Groth16Verifier::new(&neg_a, proof_b, proof_c, public_inputs, &vk)
        .map_err(|_| ZkasperError::InvalidVerifyingKey)?
        .verify()
        .map_err(|_| ZkasperError::ProofVerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negating_twice_is_the_identity() {
        let mut point = [0u8; 64];
        point[32..64].copy_from_slice(&[
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ]);
        assert_eq!(negate_g1(&negate_g1(&point).unwrap()).unwrap(), point);
    }

    #[test]
    fn infinity_negates_to_itself() {
        assert_eq!(negate_g1(&[0u8; 64]).unwrap(), [0u8; 64]);
    }

    #[test]
    fn out_of_range_y_is_rejected() {
        assert!(negate_g1(&[0xff; 64]).is_err());
    }
}
