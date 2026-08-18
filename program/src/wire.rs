//! The zkasper wire format, mirrored byte-for-byte on chain.
//!
//! Everything in this module is a restatement of code that lives in the zkasper
//! repository. If either side changes, proofs stop verifying, so the two must be
//! kept in step:
//!
//! * `FinalizationOutput::public_bytes` — `crates/common/src/types.rs`
//! * `PublicWriter`                     — `crates/common/src/recursion.rs`
//! * `Digest = [u64; 4]`                — `crates/common/src/acc.rs`

use solana_program::hash::hashv;

/// Byte length of `FinalizationOutput::public_bytes()`.
///
/// `PublicWriter` writes fixed-width little-endian fields with no framing:
/// a 4-element Goldilocks digest (4 x u64 LE), a u64 LE, and two 32-byte roots.
pub const FINALIZATION_PUBLIC_BYTES: usize = 32 + 8 + 32 + 32;

/// A zkasper accumulator digest: 4 Goldilocks elements, each little-endian.
///
/// Held as bytes rather than `[u64; 4]` because that is how it crosses the wire
/// in both directions, and the program never does field arithmetic on it.
pub type AccumulatorCommitment = [u8; 32];

/// The Zisk program verification key of the finalization guest, 4 u64s LE.
pub type ProgramVk = [u8; 32];

/// Public outputs of a zkasper finalization proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizationOutput {
    pub accumulator_commitment: AccumulatorCommitment,
    pub finalized_epoch: u64,
    pub finalized_root: [u8; 32],
    /// Beacon state root of the finalized block, opened from its header.
    ///
    /// This is the retroactive anchor described in the README: `epoch-diff`
    /// proves a registry delta between two claimed state roots but not that the
    /// second is the canonical successor of the first, so a consumer must
    /// require every state root its accumulator passed through to be named here
    /// by some later finalization proof.
    pub finalized_state_root: [u8; 32],
}

impl FinalizationOutput {
    /// Exactly the bytes `FinalizationOutput::public_bytes()` produces in
    /// zkasper, in the same order and with the same widths.
    pub fn public_bytes(&self) -> [u8; FINALIZATION_PUBLIC_BYTES] {
        let mut out = [0u8; FINALIZATION_PUBLIC_BYTES];
        out[0..32].copy_from_slice(&self.accumulator_commitment);
        out[32..40].copy_from_slice(&self.finalized_epoch.to_le_bytes());
        out[40..72].copy_from_slice(&self.finalized_root);
        out[72..104].copy_from_slice(&self.finalized_state_root);
        out
    }
}

/// Reduce a 32-byte digest to a canonical BN254 scalar by clearing the top
/// three bits.
///
/// The result is below 2^253, and the BN254 scalar field order is above
/// 2^253.5, so the value is always canonical and no rejection sampling is
/// needed. The same masking convention is used by SP1's Groth16 wrap.
pub fn mask_to_scalar(mut digest: [u8; 32]) -> [u8; 32] {
    digest[0] &= 0x1f;
    digest
}

/// First public input of the Groth16 wrap: which Zisk guest produced the proof.
pub fn program_vk_input(program_vk: &ProgramVk) -> [u8; 32] {
    mask_to_scalar(hashv(&[program_vk]).to_bytes())
}

/// Second public input of the Groth16 wrap: what that guest committed to.
pub fn finalization_output_input(output: &FinalizationOutput) -> [u8; 32] {
    mask_to_scalar(hashv(&[&output.public_bytes()]).to_bytes())
}

/// The two public inputs the wrap circuit must expose, in circuit order.
pub fn public_inputs(program_vk: &ProgramVk, output: &FinalizationOutput) -> [[u8; 32]; 2] {
    [
        program_vk_input(program_vk),
        finalization_output_input(output),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduces `PublicWriter` field by field, independently of the packed
    /// implementation above.
    #[test]
    fn public_bytes_matches_public_writer() {
        let commitment: [u64; 4] = [1, 2, 0xdead_beef_cafe_babe, u64::MAX];
        let mut acc = [0u8; 32];
        for (i, w) in commitment.iter().enumerate() {
            acc[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        let output = FinalizationOutput {
            accumulator_commitment: acc,
            finalized_epoch: 372_105,
            finalized_root: [7u8; 32],
            finalized_state_root: [9u8; 32],
        };

        let mut expected = Vec::new();
        for w in commitment.iter() {
            expected.extend_from_slice(&w.to_le_bytes());
        }
        expected.extend_from_slice(&372_105u64.to_le_bytes());
        expected.extend_from_slice(&[7u8; 32]);
        expected.extend_from_slice(&[9u8; 32]);

        assert_eq!(expected.len(), FINALIZATION_PUBLIC_BYTES);
        assert_eq!(output.public_bytes().as_slice(), expected.as_slice());
    }

    #[test]
    fn masked_scalar_is_below_the_bn254_order() {
        // r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
        let r = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
            0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93,
            0xf0, 0x00, 0x00, 0x01,
        ];
        assert!(mask_to_scalar([0xff; 32]) < r);
    }
}
