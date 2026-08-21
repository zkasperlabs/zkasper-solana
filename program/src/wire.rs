//! The zkasper wire format, mirrored byte-for-byte on chain.
//!
//! Everything in this module is a restatement of code that lives in the zkasper
//! repository. If either side changes, proofs stop verifying, so the two must be
//! kept in step:
//!
//! * `StreamFinalOutput::public_bytes` — `crates/common/src/types.rs`
//! * `PublicWriter`                    — `crates/common/src/recursion.rs`
//! * `Digest = [u64; 4]`               — `crates/common/src/acc.rs`
//!
//! # Which proof this is
//!
//! zkasper has two pipelines and they publish different bytes. The batch
//! pipeline's `FinalizationOutput` is 136 bytes. The streaming pipeline — the
//! one `zkasperd` runs, and the only one on the latency path — publishes
//! `StreamFinalOutput`, which is those same five fields followed by
//! `justified_epoch` and `justified_root`. That is the one mirrored here, and
//! it is the shape of the wrapped proof in `fixtures/`.
//!
//! There is a third thing `/v1/proofs/{epoch}` can serve: for the first epoch of
//! a run it is a *justification* proof, 72 bytes of publics and no finalized
//! checkpoint at all. Whatever wraps must select the stage, not the epoch.

use crate::plonk::vk::PUBLIC_VALUES_LEN;

/// Byte length of `StreamFinalOutput::public_bytes()` as this program builds it.
///
/// `PublicWriter` writes fixed-width little-endian fields with no framing: two
/// 4-element Goldilocks digests, a u64, three 32-byte roots and a second u64.
pub const FINALIZATION_PUBLIC_BYTES: usize = 32 + 32 + 8 + 32 + 32 + 8 + 32;

/// Whether the guest commits its own program key as a trailing field.
///
/// zkasper's `StreamFinalOutput` gained a `program_vk` field on 2026-08-19
/// (`bake child program keys into the guests that verify them`), and
/// `public_bytes()` appends it, taking the committed output from 176 bytes to
/// 208. `types.rs` says of it: *"an on-chain verifier must require this to equal
/// the program key it already pins"*.
///
/// This program does exactly that, and does it by construction: when the flag is
/// set, [`public_values`] appends the key **the light client pinned**, so a
/// proof whose guest committed any other key produces a different digest and
/// fails. The submitter never gets to name it, which is the whole point.
///
/// It is `true` since `fixtures/wrap-469993.json`, whose guest is a production
/// zkasperd from after that commit: slots 44..52 of its public window hold the
/// key its own proof was produced under. A proof from a guest that predates the
/// field no longer verifies here, which is the same statement as the release
/// pin in [`crate::plonk::vk`] and is deliberate — both ends moved at once.
pub const GUEST_COMMITS_PROGRAM_VK: bool = true;

/// A zkasper accumulator digest: 4 Goldilocks elements, each little-endian.
///
/// Held as bytes rather than `[u64; 4]` because that is how it crosses the wire
/// in both directions, and the program never does field arithmetic on it.
pub type AccumulatorCommitment = [u8; 32];

/// The Zisk program verification key of the finalization guest.
///
/// Four u64s **big-endian**: the `programVK` of a Zisk Solidity fixture, and the
/// bytes [`crate::plonk::public_input`] hashes. The guest writes the same four
/// words little-endian into its own output, so the two encodings of one key both
/// appear in the preimage, eight bytes apart — `guest_program_vk` below is the
/// reversal between them.
pub type ProgramVk = [u8; 32];

/// Public outputs of a zkasper streaming finalization proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizationOutput {
    /// Accumulator that the finalized epoch was justified against.
    pub accumulator_commitment: AccumulatorCommitment,
    /// Accumulator that the justified epoch was proven against, linked to the
    /// one above by the epoch diff the proof verified while streaming.
    ///
    /// This is what lets the program chain finalizations without ever seeing an
    /// epoch-diff proof: each finalization names both ends of one proven
    /// transition, so requiring the incoming start to equal the stored
    /// accumulator makes the chain unbroken by construction.
    pub next_accumulator_commitment: AccumulatorCommitment,
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
    /// The checkpoint this proof justified, published so the next epoch's proof
    /// can consume this one as its previous justification.
    pub justified_epoch: u64,
    pub justified_root: [u8; 32],
}

impl FinalizationOutput {
    /// Exactly the bytes `StreamFinalOutput::public_bytes()` produces in
    /// zkasper, in the same order and with the same widths.
    pub fn public_bytes(&self) -> [u8; FINALIZATION_PUBLIC_BYTES] {
        let mut out = [0u8; FINALIZATION_PUBLIC_BYTES];
        out[0..32].copy_from_slice(&self.accumulator_commitment);
        out[32..64].copy_from_slice(&self.next_accumulator_commitment);
        out[64..72].copy_from_slice(&self.finalized_epoch.to_le_bytes());
        out[72..104].copy_from_slice(&self.finalized_root);
        out[104..136].copy_from_slice(&self.finalized_state_root);
        out[136..144].copy_from_slice(&self.justified_epoch.to_le_bytes());
        out[144..176].copy_from_slice(&self.justified_root);
        out
    }

    /// The inverse, for decoding a submission.
    pub fn from_public_bytes(bytes: &[u8; FINALIZATION_PUBLIC_BYTES]) -> Self {
        let a32 = |off: usize| -> [u8; 32] { bytes[off..off + 32].try_into().unwrap() };
        let u64_at = |off: usize| u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        Self {
            accumulator_commitment: a32(0),
            next_accumulator_commitment: a32(32),
            finalized_epoch: u64_at(64),
            finalized_root: a32(72),
            finalized_state_root: a32(104),
            justified_epoch: u64_at(136),
            justified_root: a32(144),
        }
    }
}

/// The pinned key in the encoding the guest wrote it in.
///
/// [`ProgramVk`] is big-endian because that is how the SNARK preimage opens; the
/// trailing field of the committed output is the same key as zkasper's
/// `PublicWriter` laid it down, four little-endian u64s. Reversing eight bytes
/// at a time is the whole of the difference, and doing it here means the program
/// stores one encoding rather than two fields that must agree.
fn guest_program_vk(program_vk: &ProgramVk) -> ProgramVk {
    let mut out = *program_vk;
    for word in out.chunks_exact_mut(8) {
        word.reverse();
    }
    out
}

/// The guest's committed output, re-expanded into Zisk's fixed public window.
///
/// Zisk hashes a window of constant width whatever the guest wrote, so the
/// program can carry the fields alone — 176 bytes on the wire instead of 512 —
/// and rebuild the rest here.
///
/// The window is 64 slots holding four bytes of guest output each, and the
/// preimage renders every slot as a little-endian u64: four bytes on, four
/// bytes off. Those interleaved zeros are not padding the guest could have
/// written into — they are the high half of a u32 read at u64 width — but they
/// are covered by the digest exactly as the trailing zeros are.
pub fn public_values(
    output: &FinalizationOutput,
    program_vk: &ProgramVk,
) -> [u8; PUBLIC_VALUES_LEN] {
    let mut committed = [0u8; FINALIZATION_PUBLIC_BYTES + 32];
    committed[..FINALIZATION_PUBLIC_BYTES].copy_from_slice(&output.public_bytes());
    if GUEST_COMMITS_PROGRAM_VK {
        committed[FINALIZATION_PUBLIC_BYTES..].copy_from_slice(&guest_program_vk(program_vk));
    }
    let mut window = [0u8; PUBLIC_VALUES_LEN];
    for (slot, four) in window.chunks_exact_mut(8).zip(committed.chunks_exact(4)) {
        slot[..4].copy_from_slice(four);
    }
    window
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(w: &[u64; 4]) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, x) in w.iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&x.to_le_bytes());
        }
        b
    }

    fn sample() -> FinalizationOutput {
        FinalizationOutput {
            accumulator_commitment: digest(&[1, 2, 0xdead_beef_cafe_babe, u64::MAX]),
            next_accumulator_commitment: digest(&[9, 8, 0x0123_4567_89ab_cdef, 42]),
            finalized_epoch: 372_105,
            finalized_root: [7u8; 32],
            finalized_state_root: [9u8; 32],
            justified_epoch: 372_106,
            justified_root: [11u8; 32],
        }
    }

    #[test]
    fn public_bytes_round_trips() {
        assert_eq!(
            FinalizationOutput::from_public_bytes(&sample().public_bytes()),
            sample()
        );
    }

    /// Reproduces `PublicWriter` field by field, independently of the packed
    /// implementation above.
    #[test]
    fn public_bytes_matches_public_writer() {
        let output = sample();
        let mut expected = Vec::new();
        for w in [1, 2, 0xdead_beef_cafe_babe, u64::MAX] {
            expected.extend_from_slice(&w.to_le_bytes());
        }
        for w in [9u64, 8, 0x0123_4567_89ab_cdef, 42] {
            expected.extend_from_slice(&w.to_le_bytes());
        }
        expected.extend_from_slice(&372_105u64.to_le_bytes());
        expected.extend_from_slice(&[7u8; 32]);
        expected.extend_from_slice(&[9u8; 32]);
        expected.extend_from_slice(&372_106u64.to_le_bytes());
        expected.extend_from_slice(&[11u8; 32]);

        assert_eq!(expected.len(), FINALIZATION_PUBLIC_BYTES);
        assert_eq!(output.public_bytes().as_slice(), expected.as_slice());
    }

    /// Every slot carries four bytes of guest output and four zeros, and the
    /// four-byte halves in order are the output, then the pinned key if the
    /// guest commits one, then nothing.
    #[test]
    fn the_public_window_spreads_the_output() {
        let program_vk: ProgramVk = std::array::from_fn(|i| i as u8);
        let window = public_values(&sample(), &program_vk);

        let mut halves = Vec::new();
        for slot in window.chunks_exact(8) {
            halves.extend_from_slice(&slot[..4]);
            assert!(
                slot[4..].iter().all(|b| *b == 0),
                "slot high half is not zero"
            );
        }

        assert_eq!(
            halves[..FINALIZATION_PUBLIC_BYTES],
            sample().public_bytes()[..]
        );
        let tail = &halves[FINALIZATION_PUBLIC_BYTES..];
        if GUEST_COMMITS_PROGRAM_VK {
            assert_eq!(tail[..32], guest_program_vk(&program_vk));
            assert!(tail[32..].iter().all(|b| *b == 0));
        } else {
            assert!(tail.iter().all(|b| *b == 0));
        }
    }

    /// The two encodings of the key are byte reversals of one another, eight
    /// bytes at a time, and neither is a reversal of the whole.
    #[test]
    fn the_guest_writes_the_pinned_key_the_other_way_round() {
        let program_vk: ProgramVk = std::array::from_fn(|i| i as u8);
        let guest = guest_program_vk(&program_vk);
        assert_eq!(guest[..8], [7, 6, 5, 4, 3, 2, 1, 0]);
        assert_eq!(guest[24..], [31, 30, 29, 28, 27, 26, 25, 24]);
        assert_eq!(guest_program_vk(&guest), program_vk);
    }
}
