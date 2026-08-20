//! The verifier, off chain, against the real wrapped proof.
//!
//! These run the same code the SBF program runs — `plonk::verify` is not
//! duplicated anywhere — so what they establish about acceptance and rejection
//! holds on chain. What they cannot establish is cost; that is `verifier.rs`.

use zkasper_program_tests::fixture;
use zkasper_solana_program::plonk::{self, Proof, COMPRESSED_PROOF_LEN, PROOF_LEN};

/// Word offsets of the nine G1 commitments in the 24-word proof.
const COMMITMENTS: [(usize, &str); 9] = [
    (0, "A"),
    (2, "B"),
    (4, "C"),
    (6, "Z"),
    (8, "T1"),
    (10, "T2"),
    (12, "T3"),
    (14, "Wxi"),
    (16, "Wxiw"),
];

#[test]
fn the_real_wrapped_proof_verifies() {
    let f = fixture();
    assert!(
        plonk::verify(&f.proof, &f.program_vk, &f.public_values).is_ok(),
        "the real wrap does not verify",
    );
}

/// The public input is the one the wrap committed, so the preimage this program
/// builds — pinned guest key, re-expanded window, pinned `rootCVadcopFinal` — is
/// the preimage Zisk hashed.
#[test]
fn the_public_input_matches_the_wrap() {
    use ark_ff::{BigInteger, PrimeField};
    let f = fixture();
    assert_eq!(
        hex::encode(
            plonk::public_input(&f.program_vk, &f.public_values)
                .into_bigint()
                .to_bytes_be()
        ),
        "1ff2741cc9d9d642ef0507c1939c7c1da13dca625d7d00ceda84343b9dcc7476",
    );
}

/// Compression is a re-encoding and not a re-derivation, which is the whole
/// soundness question: the transcript hashes the wire bytes, so the 768 bytes
/// the verifier sees have to be the artifact's own, byte for byte.
#[test]
fn decompression_reproduces_the_proof_byte_for_byte() {
    let f = fixture();
    let compressed = plonk::compress_proof(&f.proof).expect("compress");
    assert_eq!(compressed.len(), COMPRESSED_PROOF_LEN);
    assert_eq!(
        plonk::decompress_proof(&compressed).expect("decompress")[..],
        f.proof[..],
    );
}

/// And so a compressed submission verifies through exactly the code an
/// uncompressed one ran.
#[test]
fn the_compressed_proof_verifies() {
    let f = fixture();
    let proof = plonk::decompress_proof(&plonk::compress_proof(&f.proof).unwrap()).unwrap();
    assert!(plonk::verify(&proof, &f.program_vk, &f.public_values).is_ok());
}

/// The compressed encoding is canonical everywhere but at infinity, and that
/// exception costs nothing.
///
/// The top two bits of the leading byte are flags — `0x80` picks the other
/// square root, `0x40` says the point is infinity — and the x below them is
/// always canonical, since the modulus is under `2^254`. Setting `0x40` over a
/// real x is accepted and decompresses to the 64 zero bytes, discarding the x:
/// infinity is *folded* onto one encoding rather than rejected, so a submission
/// carrying it has many spellings and every one of them fails the pairing. The
/// tree said "rejected" until a proof whose first commitment had `0x80` clear
/// showed the difference; with `0x80` set the pair `0xc0` is not a spelling of
/// anything, which is what was really being observed.
#[test]
fn the_compressed_encoding_is_canonical_except_at_infinity() {
    let f = fixture();
    let compressed = plonk::compress_proof(&f.proof).unwrap();

    let mut infinity = compressed;
    infinity[..32].fill(0);
    assert!(plonk::decompress_proof(&infinity).unwrap()[..64]
        .iter()
        .all(|b| *b == 0));

    for (word, name) in COMMITMENTS {
        let at = word / 2 * 32;
        // Drop both flags to reach the x alone, whatever this proof spelled it as.
        let mut plain = compressed;
        plain[at] &= 0x3f;

        let mut point_at_infinity = plain;
        point_at_infinity[at] |= 0x40;
        let out = plonk::decompress_proof(&point_at_infinity)
            .unwrap_or_else(|_| panic!("{name}: the infinity spelling was rejected"));
        assert!(
            out[word * 32..word * 32 + 64].iter().all(|b| *b == 0),
            "{name}: the infinity flag did not discard the x below it",
        );

        let mut both = plain;
        both[at] |= 0xc0;
        assert!(
            plonk::decompress_proof(&both).is_err(),
            "{name}: both flags at once was accepted",
        );

        // And the sign bit names the other root, not the same point twice.
        let mut negated = plain;
        negated[at] |= 0x80;
        let positive = plonk::decompress_proof(&plain)
            .unwrap_or_else(|_| panic!("{name}: the positive root was rejected"));
        let negated = plonk::decompress_proof(&negated)
            .unwrap_or_else(|_| panic!("{name}: the negated root was rejected"));
        assert_eq!(
            positive[word * 32..word * 32 + 32],
            negated[word * 32..word * 32 + 32]
        );
        assert_ne!(
            positive[word * 32 + 32..word * 32 + 64],
            negated[word * 32 + 32..word * 32 + 64],
            "{name}: the sign bit changed nothing",
        );
    }
}

/// A proof of a different guest is a proof of a different program, and this is
/// the check that says so. Nothing about the proof changes here — only the key
/// the verifier pins.
#[test]
fn a_proof_of_another_guest_is_rejected() {
    let f = fixture();
    let mut other = f.program_vk;
    other[0] ^= 1;
    assert!(plonk::verify(&f.proof, &other, &f.public_values).is_err());
}

#[test]
fn a_flipped_output_bit_is_rejected() {
    let f = fixture();
    let mut publics = f.public_values;
    publics[0] ^= 1;
    assert!(plonk::verify(&f.proof, &f.program_vk, &publics).is_err());
}

/// Padding is not a free field: a byte written past the guest's output changes
/// the digest, so the window cannot be stuffed.
#[test]
fn a_byte_in_the_padding_is_rejected() {
    let f = fixture();
    let mut publics = f.public_values;
    *publics.last_mut().unwrap() = 1;
    assert!(plonk::verify(&f.proof, &f.program_vk, &publics).is_err());
}

/// Nor is the half of each slot the guest cannot reach. Every public is four
/// bytes read at eight, so half the window is interleaved zeros — and they are
/// hashed like everything else rather than skipped.
#[test]
fn a_byte_in_a_slot_the_guest_did_not_write_is_rejected() {
    let f = fixture();
    for slot in [0, 43, 51] {
        let mut publics = f.public_values;
        publics[slot * 8 + 4] = 1;
        assert!(
            plonk::verify(&f.proof, &f.program_vk, &publics).is_err(),
            "the high half of slot {slot} was accepted",
        );
    }
}

// ---------------------------------------------------------------------------
// Why `checkProofData` is not in the verification path
// ---------------------------------------------------------------------------

fn corrupt(proof: &[u8], word: usize, kind: usize) -> Vec<u8> {
    let mut p = proof.to_vec();
    match kind {
        // Still canonical field elements, but not a point on `y^2 = x^3 + 3`.
        0 => p[word * 32] ^= 0x01,
        // x is not below the base field modulus, so not a field element at all.
        1 => p[word * 32..word * 32 + 32].copy_from_slice(&[0xff; 32]),
        // The encoded point at infinity. The syscalls *accept* this one — it is
        // a legitimate group element — so nothing rejects it before the pairing.
        _ => p[word * 32..word * 32 + 64].fill(0),
    }
    p
}

/// Every corrupted commitment is rejected without `checkProofData` ever running.
///
/// This is the evidence for dropping it. Each of the nine commitments is an
/// operand to an `alt_bn128` syscall before it can reach the pairing, and the
/// syscall parses coordinates canonically and rejects points off the curve, so
/// the software curve test costs 104,679 units to reach the same verdict.
#[test]
fn a_corrupted_commitment_is_rejected_without_the_membership_check() {
    let f = fixture();
    for (word, name) in COMMITMENTS {
        for kind in 0..3 {
            let bad = corrupt(&f.proof, word, kind);
            assert!(
                plonk::verify_with(&bad, &f.program_vk, &f.public_values, false).is_err(),
                "{name} corruption {kind} was accepted with the membership check off",
            );
            assert!(
                plonk::verify_with(&bad, &f.program_vk, &f.public_values, true).is_err(),
                "{name} corruption {kind} was accepted with the membership check on",
            );
        }
    }
}

/// The two paths disagree about exactly one thing, and it is not a soundness
/// difference: `checkProofData` rejects the point at infinity, which the
/// syscalls accept and which the pairing then rejects anyway.
#[test]
fn the_membership_check_differs_only_on_infinity() {
    let f = fixture();
    let parse = |b: &[u8]| -> bool { Proof::parse(b).map(|p| p.well_formed()).unwrap_or(false) };
    assert!(parse(&f.proof), "the real proof is not well formed");
    for (word, name) in COMMITMENTS {
        assert!(!parse(&corrupt(&f.proof, word, 0)), "{name} off curve");
        assert!(!parse(&corrupt(&f.proof, word, 1)), "{name} non-canonical");
        assert!(!parse(&corrupt(&f.proof, word, 2)), "{name} infinity");
    }
}

/// The evaluations are range-checked in `Proof::parse`, and that check is *not*
/// redundant: the transcript hashes the wire bytes, so a non-canonical
/// evaluation would hash differently from the value the algebra uses.
#[test]
fn a_non_canonical_evaluation_is_rejected_at_parse() {
    let f = fixture();
    for word in 18..24 {
        let mut p = f.proof.clone();
        p[word * 32..word * 32 + 32].copy_from_slice(&[0xff; 32]);
        assert!(Proof::parse(&p).is_none(), "word {word} parsed");
    }
}

#[test]
fn a_proof_of_the_wrong_length_is_rejected() {
    let f = fixture();
    assert_eq!(f.proof.len(), PROOF_LEN);
    assert!(Proof::parse(&f.proof[..PROOF_LEN - 1]).is_none());
}
