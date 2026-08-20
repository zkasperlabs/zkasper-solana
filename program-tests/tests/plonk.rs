//! The verifier, off chain, against the real wrapped proof.
//!
//! These run the same code the SBF program runs — `plonk::verify` is not
//! duplicated anywhere — so what they establish about acceptance and rejection
//! holds on chain. What they cannot establish is cost; that is `verifier.rs`.

use zkasper_program_tests::fixture;
use zkasper_solana_program::plonk::{self, Proof, PROOF_LEN};

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

/// The public input is the one `cargo-zisk wrap --plonk` reported, so the
/// preimage this program builds — pinned guest key, re-expanded window, pinned
/// `rootCVadcopFinal` — is the preimage Zisk hashed.
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
        "06986ad52e060708cc549df54fb38fa3c9391b8eb913176a44cdad3c32854f05",
    );
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
