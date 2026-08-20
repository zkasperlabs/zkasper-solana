//! The real wrapped proof, verified off-chain, so the compute-unit measurement
//! is known to be measuring a verification that succeeds.
//!
//! `wrap-469426.json` is the output of `cargo-zisk wrap --plonk` on Zisk
//! v1.0.0-alpha over the 176 bytes `/v1/proofs/469426` published — the only
//! wrapped zkasper proof that exists.

use zkasper_plonk_cost::{public_input, verify, Proof, PROGRAM_VK, ROOT_C};

struct Fixture {
    proof: Vec<u8>,
    publics: Vec<u8>,
}

fn fixture() -> Fixture {
    let raw = include_str!("wrap-469426.json");
    let field = |name: &str| -> Vec<u8> {
        let at = raw.find(name).expect("field") + name.len();
        let rest = &raw[at..];
        let start = rest.find("0x").expect("hex") + 2;
        let end = rest[start..].find('"').expect("close") + start;
        hex::decode(&rest[start..end]).expect("hex")
    };
    assert_eq!(field("programVK"), PROGRAM_VK);
    assert_eq!(field("rootCVadcopFinal"), ROOT_C);
    let public_values = field("publicValues");
    assert_eq!(public_values.len(), 256);
    assert!(public_values[176..].iter().all(|b| *b == 0));
    Fixture {
        proof: field("proofBytes"),
        publics: public_values[..176].to_vec(),
    }
}

#[test]
fn the_public_input_is_the_one_the_wrap_reported() {
    let f = fixture();
    assert_eq!(
        hex::encode(public_input(&f.publics).to_string()),
        hex::encode(public_input(&f.publics).to_string()),
    );
    let pi = public_input(&f.publics);
    let bytes = {
        use ark_ff::{BigInteger, PrimeField};
        hex::encode(pi.into_bigint().to_bytes_be())
    };
    assert_eq!(
        bytes,
        "06986ad52e060708cc549df54fb38fa3c9391b8eb913176a44cdad3c32854f05",
    );
}

#[test]
fn the_proof_is_well_formed() {
    let f = fixture();
    let proof = Proof::parse(&f.proof).expect("24 words");
    assert!(proof.well_formed());
}

#[test]
fn the_wrapped_proof_verifies() {
    let f = fixture();
    assert!(
        verify(&f.proof, &f.publics),
        "the real wrap does not verify"
    );
}

#[test]
fn a_flipped_bit_does_not_verify() {
    let f = fixture();
    let mut publics = f.publics.clone();
    publics[0] ^= 1;
    assert!(!verify(&f.proof, &publics));
}
