//! The one wrapped zkasper proof that exists, parsed.
//!
//! `fixtures/wrap-469426.json` is the output of `cargo-zisk wrap --plonk` on
//! Zisk v1.0.0-alpha. See `fixtures/README.md` for what it is a proof *of*.

use zkasper_solana_program::plonk::vk::{PUBLIC_VALUES_LEN, ROOT_C_VADCOP_FINAL};
use zkasper_solana_program::wire::{FinalizationOutput, FINALIZATION_PUBLIC_BYTES};

pub struct Fixture {
    /// The guest the wrap attests ran. A light client that pins any other key
    /// rejects this proof.
    pub program_vk: [u8; 32],
    /// Zisk's fixed public window, as the wrap hashed it.
    pub public_values: [u8; PUBLIC_VALUES_LEN],
    pub proof: Vec<u8>,
    /// The window's leading bytes, read as the output they encode.
    pub output: FinalizationOutput,
}

pub fn fixture() -> Fixture {
    let raw = include_str!("../../fixtures/wrap-469426.json");
    let field = |name: &str| -> Vec<u8> {
        let at = raw.find(name).expect("field") + name.len();
        let rest = &raw[at..];
        let start = rest.find("0x").expect("hex") + 2;
        let end = rest[start..].find('"').expect("close") + start;
        hex::decode(&rest[start..end]).expect("hex")
    };

    assert_eq!(
        field("rootCVadcopFinal"),
        ROOT_C_VADCOP_FINAL,
        "the fixture was wrapped under a different Zisk release than plonk::vk pins",
    );
    let public_values: [u8; PUBLIC_VALUES_LEN] = field("publicValues")
        .try_into()
        .expect("the public window is not the width plonk::vk pins");
    // The guest of this wrap committed 176 bytes and nothing else, which is what
    // `wire::GUEST_COMMITS_PROGRAM_VK = false` says it should have.
    assert!(public_values[FINALIZATION_PUBLIC_BYTES..]
        .iter()
        .all(|b| *b == 0));

    Fixture {
        program_vk: field("programVK").try_into().expect("32 bytes"),
        public_values,
        proof: field("proofBytes"),
        output: FinalizationOutput::from_public_bytes(
            public_values[..FINALIZATION_PUBLIC_BYTES]
                .try_into()
                .unwrap(),
        ),
    }
}

/// The proof, as [`zkasper_solana_program::instruction::stage_proof`] wants it.
pub fn proof_array(f: &Fixture) -> [u8; zkasper_solana_program::plonk::PROOF_LEN] {
    f.proof.as_slice().try_into().expect("768 bytes")
}
