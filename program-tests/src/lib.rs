//! The wrapped zkasper proof of a mainnet epoch, parsed.
//!
//! `fixtures/wrap-469891.json` is the output of `cargo-zisk wrap --plonk` on
//! Zisk v1.1.0-alpha. See `fixtures/README.md` for what it is a proof *of*.

use zkasper_solana_program::plonk::vk::{PUBLIC_VALUES_LEN, ROOT_C_VADCOP_FINAL};
use zkasper_solana_program::plonk::{compress_proof, COMPRESSED_PROOF_LEN};
use zkasper_solana_program::wire::{public_values, FinalizationOutput, FINALIZATION_PUBLIC_BYTES};

pub struct Fixture {
    /// The guest the wrap attests ran. A light client that pins any other key
    /// rejects this proof.
    pub program_vk: [u8; 32],
    /// Zisk's fixed public window, as the wrap hashed it.
    pub public_values: [u8; PUBLIC_VALUES_LEN],
    pub proof: Vec<u8>,
    /// The same proof as a submission carries it: nine halved commitments.
    pub compressed: [u8; COMPRESSED_PROOF_LEN],
    /// The window's leading bytes, read as the output they encode.
    pub output: FinalizationOutput,
}

pub fn fixture() -> Fixture {
    let raw = include_str!("../../fixtures/wrap-469891.json");
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
    let window: [u8; PUBLIC_VALUES_LEN] = field("publicValues")
        .try_into()
        .expect("the public window is not the width plonk::vk pins");
    let program_vk: [u8; 32] = field("programVK").try_into().expect("32 bytes");

    // Read the guest's output back out of the window: four bytes to a slot, and
    // the first 176 of them are the fields a submission carries.
    let mut committed = [0u8; FINALIZATION_PUBLIC_BYTES];
    for (four, slot) in committed.chunks_exact_mut(4).zip(window.chunks_exact(8)) {
        four.copy_from_slice(&slot[..4]);
    }
    let output = FinalizationOutput::from_public_bytes(&committed);

    // And the rest of the window is not taken on trust: it has to be what the
    // program rebuilds from those fields and the key it pins. This is the whole
    // of what a submission has to reproduce, checked once, here.
    assert_eq!(
        public_values(&output, &program_vk),
        window,
        "the program does not rebuild the window the wrap hashed",
    );

    let proof = field("proofBytes");
    Fixture {
        program_vk,
        public_values: window,
        compressed: compress_proof(&proof).expect("768 bytes of proof"),
        proof,
        output,
    }
}
