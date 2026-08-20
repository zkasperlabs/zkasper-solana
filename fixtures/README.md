# Fixtures

`wrap-469426.json` is a real `cargo-zisk wrap --plonk` output: a 768-byte BN254
PLONK proof, the 256-byte public window it commits to, the guest key it was
produced under, and the `rootCVadcopFinal` of the Zisk release that made it. The
tests verify it — off chain in `program-tests/tests/plonk.rs`, and through the
compiled SBF program in `program-tests/tests/verifier.rs`.

**It is not a proof of Ethereum finality.** The guest is a stand-in:

```rust
// the whole program
fn main() {
    let input = ziskos::io::read_slice();
    ziskos::io::commit_slice(input);
}
```

It commits its input verbatim, and the input it was given is the 176 bytes
`/v1/proofs/469426` published — the real `StreamFinalOutput` of a real zkasper
run, epoch 469425. So the *bytes* are real and the *claim about them* is not:
this proof says "some Zisk execution of program `0xe4322cd5…` produced these
public values", which is true, and says nothing about Casper FFG.

## Why that is still worth having

Zisk's wrap circuits are fixed size and never look at the guest — every zkasper
proof is 254,624 bytes whatever stage produced it — so a wrap of this guest has
the same shape, the same verifying key and the same cost as a wrap of the real
one. What the tests exercise is therefore exactly what a real proof exercises:
the transcript, the eighteen scalar multiplications, the pairing, the public
input derivation, the staging buffer, the account plumbing, the accumulator
chaining, and the compute-unit and transaction-size numbers the README quotes.

What is *not* exercised is whether zkasper's circuits are sound. That question
lives in the zkasper repository.

It is also the reason the program pins `programVK` in account data rather than
letting a submitter name it. This fixture is precisely the attack that pinning
prevents: a genuine proof of a guest that asserts nothing. A light client
bootstrapped on the real finalization guest rejects it, and
`rejects_a_proof_bound_to_a_different_guest` is that test.

## Provenance

Produced 2026-08-18 on a rented GPU box under Zisk **v1.0.0-alpha** — the newest
release whose SNARK proving key exists. `prove` took 689 s and `wrap --plonk`
436 s, both on CPU: `cargo-zisk` reported itself as the `[gpu]` build but the
card sat at 0% utilisation throughout. The full artifact set, the guest source
and the run log are in `workspace/zkasper-plonk-wrap-artifacts/`.

| field | bytes | |
| --- | --- | --- |
| `programVK` | 32 | the stand-in guest |
| `rootCVadcopFinal` | 32 | v1.0.0-alpha's vadcop_final verkey |
| `publicValues` | 256 | the 176 real bytes, zero-padded into Zisk's 64-slot window |
| `proofBytes` | 768 | `uint256[24]` |

The single public input those hash to is
`0x06986ad52e060708cc549df54fb38fa3c9391b8eb913176a44cdad3c32854f05`, and
`the_public_input_matches_the_wrap` checks the program derives exactly that.

## Replacing it

A real proof drops in as the same four fields — no code change, as long as the
Zisk release matches `program/src/plonk/vk.rs` and the guest matches whatever
`programVK` the light client was bootstrapped with. See "Going live" in the
top-level README for what is still blocking upstream.
