# Fixtures

**Nothing here is a zkasper proof.**

zkasper's STARK-to-Groth16 wrap has never been run. No proof of Ethereum
finality exists in this format yet, so there was nothing real to check the
program against. These files are the substitute.

## What they are

`zkasper-fixture-gen` runs a real Groth16 trusted setup over BN254 and produces
real proofs. The trusted setup, the proving key, the pairing check the program
performs on chain — all genuine. What is fake is the *statement*. The circuit is:

```rust
// fixture-gen/src/main.rs
let a   = cs.new_input_variable(|| Ok(self.pi0))?;   // public
let b   = cs.new_input_variable(|| Ok(self.pi1))?;   // public
let sum = cs.new_witness_variable(|| Ok(self.pi0 + self.pi1))?;
cs.enforce_constraint(lc!() + a + b, lc!() + Variable::One, lc!() + sum)?;
```

It proves that two numbers add up. It says nothing about Ethereum, Casper FFG,
validator sets or accumulators.

## Why that is still worth having

Groth16 verification cost does not depend on what the circuit proves. It depends
only on the number of public inputs, which is fixed at two. So the compute-unit
figures measured against these fixtures are the figures a real proof will cost,
to the unit.

The same goes for correctness of the plumbing: byte layouts, public-input
derivation, the negation of `proof_a`, the verifying-key encoding, PDA
derivation, replay rejection. All of it is exercised for real.

What is *not* exercised is whether zkasper's circuits are sound. That question
lives in the zkasper repository.

## Files

| File | Contents |
| --- | --- |
| `vk.bin` | 640-byte Groth16 verifying key |
| `bootstrap.bin` | the `Initialize` instruction payload, minus its tag byte |
| `finalization_{0,1,2}.bin` | `SubmitFinalization` payloads, minus their tag bytes |
| `fixtures.json` | the same values in hex, for scripts and humans |

The three finalizations cover epochs 300001 to 300003. The first reuses the
bootstrap accumulator commitment; the other two change it, so both branches of
`submit_finalization` are covered.

Regenerate with `./scripts/fixtures.sh`. The RNG is seeded, so the output is
byte-for-byte reproducible.

## Replacing them

The program reads its verifying key from the light-client account, so swapping
in real proofs is a data change, not a code change. See "Going live" in the
top-level README.
