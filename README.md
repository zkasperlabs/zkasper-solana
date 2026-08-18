# zkasper-solana

A Solana program that verifies [zkasper](https://github.com/zkasperlabs/zkasper)
proofs of Ethereum beacon-chain finality, and keeps a light-client state account
that other Solana programs can read.

zkasper proves, inside a [Zisk](https://github.com/0xPolygonHermez/zisk) zkVM,
that a Casper FFG checkpoint was finalized by at least two thirds of the **full**
Ethereum validator set — not a sync committee, not a multisig, not an oracle.
This repository is the consumer end of that: a Groth16 verifier over BN254 using
Solana's `alt_bn128` syscalls, plus the accounting needed to turn a stream of
proofs into a queryable finality oracle.

> **Status: the verifier is real, the proofs are not.**
> zkasper's STARK-to-Groth16 wrap has never been run, so no real proof exists in
> this format yet. Every proof in this repository is a placeholder: genuine
> Groth16 over a circuit that proves two numbers add up. See
> [`fixtures/README.md`](fixtures/README.md), and "Going live" below for the
> exact list of what zkasper must produce.

## Measured cost

Groth16 verification costs **86,699 compute units**, and a full state-advancing
submission costs **99,033**. Both fit inside Solana's 200,000-unit default, so a
submitter does **not** need to raise the limit with `ComputeBudgetProgram`.

| Path | Compute units |
| --- | --- |
| `submit_finalization` — verify, advance state, write two records | **99,033** |
| `verify_only` — Groth16 verification alone | **86,699** |
| `assert_finalized` / `assert_anchored` — read path | 5,235 |
| `initialize` — trusted bootstrap | 6,868 |

Whole-transaction figures, each including 150 units for the `ComputeBudget`
instruction itself. Measured under LiteSVM against the compiled SBPF v3 program;
reproduce with `./scripts/test.sh`, and see `measures_compute_units` in
[`program-tests/tests/verifier.rs`](program-tests/tests/verifier.rs).

Published Groth16-on-Solana numbers are usually quoted as 170,000 to 500,000
units. This lands well below that, for two reasons. The circuit exposes only two
public inputs, so input preparation is two scalar multiplications rather than a
dozen. And Solana's own syscall prices put a floor of 81,075 units on the work —
36,364 for the first pair of the pairing, 12,121 for each of the other three,
3,840 per scalar multiplication and 334 per point addition. The verifier spends
only about 5,600 units above that floor, so there is very little left to
optimise: the cost is the syscalls.

## Design

### Why raw `solana-program` and not Anchor

The program is written directly against `solana-program`, with hand-rolled
fixed-offset account layouts.

* **Compute headroom.** Anchor's discriminator checks, Borsh derives and account
  validation would add several thousand units to a transaction whose budget is
  dominated by a pairing. Fixed-offset slicing costs a few hundred.
* **Auditability.** This is a verifier. Every byte that reaches the pairing
  should be traceable to a line of code, not to a derive macro.
* **Toolchain.** `cargo-build-sbf` is enough. No `avm`, no `anchor-cli`, no Node.
* Nothing is given up in ergonomics: `instruction.rs` ships typed builders, and
  every account layout is a documented constant table.

### Accounts

Every account is scoped to the authority that bootstrapped it, so a deployment
can host several independent light clients and nobody can front-run the
deployer's `initialize`.

| Account | Seeds | Size | Holds |
| --- | --- | --- | --- |
| `LightClientState` | `["zkasper-state", authority]` | 826 | accumulator commitment, latest state root, finalized epoch and root, guest program key, and the 640-byte Groth16 verifying key |
| `FinalizationRecord` | `["zkasper-fin", authority, epoch_le]` | 114 | one accepted finalization, never rewritten |
| `AnchorRecord` | `["zkasper-anchor", authority, state_root]` | 42 | a beacon state root some accepted proof named |

### Instructions

| Tag | Instruction | Effect |
| --- | --- | --- |
| 0 | `Initialize` | trusted bootstrap: write the starting checkpoint and bind the verifying key |
| 1 | `SubmitFinalization` | verify a proof, advance the state, write a finalization record and an anchor record. Permissionless |
| 2 | `AssertFinalized` | fail unless `root` was finalized at `epoch`. For CPI |
| 3 | `AssertAnchored` | fail unless some accepted proof named `state_root`. For CPI |
| 4 | `VerifyOnly` | check a proof against the bound key and change nothing. For `simulateTransaction` |

The read path works two ways. A program that wants a hard failure CPIs
`AssertFinalized`; a program that wants a value derives the record PDA and reads
the account directly, with no CPI at all.

## The proof interface

The verifying key lives in account data, so this program is not tied to one
circuit. What it *does* fix is the shape of the public inputs. zkasper's wrap
must expose exactly two, in this order:

```
PI[0] = sha256( program_vk )                              , top 3 bits cleared
PI[1] = sha256( FinalizationOutput::public_bytes() )      , top 3 bits cleared
```

Both are 32-byte big-endian BN254 scalars. Clearing the top three bits puts the
value below 2^253, and the BN254 scalar field order is above 2^253.5, so the
result is always canonical without rejection sampling. This is the same
convention SP1's Groth16 wrap uses.

`program_vk` is the Zisk verification key of the finalization guest — the four
`u64` words of `ProgramVk`, little-endian — bound at bootstrap. It is what stops
a valid proof from a *different* guest being accepted.

`public_bytes()` is zkasper's own encoding, mirrored byte for byte in
[`program/src/wire.rs`](program/src/wire.rs):

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 32 | `accumulator_commitment` — 4 Goldilocks elements, each `u64` little-endian |
| 32 | 8 | `finalized_epoch` — `u64` little-endian |
| 40 | 32 | `finalized_root` |
| 72 | 32 | `finalized_state_root` |

That is 104 bytes, and it is produced by `PublicWriter` in
`crates/common/src/recursion.rs`. If either side changes, proofs stop verifying.

Proofs and keys use the EIP-197 encoding the `alt_bn128` syscalls expect: G1 is
`x || y` as two 32-byte big-endian values, G2 is `x.c1 || x.c0 || y.c1 || y.c0`.
Submit `proof_a` unmodified — the program negates it internally, so a proof
straight out of arkworks, snarkjs or gnark works as-is.

## Trust model

### What a proof buys you

That at least two thirds of the effective balance in the validator set committed
to by `accumulator_commitment` attested to `(finalized_epoch, finalized_root)`
under Casper FFG, and that `finalized_state_root` is the beacon state root
opened from that block's header.

### What is trusted, not proved

`initialize` writes a checkpoint nobody proved. Every light client needs a
subjective starting point; the operator's job is to pick a finalized checkpoint
old enough to be beyond weak subjectivity, and consumers must decide whether they
trust that operator. This is why accounts are scoped by authority: a consumer
names the light client it trusts, rather than reading whichever singleton exists.

### Known gap: `epoch-diff` does not prove succession

**This is unfixed in zkasper today and it matters.**

zkasper's accumulator tracks the validator registry across epochs. The
`epoch-diff` stage proves that a registry delta is consistent between two claimed
beacon state roots — but it does **not** prove that the second state root is the
canonical successor of the first. Nothing in that stage is tied to the chain.

So a prover with no stake can fabricate a chain of `epoch-diff` proofs from the
honest bootstrap state to an accumulator containing validators they invented, and
then produce a perfectly valid finalization proof under it. The accumulator
therefore advances **optimistically**. `submit_finalization` accepts a changed
`accumulator_commitment` and says so in its logs; it cannot do better, because it
never sees the `epoch-diff` chain.

**The mitigation, which this program implements.** `finalized_state_root` is
opened from the header of a block that two thirds of the stake attested to, so it
names a real state root on the real chain — an attacker cannot produce one for a
fabricated state without two thirds of the real validator set. Every accepted
proof writes an `AnchorRecord` for its `finalized_state_root`.

A consumer that follows an accumulator from state root A to state root B must
require **every beacon state root the chain passed through to have an
`AnchorRecord`**. A branched accumulator can never satisfy that, so it can never
be confirmed. Query it with `AssertAnchored`, or by deriving
`["zkasper-anchor", authority, state_root]` and reading the account.

The same reasoning is written at the point where state advances, in
[`program/src/processor.rs`](program/src/processor.rs).

### Other properties

* `finalized_epoch` must strictly increase; a replayed proof is rejected before
  the pairing runs, for a few hundred units rather than ninety thousand.
* `FinalizationRecord` accounts are write-once. There is no path that rewrites
  one, so a consumer that has read a record can cache it forever.
* PDAs are always derived with `find_program_address`. Accepting a client-supplied
  bump would be cheaper by roughly 1,500 units per account, but it would let a
  submitter place a record at a non-canonical address — advancing the state while
  leaving the address consumers actually read empty. That trade is not worth it.
* `submit_finalization` is permissionless. Anyone can pay to advance the light
  client; the proof is the only thing that decides whether it advances.

## Building and testing

```sh
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"   # if needed

./scripts/build.sh      # compile the SBF program (SBPF v3)
./scripts/test.sh       # unit + LiteSVM tests, prints the compute-unit table
./scripts/fixtures.sh   # regenerate fixtures (deterministic)
./scripts/demo.sh       # full local-validator demo
```

`scripts/demo.sh` starts `solana-test-validator`, deploys the verifier,
bootstraps a light client, submits the three fixture proofs, then exercises the
read path — including a negative case where an unanchored state root is correctly
rejected.

agave 4.x has `disable_sbpf_v0_execution` active, so the program is built with
`--arch v3`. A v0 build deploys nowhere useful.

### Layout

```
program/       the on-chain program
  wire.rs      zkasper's output encoding and public-input derivation
  verifier.rs  Groth16 over BN254, via groth16-solana
  state.rs     account layouts
  instruction.rs  encoding and client-side builders
  processor.rs handlers
fixture-gen/   generates the placeholder Groth16 fixtures
program-tests/ LiteSVM integration tests, including the CU measurement
cli/           command-line client used by the demo
fixtures/      placeholder verifying key and proofs
```

## Going live

The program does not need to change. Everything below is something **zkasper**
must produce.

1. **Run the STARK-to-Groth16 wrap.** This is the blocking item. Zisk emits a
   VADCOP final proof; something must wrap it into a BN254 Groth16 proof. Until
   that exists, nothing else on this list can be tested.

2. **Make the wrap circuit expose exactly the two public inputs above.** Two
   inputs, in that order, each a sha256 with the top three bits cleared. Getting
   this wrong is the most likely source of a silent mismatch, so check it against
   `wire.rs` before running a ceremony.

3. **Run a trusted setup and publish the verifying key** in the 640-byte layout
   `state.rs` documents: `alpha_g1(64) || beta_g2(128) || gamma_g2(128) ||
   delta_g2(128) || ic[0..3](64 each)`, EIP-197 encoding. A circuit-specific
   setup with a single participant is a single point of failure; a real
   deployment wants a multi-party ceremony.

4. **Publish the finalization guest's `ProgramVk`** — the four `u64` words. It is
   bound at bootstrap and is what stops proofs from another guest being accepted.

5. **Pick a bootstrap checkpoint** and publish `accumulator_commitment`,
   `latest_state_root`, `finalized_epoch` and `finalized_root` for it, along with
   how they were derived, so consumers can check the starting point themselves.

6. **Close the `epoch-diff` succession gap, or ship the anchor check.** If the
   gap stays open, every consumer needs the anchor-record walk described above,
   and that requirement belongs in zkasper's own documentation, not only here.

7. **Then swap the fixtures.** Replace `fixtures/*.bin` with real bytes and
   re-run `./scripts/test.sh`. If the tests pass, the deployment is ready. No
   program change, no redeploy — the verifying key is account data.

Also: `keys/zkasper_verifier-keypair.json` is a public local-development
keypair. A real deployment generates its own, keeps it private, and updates
`declare_id!` — see [`keys/README.md`](keys/README.md).

Two smaller items worth doing at the same time: pin `groth16-solana` and the
agave dependency versions once (this repository already pins several, because the
4.1/4.2 point releases are not compatible), and decide who holds the bootstrap
authority for the canonical instance.

## License

MIT
