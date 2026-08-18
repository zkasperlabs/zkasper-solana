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

### What a submission costs in SOL

Compute units are not the bill. Measured on a validator, one `submit_finalization`
spends **2,872,520 lamports**, of which the transaction fee is **5,000** and the
other **2,867,520** is rent-exempt balance left behind in the two accounts the
program creates per finalization — 1,684,320 for the finalization record and
1,183,200 for the anchor record.

| | lamports | at $77/SOL |
| --- | --- | --- |
| transaction fee | 5,000 | $0.0004 |
| rent for the two records | 2,867,520 | $0.22 |
| **total per finalization** | **2,872,520** | **$0.22** |
| `initialize`, once | 6,644,840 | $0.51 |
| deploying the program | 597,397,240 | $46.11 |

The rent is not refundable: no instruction closes an account, by design — the
records *are* the read path, and a record that can be closed is a finality claim
that can be withdrawn. Any quote of a per-proof cost that names only the fee is
off by a factor of 574.

Priority fees are on top and were zero for these accounts at the time of
measurement; nothing here contends for a hot account.

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
| 32 | 32 | `next_accumulator_commitment` — the same, after the epoch diff |
| 64 | 8 | `finalized_epoch` — `u64` little-endian |
| 72 | 32 | `finalized_root` |
| 104 | 32 | `finalized_state_root` |

That is 136 bytes, and it is produced by `PublicWriter` in
`crates/common/src/recursion.rs`. If either side changes, proofs stop verifying.

**This is the batch pipeline's output.** zkasper's streaming pipeline — what
`zkasperd` runs by default — publishes `StreamFinalOutput` instead: the same
136 bytes followed by `justified_epoch` (8) and `justified_root` (32), so 176
bytes and a different `PI[1]`. A streaming proof will not verify against this
program as it stands. Deciding which of the two the wrap runs over is item 1 of
"Going live", and it has to be decided before a ceremony, not after.

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


## Production defaults

`scripts/deploy-mainnet.sh` deploys with the **upgrade authority burned**. That
is the default because a live upgrade authority can replace the verifier
outright, which is strictly more power than swapping the verifying key. Keeping
it requires `KEEP_UPGRADE_AUTHORITY=1`, an explicit authority, and a typed
confirmation.

The verifying key lives in account data rather than the binary. This is
deliberate and it is not a mutation path: `Initialize` is guarded by
`data_is_empty`, no instruction writes `vk` or `program_vk` afterwards, and the
account is a program-owned PDA. It is write-once. The benefit is that swapping
fixture proofs for real ones needs no program upgrade — so the dangerous
mechanism never has to be used.

**Unchecked invariant.** `program_vk` (the Zisk guest identity) and the Groth16
`vk` are supplied independently at `Initialize`, and nothing on chain verifies
they came from the same wrap. A mismatched pair fails open: it verifies proofs
of a statement nobody intended. Publish them as a pair and check them before
bootstrapping.

### Accumulator chaining

Each finalization proof names **both ends** of one proven epoch transition:
`accumulator_commitment` (what epoch E was justified against) and
`next_accumulator_commitment` (what E+1 was justified against, proven inside the
circuit to be the first advanced by exactly the epoch diff E to E+1).

`submit_finalization` therefore requires the incoming start to equal the
accumulator the client holds, and stores the end. The chain is unbroken by
construction and the program never needs to see an epoch-diff proof. A prover
who branched the accumulator cannot rejoin: the branch's commitment will not
match what is stored, and the submission is rejected with
`AccumulatorMismatch`.

This replaced an earlier design that adopted any new commitment optimistically
and left detection to the consumer.

`AnchorRecord`s are still written per accepted proof, keyed by
`finalized_state_root`. They remain useful to a consumer reasoning about which
beacon states the accumulator passed through, but they are no longer the only
thing standing between a branch and acceptance.

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
   VADCOP final proof of 262,144 bytes; something must wrap it into a BN254
   Groth16 proof of 256. Until that exists, nothing else on this list can be
   tested. The STARK itself never goes on chain — a whole submission is 393
   bytes of instruction data (256 of proof, 136 of public output, one tag) in a
   736-byte transaction.

   Decide at the same time **which proof gets wrapped**, the batch pipeline's
   `FinalizationOutput` or the streaming pipeline's `StreamFinalOutput`. They
   commit to different bytes; see "The proof interface".

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

## Reporting a submission

`zkasper-cli submit` prints a *posting record* — the `posting` object of
`docs/api-v1.md` in the zkasper repository — and appends it to the file named by
`ZKASPER_POSTINGS` when that is set:

```sh
ZKASPER_POSTINGS=/var/lib/zkasper/postings.jsonl \
  zkasper-cli https://api.devnet.solana.com payer.json submit fixtures 0
```

```json
{"chain":"solana-devnet","cluster":"devnet","epoch":300001,"signature":"4Jr…","slot":11,
 "compute_units":99150,"fee_lamports":5000,"rent_lamports":2867520,"lamports_spent":2872520,
 "status":"confirmed","explorer":"https://explorer.solana.com/tx/4Jr…?cluster=devnet","…":""}
```

`zkasperd --postings <path>` reads that file, publishes each new line as a
`posting.landed` event and carries the recent ones in `status.json`, which is
what lets the website show the transaction rather than assert it. The chain name
comes from the cluster's genesis hash, so a posting cannot claim a chain it did
not land on. The two processes share nothing but the file: the daemon never
holds a key, and the submitter never holds the ingest token.

## License

MIT
