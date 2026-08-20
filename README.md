# zkasper-solana

A Solana program that verifies [zkasper](https://github.com/zkasperlabs/zkasper)
proofs of Ethereum beacon-chain finality, and keeps a light-client state account
that other Solana programs can read.

zkasper proves, inside a [Zisk](https://github.com/0xPolygonHermez/zisk) zkVM,
that a Casper FFG checkpoint was finalized by at least two thirds of the **full**
Ethereum validator set — not a sync committee, not a multisig, not an oracle.
This repository is the consumer end of that: a PLONK verifier over BN254 using
Solana's `alt_bn128` syscalls, plus the accounting needed to turn a stream of
proofs into a queryable finality oracle.

PLONK because that is what Zisk emits. `cargo-zisk wrap --plonk` produces a
768-byte snarkjs PLONK proof with a single public input; there is no Groth16
anywhere in Zisk. The verifier here is a transliteration of the Solidity verifier
Zisk ships as `zisk-contracts/PlonkVerifier.sol`, with every precompile call
replaced by the matching syscall.

> **Status: the verifier is real and the proof it verifies is real.**
> [`fixtures/wrap-469426.json`](fixtures/README.md) is an actual `wrap --plonk`
> output, and the tests run it through the compiled program. What it is a proof
> *of* is a stand-in guest that commits its input verbatim, not zkasper's own
> finalization guest — see `fixtures/README.md`. Binding a deployment to the real
> guest is one 32-byte value at bootstrap and nothing else.

## One transaction

A PLONK proof is 768 bytes. The finalization output it attests to is another 176,
and the envelope around them — a signature, a blockhash, and six account keys:
payer, state, record, anchor, system program, this program and `ComputeBudget` —
is the rest. Sent whole, that is **1,288 bytes against Solana's 1,232-byte packet
limit**, and a submission does not fit.

Nine of the proof's twenty-four words are not scalars but the `x` halves of nine
G1 commitments, and a BN254 point is determined by `x` and one sign bit. So the
proof travels compressed at 32 bytes a commitment instead of 64, and the program
expands it with `alt_bn128_g1_decompress` — a syscall live on mainnet since slot
276,912,000 — before anything reads it:

| | bytes | |
| --- | --- | --- |
| one transaction, proof sent whole | 1,288 | over |
| **one transaction, nine commitments compressed** | **1,000** | **fits, 232 spare** |

Measured, not modelled — `what_a_submission_weighs` in
[`program-tests/tests/verifier.rs`](program-tests/tests/verifier.rs) serializes
both.

The instruction data is 657 bytes: one tag, 480 of compressed proof, 176 of
output. Nothing is staged, so there is no buffer account, no second signature and
no second fee.

Decompression must be exact, not merely correct, because the Fiat-Shamir
transcript hashes the proof's *wire bytes*. `alt_bn128_g1_decompress` returns the
same big-endian `x || y` pair snarkjs writes, so the 768 bytes the verifier hashes
are the artifact's own, byte for byte —
`decompression_reproduces_the_proof_byte_for_byte` in
[`program-tests/tests/plonk.rs`](program-tests/tests/plonk.rs) is that assertion.
It also tightens the parse: a compressed `x` is rejected unless it is canonical
and `x^3 + 3` is a square, so the nine commitments are on the curve by
construction, and BN254's G1 has cofactor one, so on-curve is subgroup
membership.

## Measured cost

A submission costs **484,908 compute units**, which does **not** fit Solana's
200,000-unit default: every submitter must raise the limit with
`ComputeBudgetProgram`. 700,000 is the value the CLI asks for.

| Path | Compute units |
| --- | --- |
| `submit_finalization` — decompress, verify, advance state, write two records | **484,908** |
| `verify_only` — decompression and PLONK verification alone | 472,531 |
| `assert_finalized` / `assert_anchored` — read path | 3,728 |
| `initialize` — trusted bootstrap | 6,874 |

Nine G1 decompressions are 4,878 of that, measured marginally — 542 each, of
which 498 is the syscall (a 100-unit base plus the 398 the table quotes) and the
rest is the caller moving 96 bytes. They are not the whole difference from the
two-transaction design's 481,005: dropping the buffer also drops an account load
and a `find_program_address` walk, so the net cost of going compressed and
single-transaction is 3,903 units.

Whole-transaction figures, each including 150 units for the `ComputeBudget`
instruction itself. Measured under LiteSVM with mainnet's feature set, against
the compiled SBPF v3 program running the real wrapped proof; reproduce with
`./scripts/test.sh`, and see `measures_compute_units` in
[`program-tests/tests/verifier.rs`](program-tests/tests/verifier.rs).

The same submission on a real `solana-test-validator` — `./scripts/demo.sh`,
which generates a fresh payer each run — costs a little more. The gap is bump
seeds: `find_program_address` walks downwards from 255 at 1,500 units an attempt,
and a different authority lands on different bumps for its PDAs. Budget for the
variance rather than for the measurement.

Where it goes, from `cargo test -p zkasper-plonk-cost -- --nocapture`, which
prices each piece in its own transaction:

| | units |
| --- | --- |
| eighteen `alt_bn128` scalar multiplications | 116,334 (6,463 each) |
| one pairing of two pairs | 49,088 |
| eighteen point additions | 7,524 (418 each) |
| one `Fr` inversion, in software | 50,682 |
| the public input, one SHA-256 over 320 bytes | 10,612 |
| the Fiat-Shamir transcript, six keccaks | 1,642 |
| everything else: about a hundred `Fr` multiplications at 1,990 each, and the byte conversions between them | 231,379 |
| **verification, net of the 13,020-unit baseline** | **467,261** |

Note the scalar multiplications cost 6,463 rather than the 3,840 Solana's own
table quotes, and the additions 418 rather than 334. Those are the measured
marginal costs.

The `Fr` arithmetic is the largest line and there is no syscall for it.
`sol_big_mod_exp` would invert by Fermat for a fraction of the price its table
entry implies, but an SBPF v3 program under agave 4.1 cannot reach it — the call
comes back "unsupported BPF instruction" even with mainnet's feature set active.

### What a submission costs in SOL

Compute units are not the bill. A submission spends **2,872,520 lamports**,
almost all of it rent-exempt balance left behind in the two accounts the program
creates per finalization.

| | lamports | at $77/SOL |
| --- | --- | --- |
| one transaction fee | 5,000 | $0.0004 |
| rent for the two records | 2,867,520 | $0.22 |
| **total per finalization** | **2,872,520** | **$0.22** |
| `initialize`, once | 2,190,440 | $0.17 |
| deploying the program | ~600,000,000 | ~$46 |

Measured, from `measures_lamports` in the same test file. The record rent is not
refundable, by design — the records *are* the read path, and a record that can be
closed is a finality claim that can be withdrawn.

Priority fees are on top and were zero for these accounts at the time of
measurement; nothing here contends for a hot account.

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
| `LightClientState` | `["zkasper-state", authority]` | 186 | accumulator commitment, latest state root, finalized epoch and root, and the guest program key |
| `FinalizationRecord` | `["zkasper-fin", authority, epoch_le]` | 114 | one accepted finalization, never rewritten |
| `AnchorRecord` | `["zkasper-anchor", authority, state_root]` | 42 | a beacon state root some accepted proof named |

### Instructions

| Tag | Instruction | Effect |
| --- | --- | --- |
| 0 | `Initialize` | trusted bootstrap: write the starting checkpoint and bind the guest key |
| 1 | `SubmitFinalization` | verify the compressed proof carried in the instruction, advance the state, write a finalization record and an anchor record. Permissionless |
| 2 | `AssertFinalized` | fail unless `root` was finalized at `epoch`. For CPI |
| 3 | `AssertAnchored` | fail unless some accepted proof named `state_root`. For CPI |
| 4 | `VerifyOnly` | check a proof and change nothing. For `simulateTransaction` |

The read path works two ways. A program that wants a hard failure CPIs
`AssertFinalized`; a program that wants a value derives the record PDA and reads
the account directly, with no CPI at all.

### What the verifier deliberately skips

snarkjs's Solidity verifier opens with `checkProofData`: nine tests that each G1
commitment satisfies `y^2 = x^3 + 3`, with both coordinates below the base field
modulus. This program does not run it, and that is worth 104,679 units — a fifth
of the whole submission.

The reason is that every one of the nine commitments is an operand to an
`alt_bn128` syscall before it can reach the pairing, and the syscall already does
the work: `PodG1 -> G1` deserializes each coordinate canonically, rejects
anything that is not a field element, and calls `is_on_curve`. BN254's G1 has
cofactor one, so on-curve *is* subgroup membership. Doing it again in software
buys one thing — `checkProofData` also rejects the encoded point at infinity,
which the syscalls accept, and which is a legitimate group element the KZG
argument is sound over. The pairing rejects it anyway, because the transcript
hashes the commitment bytes.

`a_corrupted_commitment_is_rejected_without_the_membership_check` in
[`program-tests/tests/plonk.rs`](program-tests/tests/plonk.rs) is the evidence:
each of the nine slots, corrupted three ways — off the curve, non-canonical, and
the point at infinity — and rejected every time with the check off. The check
itself is kept as `Proof::well_formed`, unused by the verification path, so its
cost can be quoted and the two paths compared.

What is *not* skipped is the range check on the six opening evaluations. That one
is not redundant: the transcript hashes the wire bytes, so a non-canonical
evaluation would hash differently from the value the algebra uses. It happens in
`Proof::parse` and is nearly free.

## The proof interface

Zisk's wrap commits exactly one public input:

```
PI = sha256( programVK || publicValues || rootCVadcopFinal )  mod r
```

with `publicValues` the fixed 256-byte window Zisk pads the guest's committed
output into. Three things therefore decide what a verifying proof *means*, and
the program holds all three. None of them is read from a submission:

| | what it pins | where it lives | changes when |
| --- | --- | --- | --- |
| `programVK` | which guest ran | `LightClientState`, written once at `Initialize` | zkasper ships a new guest |
| `rootCVadcopFinal` | which VADCOP final verification key the recursion terminated at | [`program/src/plonk/vk.rs`](program/src/plonk/vk.rs) | Zisk ships a new release |
| `Qm..Qc`, `S1..S3`, `X_2`, `w`, `k1`, `k2`, `n` | which wrap circuit | the same module | the same |

The split is deliberate. `programVK` is zkasper's and moves on zkasper's
schedule, so it is deployment configuration and a new guest is a new light
client. The rest is Zisk's, moves together, and a new Zisk release is a program
upgrade. They live in one module rather than three so they cannot drift apart.

**Why the program must pin `programVK`.** A PLONK proof is a proof that *some*
Zisk execution produced these public values. Which execution is exactly what
`programVK` names. If the submitter supplied it, anyone could write a guest whose
entire body is "commit these 176 bytes", prove it in a few minutes, wrap it, and
submit a genuine proof of an Ethereum finality that never happened — the fixture
in this repository is that guest, which is why it verifies here and would be
rejected by a light client bootstrapped on the real one. The same argument
applies to `rootCVadcopFinal`: it names the STARK verifier the recursion ends at,
so a submitter who chose it could point at a verifier they set up themselves.

The 176 bytes the instruction carries are the whole of what a submitter gets to
say, and the program re-expands them into the 256-byte window itself. Padding is
not a free field either: a byte written past the output changes the digest.

`public_bytes()` is zkasper's own encoding, mirrored byte for byte in
[`program/src/wire.rs`](program/src/wire.rs):

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 32 | `accumulator_commitment` — 4 Goldilocks elements, each `u64` little-endian |
| 32 | 32 | `next_accumulator_commitment` — the same, after the epoch diff |
| 64 | 8 | `finalized_epoch` — `u64` little-endian |
| 72 | 32 | `finalized_root` |
| 104 | 32 | `finalized_state_root` |
| 136 | 8 | `justified_epoch` — `u64` little-endian |
| 144 | 32 | `justified_root` |

That is 176 bytes, and it is produced by `PublicWriter` in
`crates/common/src/recursion.rs`. If either side changes, proofs stop verifying.

**This is the streaming pipeline's output**, `StreamFinalOutput` — what `zkasperd`
runs and the only one on the latency path. The batch pipeline's
`FinalizationOutput` is the first 136 bytes of it.

zkasper appended one more field to that struct on 2026-08-19: the guest's own
`program_vk`, taking the committed output to 208 bytes.
`GUEST_COMMITS_PROGRAM_VK` in `wire.rs` is the switch for it, and it is `false`
because the only wrapped proof that exists predates the change. When it is
flipped, the program appends **the key it already pinned**, which is exactly the
comparison zkasper's `types.rs` asks an on-chain verifier to make — a proof whose
guest committed any other key produces a different digest and fails. The
submitter never names it, either way.

Proofs use the EIP-197 encoding the `alt_bn128` syscalls expect: G1 is `x || y`
as two 32-byte big-endian values, G2 is `x.c1 || x.c0 || y.c1 || y.c0`. The 24
words of a `wrap --plonk` proof go on the wire unmodified.

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

The guest key lives in account data rather than the binary. This is deliberate
and it is not a mutation path: `Initialize` is guarded by `data_is_empty`, no
instruction writes `program_vk` afterwards, and the account is a program-owned
PDA. It is write-once. The benefit is that binding a deployment to a new zkasper
guest needs no program upgrade — so the dangerous mechanism never has to be used.

**Unchecked invariant.** Nothing on chain checks that the `program_vk` an
operator bootstraps with is a guest that exists, or that the compiled circuit
constants match the Zisk release that guest's proofs are wrapped under. Both
mismatches fail *closed* — proofs simply stop verifying — which is the safe
direction, but they fail silently at submission time rather than at bootstrap.
Check the pair before bootstrapping.

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

**Unbranched is not the same as consecutive.** An accumulator commitment binds a
validator-set root and a total active balance, and no epoch: two epochs that left
the validator set untouched commit to identical bytes. On its own the check above
would therefore let a client sitting one epoch further back than it thinks accept
a proof that skips an epoch — no branch, just a hole. That no gap has slipped
past is a fact about mainnet, where the validator set churns every epoch and so
keeps the commitment moving, not a property of the format.

So the state also carries `accumulator_epoch`, the epoch its accumulator belongs
to, and a submission must finalize exactly that epoch or be rejected with
`AccumulatorEpochMismatch`. This is load-bearing rather than tidy: zkasper proves
the supermajority target vote and the ancestry of the finalized root, but never
the FFG link, so a consumer holds only Casper's double-vote clause — and that
clause binds only while *every* epoch in the sequence carries a supermajority
vote. One gap and it does not. See `docs/finality/assumptions.md` in the zkasper
repository.

Bootstrap is where the two can disagree, and it is the reason to be careful with
`Initialize`: its `finalized_epoch` is the checkpoint being trusted, while its
`accumulator_commitment` belongs to the epoch *above* that checkpoint, because
the first proof the client accepts finalizes `finalized_epoch + 1` and starts
from that epoch's accumulator.

`AnchorRecord`s are still written per accepted proof, keyed by
`finalized_state_root`. They remain useful to a consumer reasoning about which
beacon states the accumulator passed through, but they are no longer the only
thing standing between a branch and acceptance.

## Building and testing

```sh
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"   # if needed

./scripts/build.sh      # compile the SBF program (SBPF v3)
./scripts/test.sh       # unit + LiteSVM tests, prints the cost tables
./scripts/demo.sh       # full local-validator demo
```

`scripts/demo.sh` starts `solana-test-validator`, deploys the verifier,
bootstraps a light client, submits the real wrapped proof, then
exercises the read path — including a negative case where an unanchored state
root is correctly rejected.

agave 4.x has `disable_sbpf_v0_execution` active, so the program is built with
`--arch v3`. A v0 build deploys nowhere useful.

### Layout

```
program/       the on-chain program
  wire.rs      zkasper's output encoding and the public window
  plonk.rs     PLONK over BN254, through the alt_bn128 syscalls
  plonk/vk.rs  the circuit constants, and the only place a Zisk release is named
  state.rs     account layouts
  instruction.rs  encoding and client-side builders
  processor.rs handlers
program-tests/ LiteSVM integration tests, the cost measurements, and the
               off-chain tests that run the real proof through the same verifier
plonk-cost/    the same verifier under a mode dispatch, so the cost decomposes
cli/           command-line client used by the demo
fixtures/      the one wrapped proof that exists
```

## Going live

The program is done. Everything below is something **zkasper** or **Zisk** must
produce.

1. **Wrap a real zkasper proof.** The fixture is a wrap of a stand-in guest. Four
   things block wrapping the real one, and they are upstream, not here:
   `wrap --plonk` consumes an *uncompressed* VADCOP final proof that
   `zkasperd`'s prover currently throws away; the v1.1.0-alpha SNARK proving key
   Zisk published is a 660 KB macOS `.dylib` rather than the 21.9 GB key;
   v1.0.0-alpha's md5 manifest names the wrong filename, so `ziskup setup_snark`
   fails its own check; and `cargo-zisk verify` on a PLONK proof shells out to
   `snarkjs`, which nothing in the toolchain installs.

2. **Pin the Zisk release the deployment verifies under.** The circuit constants
   and `rootCVadcopFinal` in `plonk/vk.rs` are v1.0.0-alpha's. v1.1.0-alpha has
   different selector commitments, stamps a different value in
   `rootCVadcopFinal`, and renders `publicValues` as 512 bytes rather than 256 —
   three separate reasons a v1.1.0 proof will not verify against a v1.0.0 build.
   Transcribe the new ones from that release's `PlonkVerifier.sol` and re-run the
   tests against a proof from it.

3. **Publish the finalization guest's `programVK`** — the four `u64` words. It is
   bound at bootstrap and is the whole of what stops a proof of another program
   being accepted.

4. **Decide `GUEST_COMMITS_PROGRAM_VK`.** zkasper's `StreamFinalOutput` now
   commits the guest key as a trailing field; the fixture predates it. Whichever
   is true of the proof being wrapped has to be true of this constant.

5. **Pick a bootstrap checkpoint** and publish `accumulator_commitment`,
   `latest_state_root`, `finalized_epoch` and `finalized_root` for it, along with
   how they were derived, so consumers can check the starting point themselves.
   Note that `accumulator_commitment` is the accumulator of `finalized_epoch + 1`
   — see "Accumulator chaining" — so publish which epoch it belongs to as well.

6. **Close the `epoch-diff` succession gap, or ship the anchor check.** If the
   gap stays open, every consumer needs the anchor-record walk described above,
   and that requirement belongs in zkasper's own documentation, not only here.

7. **Record the trusted setup as an assumption.** The Zisk STARK is transparent;
   the PLONK wrap is not. Its structured reference string arrives as a 21.9 GB
   `final.zkey` from a bucket, with an md5 and no ceremony transcript. Anyone
   verifying a wrapped zkasper proof trusts a setup they cannot audit. That is a
   real weakening of the trust model and belongs in zkasper's
   `docs/shared/assumptions.md`.

Also: `keys/zkasper_verifier-keypair.json` is a public local-development
keypair. A real deployment generates its own, keeps it private, and updates
`declare_id!` — see [`keys/README.md`](keys/README.md).

## Reporting a submission

`zkasper-cli submit` prints a *posting record* — the `posting` object of
`docs/api-v1.md` in the zkasper repository — and appends it to the file named by
`ZKASPER_POSTINGS` when that is set:

```sh
ZKASPER_POSTINGS=/var/lib/zkasper/postings.jsonl \
  zkasper-cli https://api.devnet.solana.com payer.json submit fixtures/wrap-469426.json
```

```json
{"chain":"solana-devnet","cluster":"devnet","epoch":469425,"signature":"4Jr…","slot":11,
 "compute_units":481004,"fee_lamports":5000,"rent_lamports":2867520,"lamports_spent":2872520,
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
