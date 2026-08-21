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

> **Status: a mainnet Ethereum epoch, verified by this program on a public
> cluster.** [`fixtures/wrap-469993.json`](fixtures/README.md) is a
> `wrap --plonk` of a proof `zkasperd` produced in production for mainnet epoch
> 469993 — finalizing 469992 — and devnet transaction
> [`2XYkwk1C…`](https://explorer.solana.com/tx/2XYkwk1CJ1sBZTsxwiQFjcDs1tzE7zMuxBUn4jp7ypprDGczNLbeZqf19Yhu8iLSvRjbckfAFKzUDG3GoaazNkw3?cluster=devnet)
> is the deployed program verifying it, in 476,789 compute units for a 5,000
> lamport fee. The guest is zkasper's own streaming finalization guest, and
> 469992 is the first epoch proved under circuits that constrain the FFG source
> checkpoint — so what a cluster has now checked is a Casper FFG link, not a
> stand-in and not a target vote with no source.

## One transaction

A PLONK proof is 768 bytes. The finalization output it attests to is another 176,
and the envelope around them — a signature, a blockhash, and five account keys:
the fee payer, the state, the ring, this program and `ComputeBudget` — is the
rest.

Nine of the proof's twenty-four words are not scalars but the `x` halves of nine
G1 commitments, and a BN254 point is determined by `x` and one sign bit. So the
proof travels compressed at 32 bytes a commitment instead of 64, and the program
expands it with `alt_bn128_g1_decompress` — a syscall live on mainnet since slot
276,912,000 — before anything reads it:

| | bytes | |
| --- | --- | --- |
| one transaction, proof sent whole | 1,221 | fits, 11 spare |
| **one transaction, nine commitments compressed** | **933** | **fits, 299 spare** |

Measured, not modelled — `what_a_submission_weighs` in
[`program-tests/tests/verifier.rs`](program-tests/tests/verifier.rs) serializes
both.

**This used to be 288 bytes or nothing.** With a finalization record and an
anchor record named in the instruction, an uncompressed submission was 1,288
bytes and did not fit the 1,232-byte packet; compression was the only thing
making a submission one transaction. The ring removed both accounts and 67 bytes
of keys and account indices with them, so an uncompressed proof now fits — by
eleven bytes. It stays compressed anyway, and not out of habit: eleven bytes is
not a margin. The test asserts that margin rather than the old inequality.

The instruction data is 657 bytes: one tag, 480 of compressed proof, 176 of
output. Nothing is staged, so there is no buffer account, no second signature and
no second fee.

It is the same 657 bytes it was before the v1.1.0-alpha repin, which is worth
stating because two things about the proof grew and neither reached the wire. The
public window went from 256 bytes to 512, and the guest's committed output from
176 to 208 — but the window is rebuilt on chain, and the 32 bytes the output grew
by are the key the program *already pins*. A submitter still sends 176 bytes and
still never names the key.

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

A submission costs **476,789 compute units**, which does **not** fit Solana's
200,000-unit default: every submitter must raise the limit with
`ComputeBudgetProgram`. 700,000 is the value the CLI asks for.

| Path | Compute units |
| --- | --- |
| `submit_finalization` — decompress, verify, advance state, write one ring entry | **476,789** |
| `verify_only` — decompression and PLONK verification alone | 472,724 |
| `assert_finalized` — index the ring by epoch, on a full ring | 2,412 |
| `assert_anchored` — a pass over all 128 entries, no match | 3,181 |
| `assert_anchored` — the same, matching in the last slot reached | 3,337 |
| `initialize` — trusted bootstrap, and the ring's one allocation | 15,288 |

These are the numbers for the fixture in the tree, and verification is not quite
a constant: the `Fr` inversion in `lagrange_1` is software extended-Euclid, whose
iteration count depends on its input, and that input descends from the
Fiat-Shamir challenge `xi` — a hash of the proof. Swapping one real wrap for
another moved `verify_only` by 498 units. It is noise against a 700,000-unit
budget, and it is why a submitter should size that budget rather than pin it.

Verifying under v1.1.0-alpha costs **692 units more** than under v1.0.0-alpha,
and all of it is the public window: the SHA-256 preimage went from 320 bytes to
576, which is four more compression blocks, and the window is now scattered four
bytes to a slot instead of copied. The nine decompressions, eighteen scalar
multiplications and the pairing are untouched.

The by-epoch lookup does not read the ring's other 127 entries, so it costs the
same whether the ring is empty or full, and it is *cheaper* than the per-epoch
account it replaced: one `create_program_address` against the bump the ring
stores, instead of a `find_program_address` walk for an address derived from the
epoch.

The by-state-root lookup is a linear pass, because the ring has no reverse index
— that index used to be an account per state root. The pass costs 769 units more
than indexing by epoch, and still less than the 3,728 the old lookup measured,
which had to walk `find_program_address` over a seed containing the state root
before it could load anything. A comparison stops at the first 8-byte word that
differs, and 128 beacon state roots agreeing past one would be a SHA-256
collision, so 3,181 is the cost and not a lucky case. Unpacking every slot to
compare it, rather than comparing in place, measured 23,662 — which is why the
scan reads the 32 bytes it needs and materialises an entry only once it has
found one.

Nine G1 decompressions are 4,878 of that, measured marginally — 542 each, of
which 498 is the syscall (a 100-unit base plus the 398 the table quotes) and the
rest is the caller moving 96 bytes. They are not the whole difference from the
two-transaction design's 481,005: dropping the buffer also drops an account load
and a `find_program_address` walk, so the net cost of going compressed and
single-transaction is 3,903 units.

The ring took another **8,321** off. A submission no longer runs two
`find_program_address` walks, two `create_account` invocations of the system
program or a `Clock` read, and names two fewer accounts; it writes 73 bytes into
an account that already exists.

Whole-transaction figures, each including 150 units for the `ComputeBudget`
instruction itself. Measured under LiteSVM with mainnet's feature set, against
the compiled SBPF v3 program running the real wrapped proof; reproduce with
`./scripts/test.sh`, and see `measures_compute_units` in
[`program-tests/tests/verifier.rs`](program-tests/tests/verifier.rs).

The same submission on a real `solana-test-validator` — `./scripts/demo.sh`,
which generates a fresh payer each run — matched the measurement to the unit
under the previous pin, 476,587 against 476,587. That run has not been repeated
here and the figure above is LiteSVM's, but nothing in the repin touches why the
two agree: a submission used to cost a little more than the measurement, and the
gap was bump seeds. `find_program_address` walks downwards from 255 at 1,500
units an attempt, and a different authority lands on different bumps for its
PDAs. A submission no longer runs that walk for anything — the state and the ring
each name the bump they were derived under — so the number is the same for every
authority. `initialize` still walks, and still varies.

Where it goes, from `cargo test -p zkasper-plonk-cost -- --nocapture`, which
prices each piece in its own transaction:

| | units |
| --- | --- |
| eighteen `alt_bn128` scalar multiplications | 116,334 (6,463 each) |
| one pairing of two pairs | 49,087 |
| eighteen point additions | 7,524 (418 each) |
| one `Fr` inversion, in software | 50,796 |
| the public input, one SHA-256 over 576 bytes | 10,771 |
| the Fiat-Shamir transcript, six keccaks | 1,642 |
| everything else: about a hundred `Fr` multiplications at 1,988 each, and the byte conversions between them | 231,234 |
| **verification, net of the 13,685-unit baseline** | **467,388** |

The inversion and the pairing move by a few dozen units between proofs and this
is not noise: extended Euclid is data-dependent, so a different proof inverts a
different field element in a different number of steps. The baseline moved for a
reason of its own — it now includes rebuilding the wider window.

Note the scalar multiplications cost 6,463 rather than the 3,840 Solana's own
table quotes, and the additions 418 rather than 334. Those are the measured
marginal costs.

The `Fr` arithmetic is the largest line and there is no syscall for it.
`sol_big_mod_exp` would invert by Fermat for a fraction of the price its table
entry implies, but an SBPF v3 program under agave 4.1 cannot reach it — the call
comes back "unsupported BPF instruction" even with mainnet's feature set active.

### What a submission costs in SOL

Compute units are not the bill. Rent was, and a submission now leaves none
behind: the finalization goes into a ring account that `initialize` paid for
once, written over the epoch 128 places back.

| | lamports | at $77/SOL |
| --- | --- | --- |
| one transaction fee | 5,000 | $0.0004 |
| rent left behind | 0 | $0 |
| **total per finalization** | **5,000** | **$0.0004** |
| `initialize`, once — state and ring | 68,129,480 | $5.25 |
| of which the ring, 9,346 bytes | 65,939,040 | $5.08 |
| deploying the program | ~600,000,000 | ~$46 |

Measured, from `measures_lamports` in the same test file, which now asserts that
a submission costs the fee and nothing more.

**What this replaced.** Each finalization used to create two accounts that were
deliberately never closed: a 114-byte record keyed by epoch and a 42-byte anchor
keyed by state root. Rent is charged on `128 + data_len` bytes, so the pair
billed 412 bytes — 2,867,520 lamports, or $0.22 — and an epoch is 6.4 minutes, so
that is 225 pairs a day. About 235 SOL a year, roughly $18,100, of which some
three quarters was addressing and account overhead rather than finality data. The
ring pays for itself after **23 epochs, about two and a half hours**, and the
recurring cost after that is the transaction fee: about $2.60 a month.

Priority fees are on top and were zero for these accounts at the time of
measurement; nothing here contends for a hot account.

### What the ring gives up, and how to check before relying on it

The old records were non-closeable, and the reason given was that a record which
can be closed is a finality claim that can be withdrawn. That argument is right
about *closeable* accounts and it does not carry over here, because nothing in
this design chooses which claim disappears. What it buys instead has to be said
plainly:

**A finalization older than 128 epochs — 13.6 hours — is no longer on chain.**
No read path can answer for it. `AssertFinalized` fails with `EpochNotInRing`
and `AssertAnchored` with `StateRootNotAnchored`, and a consumer that reads the
ring account directly finds the slot holding a different epoch.

Three things make that a schedule rather than a withdrawal. Entries age out in
epoch order, at a rate fixed by `RING_ENTRIES`, a constant in a program whose
bytes anyone can read. Nobody chooses which one goes — not the authority, not the
submitter, not this program; the only way to lose an entry is for 128 further
epochs to be finalized, which takes 13.6 hours. And the window is checkable
before you depend on it: `LightClientState` names the head epoch, so `head - 127`
is the oldest epoch the ring can be holding, and a consumer can compare the epoch
it cares about against that before it commits to anything.

`EpochNotInRing` exists so that this is not silently rounded off.
`CheckpointNotFinalized` says Ethereum did not finalize that root; `EpochNotInRing`
says this chain no longer stores the answer. A bridge should treat the first as a
rejection and the second as "the message arrived too late", and it cannot do that
if the two collapse into one error.

Whether 13.6 hours is enough is a property of the consumer, not of this program.
A bridge whose messages reference an epoch and settle within hours is well inside
it; anything that may be asked about a checkpoint from last week needs to carry
its own proof of it, or ask for a larger ring — the cost is linear and one-off.
The ceiling is 10,240 bytes, the most a program can allocate in one instruction,
which at this layout is 140 entries and just under 15 hours. Past that the ring
would have to be grown across two instructions, and that is a different design
rather than a bigger constant.

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
| `LightClientState` | `["zkasper-state", authority]` | 186 | accumulator commitment and its epoch, latest state root, finalized epoch and root, and the guest program key |
| `FinalizationRing` | `["zkasper-ring", authority]` | 9,346 | the last 128 accepted finalizations, written in place |

Both are created by `initialize` and neither is created again. The ring is a
two-byte header — a tag and the bump it was derived under — followed by 128
entries of 73 bytes at `2 + (epoch % 128) * 73`:

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 1 | tag; zero until an epoch reaches this slot |
| 1 | 8 | `finalized_epoch` — `u64` little-endian |
| 9 | 32 | `finalized_root` |
| 41 | 32 | `finalized_state_root` |

The tag byte is what separates "never written" from a genuine epoch 0 with an
all-zero root, since an untouched slot reads as exactly that.

An entry carries what the two read paths need and nothing else. The record it
replaced also held the accumulator commitment and the Solana slot it landed in,
another 40 bytes; 128 of those would not fit under the 10,240-byte ceiling on
what a program can allocate in one instruction, and neither field is read by
`AssertFinalized` or `AssertAnchored`. Losing them costs a consumer less than it
looks: the program enforces the accumulator chain at submission time, so no
consumer has to re-check it, `LightClientState` carries the head's accumulator
and its epoch, and the `(epoch, state_root)` pair an entry does keep is what the
anchor walk below actually queries.

The head stays in `LightClientState` rather than moving into the ring. It is
read on every submission and it is where configuration lives, so the two have
different lifetimes and different readers.

### Instructions

| Tag | Instruction | Effect |
| --- | --- | --- |
| 0 | `Initialize` | trusted bootstrap: write the starting checkpoint, allocate the ring, bind the guest key |
| 1 | `SubmitFinalization` | verify the compressed proof carried in the instruction, advance the state, write the epoch's ring entry. Permissionless |
| 2 | `AssertFinalized` | fail unless `root` was finalized at `epoch` and `epoch` is still in the ring. For CPI |
| 3 | `AssertAnchored` | fail unless a finalization still in the ring named `state_root`. For CPI |
| 4 | `VerifyOnly` | check a proof and change nothing. For `simulateTransaction` |

`SubmitFinalization` names two accounts, both writable and neither of them new:
the state and the ring. It creates nothing, so it takes no rent payer and no
system program.

The read path works two ways. A program that wants a hard failure CPIs
`AssertFinalized`; a program that wants a value derives the ring PDA and reads
the account directly, with no CPI at all. Reading it directly means doing what
the program does — go to slot `epoch % 128`, then **check that the entry's own
`finalized_epoch` is the epoch you asked about**. Skipping that check reads a
wrapped-around slot as an answer. The program cannot skip it: the slot is never
handed out, only `FinalizationRing::entry`, which compares before it returns.

### What the verifier deliberately skips

snarkjs's Solidity verifier opens with `checkProofData`: nine tests that each G1
commitment satisfies `y^2 = x^3 + 3`, with both coordinates below the base field
modulus. This program does not run it, and that is worth 104,667 units — a fifth
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

with `publicValues` the fixed window Zisk spreads the guest's committed output
into — 64 slots, four bytes of output each, rendered at `u64` width, so 512
bytes. Three things therefore decide what a verifying proof *means*, and the
program holds all three. None of them is read from a submission:

| | what it pins | where it lives | changes when |
| --- | --- | --- | --- |
| `programVK` | which guest ran | `LightClientState`, written once at `Initialize` | zkasper ships a new guest |
| `rootCVadcopFinal` | which VADCOP final verification key the recursion terminated at | [`program/src/plonk/vk.rs`](program/src/plonk/vk.rs) | Zisk ships a new release |
| `Qm..Qc`, `S1..S3` | which wrap circuit | the same module | the same |

`X_2`, `w`, `k1`, `k2` and `n` are in that module too and are *not* release
constants: they were byte-identical across v1.0.0-alpha and v1.1.0-alpha, which
is the same SRS, the same root of unity and the same domain. Eight points and
`rootCVadcopFinal` are the whole of a release change, plus the window width.

The three fields are encoded two different ways in the one preimage, which is a
trap worth naming: `programVK` and `rootCVadcopFinal` are four `u64`s
**big-endian**, and the publics between them are little-endian. The same guest
key therefore appears twice in the digest in two encodings — once as the
`programVK` prefix, and once inside the window where the guest wrote it — and
`wire::guest_program_vk` is the eight-byte reversal between them.

The split is deliberate. `programVK` is zkasper's and moves on zkasper's
schedule, so it is deployment configuration and a new guest is a new light
client. The rest is Zisk's, moves together, and a new Zisk release is a program
upgrade. They live in one module rather than three so they cannot drift apart.

**Why the program must pin `programVK`.** A PLONK proof is a proof that *some*
Zisk execution produced these public values. Which execution is exactly what
`programVK` names. If the submitter supplied it, anyone could write a guest whose
entire body is "commit these 176 bytes", prove it in a few minutes, wrap it, and
submit a genuine proof of an Ethereum finality that never happened. The fixture
this repository used to carry was exactly that guest; the one it carries now is
zkasper's, and the difference between them is the 32 bytes a light client pins.
The same argument applies to `rootCVadcopFinal`: it names the STARK verifier the
recursion ends at, so a submitter who chose it could point at a verifier they set
up themselves.

The 176 bytes the instruction carries are the whole of what a submitter gets to
say, and the program re-expands them into the 512-byte window itself. Padding is
not a free field either, and neither is the half of every slot the guest cannot
reach: a byte written into either changes the digest.

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
`GUEST_COMMITS_PROGRAM_VK` in `wire.rs` is the switch for it, and it is `true` —
the fixture is a production proof from after that change, and slots 44..52 of its
window hold the key. The program appends **the key it already pinned**, which is
exactly the comparison zkasper's `types.rs` asks an on-chain verifier to make: a
proof whose guest committed any other key produces a different digest and fails.
The submitter never names it, and the instruction never carries it.

Proofs use the EIP-197 encoding the `alt_bn128` syscalls expect: G1 is `x || y`
as two 32-byte big-endian values, G2 is `x.c1 || x.c0 || y.c1 || y.c0`. The 24
words of a `wrap --plonk` proof go on the wire unmodified.

## Trust model

### What a proof buys you

That at least two thirds of the effective balance in the validator set committed
to by `accumulator_commitment` attested to `(finalized_epoch, finalized_root)`
under Casper FFG, and that `finalized_state_root` is the beacon state root
opened from that block's header.

How much less that is than *"Ethereum finalized this checkpoint"* depends on the
guest the client pins, and the difference is the FFG source. A guest that leaves
the source unconstrained proves a supermajority target vote in each of two
consecutive epochs plus the ancestry between them, and leaves a consumer Casper's
double-vote clause alone. A guest that constrains it — every counted attestation
for the epoch above naming this checkpoint as its source — proves the
specification's one-epoch rule, which is the supermajority *link*, and the
surround clause comes with it. `docs/finality/assumptions.md` in the zkasper
repository holds the exact claim either way.

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
`AccumulatorEpochMismatch`. It is checked *before* the commitment, because a
skipped epoch moves the accumulator too and would otherwise be reported as a
branch. On a chain whose validator set does not move — a devnet, or any epoch
that happened to change nothing — it is the only thing ordering finalizations at
all, since the commitment check is then satisfied by every epoch at once.

**A gap strands this client, and that is a liveness limit rather than a safety
one.** Against a guest that leaves the FFG source unconstrained, consecutiveness
is the safety property: a consumer holds only Casper's double-vote clause, which
binds while *every* epoch in the sequence carries a supermajority vote. Against a
guest that constrains it, those circuits prove the one-epoch rule exactly, an
epoch the chain finalized by the two-epoch rule is one no proof of this shape
exists for, and `finalized_epoch` may legitimately jump. The program refuses the
jump anyway, and cannot do otherwise: the accumulator on the far side of a gap
differs from the one held here by an epoch diff that no proof this program can
verify has ever covered — a finalization verifies the diff between its own two
epochs and no others — so crossing would mean adopting, on the submitter's word,
the validator set the next supermajority is measured against. A client that meets
a gap stops there and has to be bootstrapped again above it. See
`docs/finality/assumptions.md` in the zkasper repository.

**Closing that is a change to the guest, not to this program.** Two things would
have to reach the chain, and `StreamFinalOutput` publishes neither: the
accumulator the proof's walk *started* from together with the epoch that
accumulator belongs to, with the intervening epoch diffs verified inside the
circuit, so that the check above stays an equality against the far end of a
longer walk; and the source checkpoint of the justification the proof consumed,
so a client can splice the link across the gap onto the checkpoint it already
holds instead of holding two links with nothing between them. A committed output
of 208 bytes leaves 48 of the 256 a Zisk proof can publish, which is room for the
first pair or for one digest binding both. Accepting a bare epoch-diff proof on
chain instead would need a second pinned key in an account that has no update
path, and would move the accumulator with no checkpoint attached to it.

Bootstrap is where the two can disagree, and it is the reason to be careful with
`Initialize`: its `finalized_epoch` is the checkpoint being trusted, while its
`accumulator_commitment` belongs to the epoch *above* that checkpoint, because
the first proof the client accepts finalizes `finalized_epoch + 1` and starts
from that epoch's accumulator.

Every accepted proof's `finalized_state_root` still goes on chain, now as a
field of its ring entry rather than an account of its own, and `AssertAnchored`
still answers for it. It remains useful to a consumer reasoning about which
beacon states the accumulator passed through, but it is no longer the only thing
standing between a branch and acceptance — and it is answerable only for the
last 128 epochs.

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
  state.rs     account layouts, and the finalization ring
  instruction.rs  encoding and client-side builders
  processor.rs handlers
program-tests/ LiteSVM integration tests, the cost measurements, and the
               off-chain tests that run the real proof through the same verifier
plonk-cost/    the same verifier under a mode dispatch, so the cost decomposes
cli/           command-line client used by the demo
fixtures/      the wrapped production proof the tests run
```

## Going live

The program is done, and so are the first four items that used to be here: a
production zkasper proof has been wrapped, the verifier is pinned to
v1.1.0-alpha, the guest key is the one that proof carries, and
`GUEST_COMMITS_PROGRAM_VK` is `true`. What is left is deployment and upstream.

1. **Make wrapping reproducible.** The fixture was produced by a `cargo-zisk`
   built from `9a5a1ac` with a one-line patch: `backend.plonk()` passes the guest
   program VK as proofman's `verkey_override`, where a plain vadcop_final leaf
   needs the vadcop_final verkey, and every stock attempt dies in `VerifyPoW`.
   The same call also stamps `rootc` from the publics rather than from the verkey
   it stamped, so the raw output had to be corrected in place before snarkjs
   would take it. Both belong upstream. Until they are there, a wrap is not
   something an operator can reproduce from a release.

2. **Settle which `vadcop_final` verkey is canonical.** `plonk/vk.rs` pins the
   2026-08-17 value, because that is the proving key zkasper's provers hold and
   the only one a production proof wraps under. Upstream reissued the file on
   2026-08-19 and `ZiskVerifier.sol` returns the new value. A deployment is
   pinned to whichever key its provers actually have, and that ought to be
   stated by upstream rather than discovered.

3. **Publish the finalization guest's `programVK`** — the four `u64` words. It is
   bound at bootstrap and is the whole of what stops a proof of another program
   being accepted. The fixture's is
   `0xe4f20c6ec9d0ad4d2d764e8403b73737844c3ba8df033ac13fb2d6bde471197d`,
   big-endian, which is the encoding `Initialize` takes.

4. **Pick a bootstrap checkpoint** and publish `accumulator_commitment`,
   `latest_state_root`, `finalized_epoch` and `finalized_root` for it, along with
   how they were derived, so consumers can check the starting point themselves.
   Note that `accumulator_commitment` is the accumulator of `finalized_epoch + 1`
   — see "Accumulator chaining" — so publish which epoch it belongs to as well.

5. **Close the `epoch-diff` succession gap, or ship the anchor check.** If the
   gap stays open, every consumer needs the anchor walk described above, and that
   requirement belongs in zkasper's own documentation, not only here. Say there
   that the walk can only be completed on chain for state roots from the last 128
   epochs; a consumer walking further back has to have collected the answers
   while they were still there.

6. **Record the trusted setup as an assumption.** The Zisk STARK is transparent;
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
  zkasper-cli https://api.devnet.solana.com payer.json submit fixtures/wrap-469993.json
```

The record below is the one this repository's own devnet submission produced,
abbreviated only in the hex fields:

```json
{"chain":"solana-devnet","cluster":"devnet","epoch":469992,"signature":"2XYkwk1C…","slot":486134401,
 "compute_units":476789,"fee_lamports":5000,"rent_lamports":0,"lamports_spent":5000,
 "status":"confirmed","explorer":"https://explorer.solana.com/tx/2XYkwk1C…?cluster=devnet","…":""}
```

`rent_lamports` is zero for every submission after the bootstrap, and the field
is kept so that it says so.

`zkasperd --postings <path>` reads that file, publishes each new line as a
`posting.landed` event and carries the recent ones in `status.json`, which is
what lets the website show the transaction rather than assert it. The chain name
comes from the cluster's genesis hash, so a posting cannot claim a chain it did
not land on. The two processes share nothing but the file: the daemon never
holds a key, and the submitter never holds the ingest token.

## License

MIT
