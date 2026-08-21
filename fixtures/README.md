# Fixtures

`wrap-469993.json` is a real `cargo-zisk wrap --plonk` output: a 768-byte BN254
PLONK proof, the 512-byte public window it commits to, the guest key it was
produced under, and the `rootCVadcopFinal` of the Zisk release that made it. The
tests verify it — off chain in `program-tests/tests/plonk.rs`, and through the
compiled SBF program in `program-tests/tests/verifier.rs`.

**It is a proof of Ethereum finality, and of the FFG link.** The guest is
zkasper's own streaming finalization guest, the one `zkasperd` runs on the
latency path, and the input is the proof it published for mainnet epoch 469993:

| | |
| --- | --- |
| `finalized_epoch` | 469992 |
| `finalized_root` | `0x39b6f3806980980dd240e48a93917287a705f29b43a3bb95b671234c45276277` |
| `finalized_state_root` | `0x4676dc1d2a6223ce401ec6c53fd3984dd70a7bd56a5e86f2e2481356c9898079` |
| `justified_epoch` | 469993 |
| `justified_root` | `0x5229c63280ef5ec0c0ff42d3fcb1208e6a7d97522e1fa541964325569dd36a63` |

469992 is the first epoch zkasper proved under circuits that **constrain the FFG
source checkpoint** (`constrain the ffg source checkpoint`, 2026-08-21). Before
that the circuits proved a supermajority attesting to a target without binding
the source the vote started from, so what they established was not yet a Casper
FFG link. This fixture is on the far side of that change, and the guest key
below is the key those circuits produce — a different guest from the one every
earlier fixture carried, which is why a light client bootstrapped against an
older key rejects this proof.

What is *not* exercised here is whether zkasper's circuits prove that soundly.
That question lives in the zkasper repository.

## Provenance

The input is `stream_final_proof.bin` of `epoch-000469993` from a production
`zkasperd` run — 369,232 bytes, `minimal = 0`, 69 STARK publics. The wrap was
produced on 2026-08-21 on a rented card, on CPU in 333 s, against the
v1.1.0-alpha SNARK proving key (`provingKeySnark`, the 2026-08-19 build) whose
`vadcop_final.verkey.json` is the 2026-08-17 value production proves under.

It took two upstream corrections, both recorded in
`/mnt/ssd/zkasper-wrap-469993/` beside the artifacts and explained at length in
`/mnt/ssd/zkasper-wrap-469891/PROVENANCE.md`:

* `backend.plonk()` passes the guest program VK as proofman's `verkey_override`,
  where a plain vadcop_final leaf needs the vadcop_final verkey. Stock
  `cargo-zisk 1.1.0-alpha` cannot wrap a plain leaf at all; every attempt dies in
  `VerifyPoW`. The wrap was made with that one line patched out.
* The same call stamps `rootc` from the publics — the guest program VK — rather
  than from the verkey it actually stamped into the RecursiveF proof. The field
  was corrected in place, length-preserving, before snarkjs would accept the
  proof.

| field | bytes | |
| --- | --- | --- |
| `programVK` | 32 | zkasper's streaming finalization guest, four `u64`s big-endian |
| `rootCVadcopFinal` | 32 | the 2026-08-17 `vadcop_final` verkey, the same way |
| `publicValues` | 512 | 64 slots, four bytes of guest output each, rendered at `u64` width |
| `proofBytes` | 768 | `uint256[24]` |

The single public input those hash to is
`0x278f1ea229b7852480503e0052425c036a2819e319400816612e076027bb7615`, and
`the_public_input_matches_the_wrap` checks the program derives exactly that.

## The fixtures that used to be here

`wrap-469891.json` was the same kind of artifact as this one and verified under
the same pin: a v1.1.0-alpha wrap of a production mainnet proof, for epoch
469891. It is gone because its guest predates the FFG source constraint, so the
claim it carries is the weaker one, and a repository that shipped both would be
offering a reader two proofs that look alike and are not. It is in git history,
with the provenance it had, and its artifacts remain at
`/mnt/ssd/zkasper-wrap-469891/`.

`wrap-469426.json` was a v1.0.0-alpha wrap of a stand-in guest whose whole body
was `commit_slice(read_slice())`. It is gone rather than kept as a regression
case, because nothing in the tree can consume it any more: its window is 256
bytes where `PUBLIC_VALUES_LEN` is now 512, and the circuit it verifies under is
eight commitments that this program no longer holds. Keeping an artifact that no
code path can reach would only invite the reading that it still verifies. It is
in git history at `6eac515`, with the provenance it had.

## Replacing it

`scripts/wrap_to_fixture.py` turns a `cargo-zisk wrap --plonk` output into those
four fields; it reproduces this file byte for byte from
`/mnt/ssd/zkasper-wrap-469993/out-F-rootc-fixed.bin`. The single public input
changes with the proof, so `the_public_input_matches_the_wrap` has to be given
the new one.

A real proof drops in as the same four fields — no code change, as long as the
Zisk release matches `program/src/plonk/vk.rs` and the guest matches whatever
`programVK` the light client was bootstrapped with. `program-tests/src/lib.rs`
checks the window it carries against the one the program rebuilds, so a fixture
from a different release fails at the loader rather than at the pairing.
