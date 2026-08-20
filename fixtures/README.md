# Fixtures

`wrap-469891.json` is a real `cargo-zisk wrap --plonk` output: a 768-byte BN254
PLONK proof, the 512-byte public window it commits to, the guest key it was
produced under, and the `rootCVadcopFinal` of the Zisk release that made it. The
tests verify it — off chain in `program-tests/tests/plonk.rs`, and through the
compiled SBF program in `program-tests/tests/verifier.rs`.

**It is a proof of Ethereum finality.** The guest is zkasper's own streaming
finalization guest, the one `zkasperd` runs on the latency path, and the input is
the proof it published for mainnet epoch 469891:

| | |
| --- | --- |
| `finalized_epoch` | 469890 |
| `finalized_root` | `0xd965c51241e51953002a436c19ed39bb37976e31c81a2dcf71b336dc8a846039` |
| `finalized_state_root` | `0x3791b4c98355df256ed996dc8030861518b98e2d25550fc7c73d376a4175abb8` |
| `justified_epoch` | 469891 |
| `justified_root` | `0x3eb6205db5239157d4821aabb740ace59778188315d766e79f908f93382a4fdb` |

So the claim the program checks is the real one: that a Casper FFG checkpoint was
finalized by a supermajority of the full validator set. What is *not* exercised
here is whether zkasper's circuits prove that soundly. That question lives in the
zkasper repository.

## Provenance

The input is `stream_final_proof.bin` of `epoch-000469891` from a production
`zkasperd` run — 369,232 bytes, `minimal = 0`, 69 STARK publics. The wrap was
produced on 2026-08-20 on a rented card, on CPU, against the v1.1.0-alpha SNARK
proving key (`provingKeySnark`, the 2026-08-19 build) whose
`vadcop_final.verkey.json` is the 2026-08-17 value production proves under.

It took two upstream corrections, both recorded in
`/mnt/ssd/zkasper-wrap-469891/PROVENANCE.md` beside the artifacts:

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
`0x1ff2741cc9d9d642ef0507c1939c7c1da13dca625d7d00ceda84343b9dcc7476`, and
`the_public_input_matches_the_wrap` checks the program derives exactly that.

## The fixture that used to be here

`wrap-469426.json` was a v1.0.0-alpha wrap of a stand-in guest whose whole body
was `commit_slice(read_slice())`. It is gone rather than kept as a regression
case, because nothing in the tree can consume it any more: its window is 256
bytes where `PUBLIC_VALUES_LEN` is now 512, and the circuit it verifies under is
eight commitments that this program no longer holds. Keeping an artifact that no
code path can reach would only invite the reading that it still verifies. It is
in git history at `6eac515`, with the provenance it had.

## Replacing it

A real proof drops in as the same four fields — no code change, as long as the
Zisk release matches `program/src/plonk/vk.rs` and the guest matches whatever
`programVK` the light client was bootstrapped with. `program-tests/src/lib.rs`
checks the window it carries against the one the program rebuilds, so a fixture
from a different release fails at the loader rather than at the pairing.
