#!/usr/bin/env bash
set -euo pipefail

# Production deploy. Safe by default: the upgrade authority is burned unless you
# explicitly keep it.
#
# Why the default is burn: a live upgrade authority can replace the verifier
# outright. That is strictly more power than swapping the verifying key, and it
# makes every other guarantee in this program conditional on one key staying
# uncompromised. The verifying key itself is write-once (Initialize is guarded by
# `data_is_empty`, and no instruction mutates it), so keeping an upgrade
# authority buys you nothing that the VK-in-account-data design does not already
# give you.
#
# Why you may still want to keep it: that argument assumes the verifier is
# correct. This program has not been audited. Burning the authority on an
# unaudited verifier makes every bug in it permanent — there is no patch, only a
# redeploy at a new address that every consumer has to be told about. For a first
# deployment, keep the authority under a multisig, and burn it after an audit.
#
#   KEEP_UPGRADE_AUTHORITY=1   keep it (must also set UPGRADE_AUTHORITY)
#   CLUSTER=devnet             target cluster (default mainnet-beta)

CLUSTER="${CLUSTER:-mainnet-beta}"
KEEP="${KEEP_UPGRADE_AUTHORITY:-0}"
SO=target/deploy/zkasper_solana_program.so

[ -f "$SO" ] || { echo "build first: ./scripts/build.sh"; exit 1; }

echo "cluster: $CLUSTER"
if [ "$KEEP" = "1" ]; then
  : "${UPGRADE_AUTHORITY:?set UPGRADE_AUTHORITY when KEEP_UPGRADE_AUTHORITY=1}"
  echo "WARNING: keeping upgrade authority $UPGRADE_AUTHORITY"
  echo "WARNING: that key can replace the verifier and forge any finalization."
  echo "WARNING: use a multisig, never a single hot key."
  read -r -p "type 'i accept' to continue: " ack
  [ "$ack" = "i accept" ] || { echo "aborted"; exit 1; }
  solana program deploy --url "$CLUSTER" --upgrade-authority "$UPGRADE_AUTHORITY" "$SO"
else
  echo "upgrade authority will be BURNED (immutable program)"
  solana program deploy --url "$CLUSTER" --final "$SO"
fi

cat <<'NOTE'

Before Initialize, confirm all of the following:

1. The `program_vk` you are about to bind is the finalization guest zkasper is
   actually running, and the circuit constants in `program/src/plonk/vk.rs` are
   the Zisk release its proofs are wrapped under. Nothing on chain checks either.
   Both mismatches fail closed -- proofs stop verifying -- but they fail at
   submission time, not now.
2. You accept the PLONK wrap's trusted setup. Zisk ships `provingKeySnark` as a
   prebuilt 21.9 GB `final.zkey` with an md5 and no ceremony transcript. Whoever
   generated it can forge any finalization, whatever this program does. The STARK
   underneath is transparent; this step is not.
3. The bootstrap checkpoint is a weak-subjectivity checkpoint you independently
   verified, not one taken from an RPC you do not control.
4. `Initialize` is first-come per authority. Run it in the same session as the
   deploy so nobody else claims your PDA.
NOTE
