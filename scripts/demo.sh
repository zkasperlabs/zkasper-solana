#!/usr/bin/env bash
# End-to-end demo against a local validator.
#
# Starts solana-test-validator, deploys the verifier, bootstraps a light client,
# submits the three fixture finalization proofs, and queries the read path.
#
#   ./scripts/demo.sh
#
# Set KEEP_VALIDATOR=1 to leave the validator running afterwards.
set -euo pipefail
cd "$(dirname "$0")/.."

export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

RPC_URL="${RPC_URL:-http://127.0.0.1:8899}"
LEDGER="${LEDGER:-.demo-ledger}"
KEYPAIR="$LEDGER/payer.json"
VALIDATOR_PID=""

cleanup() {
  if [ -n "$VALIDATOR_PID" ] && [ -z "${KEEP_VALIDATOR:-}" ]; then
    kill "$VALIDATOR_PID" 2>/dev/null || true
    wait "$VALIDATOR_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

step() { printf '\n=== %s\n' "$1"; }

step "build"
./scripts/build.sh

step "start validator"
rm -rf "$LEDGER"
mkdir -p "$LEDGER"
solana-test-validator --ledger "$LEDGER/ledger" --reset --quiet >"$LEDGER/validator.log" 2>&1 &
VALIDATOR_PID=$!

for _ in $(seq 1 60); do
  if solana --url "$RPC_URL" cluster-version >/dev/null 2>&1; then break; fi
  sleep 1
done
solana --url "$RPC_URL" cluster-version

step "fund payer"
solana-keygen new --no-bip39-passphrase --silent --force --outfile "$KEYPAIR"
solana --url "$RPC_URL" airdrop 100 --keypair "$KEYPAIR" >/dev/null
solana --url "$RPC_URL" balance --keypair "$KEYPAIR"

step "deploy verifier"
solana --url "$RPC_URL" program deploy \
  --keypair "$KEYPAIR" \
  --program-id target/deploy/zkasper_solana_program-keypair.json \
  target/deploy/zkasper_solana_program.so

cli() { cargo run --quiet --release -p zkasper-cli -- "$RPC_URL" "$KEYPAIR" "$@"; }

step "addresses"
cli address

WRAP=fixtures/wrap-469993.json

step "bootstrap (trusted, unproved)"
cli init "$WRAP"
cli show

step "submit the wrapped proof"
cli submit "$WRAP"
cli show

step "read path"
read -r EPOCH ROOT STATE_ROOT <<<"$(python3 -c "
import json
w = bytes.fromhex(json.load(open('$WRAP'))['publicValues'][2:])
# Four bytes to a slot: the window renders each public at u64 width.
p = b''.join(w[i * 8:i * 8 + 4] for i in range(len(w) // 8))
print(int.from_bytes(p[64:72], 'little'), '0x' + p[72:104].hex(), '0x' + p[104:136].hex())
")"

echo "assert_finalized epoch=$EPOCH root=$ROOT"
cli assert-finalized "$EPOCH" "$ROOT"

echo "assert_anchored state_root=$STATE_ROOT"
cli assert-anchored "$STATE_ROOT"

echo "assert_anchored on a state root nobody proved (must fail)"
if cli assert-anchored 0x0000000000000000000000000000000000000000000000000000000000000000; then
  echo "UNEXPECTED: unanchored state root was accepted" >&2
  exit 1
fi

printf '\n=== demo complete\n'
