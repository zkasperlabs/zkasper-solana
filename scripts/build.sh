#!/usr/bin/env bash
# Builds the SBF program into target/deploy/.
set -euo pipefail
cd "$(dirname "$0")/.."

export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

mkdir -p target/deploy
# Keep the deployed address equal to the one in `declare_id!`. The CLI resolves
# the program id from `declare_id!` and nothing else, so a keypair that does not
# match it produces a deployment no client can talk to.
PROGRAM_KEYPAIR="${PROGRAM_KEYPAIR:-keys/zkasper_verifier-keypair.json}"
cp "$PROGRAM_KEYPAIR" target/deploy/zkasper_solana_program-keypair.json

# agave 4.x has `disable_sbpf_v0_execution` active, so new deployments must be v3.
cargo-build-sbf --manifest-path program/Cargo.toml --arch v3 "$@"
ls -l target/deploy/zkasper_solana_program.so
