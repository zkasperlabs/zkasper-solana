#!/usr/bin/env bash
# Builds the program and runs every test, printing the compute-unit measurements.
set -euo pipefail
cd "$(dirname "$0")/.."

export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

./scripts/build.sh
cargo test -p zkasper-solana-program --features no-entrypoint
cargo test -p zkasper-program-tests -- --nocapture --test-threads=1
