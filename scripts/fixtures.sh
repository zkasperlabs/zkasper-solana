#!/usr/bin/env bash
# Regenerates fixtures/. Deterministic: the output is byte-for-byte stable.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo run --release -p zkasper-fixture-gen -- fixtures
