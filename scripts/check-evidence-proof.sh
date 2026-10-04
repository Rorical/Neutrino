#!/usr/bin/env bash
# Real evidence → block → chunk gate with bounded local CPU worker concurrency.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/sp1-cpu-env.sh
source scripts/sp1-cpu-env.sh
export NEUTRINO_EVIDENCE_GATE_DIR="${NEUTRINO_EVIDENCE_GATE_DIR:-$PWD/target/proof-acceptance/evidence-pipeline}"

exec cargo test --locked -p neutrino-runtime-host --test evidence_pipeline \
  evidence_block_chunk_real_compressed_recursion -- --ignored --nocapture
