#!/usr/bin/env bash
# Real two-block SP1 recursion gate with bounded local CPU worker concurrency.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/sp1-cpu-env.sh
source scripts/sp1-cpu-env.sh

exec cargo test --locked --workspace --test consensus_chunk \
  consensus_guest_real_compressed_recursion -- --ignored --nocapture
