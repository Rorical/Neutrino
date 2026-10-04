#!/usr/bin/env bash
# One-shot GPU acceptance run for a fresh Linux x86-64 box with an NVIDIA GPU,
# written for Google Colab but usable on any VM. Run from a notebook cell as:
#
#   !bash scripts/colab-gpu-gate.sh 2>&1 | tee -a /content/drive/MyDrive/neutrino-gpu/run.log
#
# Prerequisites inside the notebook (before calling this script):
#   from google.colab import drive; drive.mount('/content/drive')
#   !git clone <repo-url> /content/neutrino && cd /content/neutrino && git checkout <commit>
#
# What it does:
#   1. Installs build dependencies, rustup (toolchain pinned by rust-toolchain.toml)
#      and the SP1 toolchain at the pinned version.
#   2. Builds the workspace with the CUDA feature.
#   3. Runs the CUDA evidence -> block -> chunk -> history gate with memory-
#      conscious SP1 worker settings, persisting stage caches to OUT_DIR so an
#      interrupted session can resume.
#
# Environment knobs:
#   OUT_DIR   where caches and logs go (default: Google Drive path below)
#   SKIP_CPU  set to 1 to skip the CPU consensus gate (default: skipped)
set -euo pipefail

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
OUT_DIR="${OUT_DIR:-/content/drive/MyDrive/neutrino-gpu}"
SP1_VERSION="${SP1_VERSION:-6.8.1}"
mkdir -p "$OUT_DIR"
cd "$REPO_DIR"

echo "== host =="
uname -a
nvidia-smi || { echo "no NVIDIA GPU visible; pick a GPU runtime"; exit 1; }
free -g | head -2
df -h "$OUT_DIR" | tail -1

echo "== system packages =="
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  # libprotobuf-dev carries protoc's standard includes (google/protobuf/*.proto),
  # which sp1-prover-types needs; it is only a recommended package of protobuf-compiler.
  apt-get install -y -qq build-essential clang cmake curl git libclang-dev libprotobuf-dev libssl-dev pkg-config protobuf-compiler time >/dev/null
fi

echo "== rust toolchain =="
if ! command -v rustup >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path
fi
export PATH="$HOME/.cargo/bin:$HOME/.sp1/bin:$PATH"
rustup show >/dev/null            # installs the pinned 1.99.0 toolchain
rustup target add wasm32-unknown-unknown >/dev/null

echo "== sp1 toolchain $SP1_VERSION =="
if ! command -v cargo-prove >/dev/null || ! cargo prove --version 2>/dev/null | grep -q "$SP1_VERSION"; then
  curl -fsSL https://sp1up.succinct.xyz | bash
  "$HOME/.sp1/bin/sp1up" --version "$SP1_VERSION"
fi
cargo prove --version

echo "== build (cuda feature) =="
# The build directory must be on local disk: Google Drive is mounted without
# execute permission, so build scripts and test binaries there cannot run.
# Only SP1 stage caches and logs go to OUT_DIR. A disconnect therefore costs a
# rebuild, but never a lost proving stage.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_DIR/target}"
case "$CARGO_TARGET_DIR" in
  /content/drive/*) echo "CARGO_TARGET_DIR must not be on Drive (noexec): $CARGO_TARGET_DIR"; exit 1 ;;
esac
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$(nproc)}"
export SP1_PROVER=cuda
cargo build --locked --release -p neutrino-node -p neutrino-runtime-host --features neutrino-node/cuda

# GNU time reports peak resident memory; degrade gracefully without it.
if [ -x /usr/bin/time ]; then
  MEASURE=(/usr/bin/time -v)
else
  echo "GNU time not installed; peak memory will not be reported"
  MEASURE=()
fi

echo "== cuda runtime libraries =="
# sp1-gpu-server is a prebuilt binary that dynamically links the CUDA runtime
# (libcudart.so.12 and friends). Colab ships the driver but not always the
# toolkit libraries on the loader path, so collect every plausible location.
cuda_lib_dirs=()
for d in /usr/local/cuda/lib64 /usr/local/cuda-12*/lib64 /usr/local/cuda/targets/x86_64-linux/lib \
         /usr/lib/x86_64-linux-gnu /usr/local/nvidia/lib64 /usr/lib64-nvidia; do
  [ -d "$d" ] && cuda_lib_dirs+=("$d")
done
# pip-provided runtimes (nvidia-cuda-runtime-cu12 and siblings).
while IFS= read -r d; do cuda_lib_dirs+=("$d"); done < <(python3 - <<'PY' 2>/dev/null
import glob, site, sys
roots = set(site.getsitepackages() + [site.getusersitepackages()])
for root in roots:
    for d in glob.glob(f"{root}/nvidia/*/lib"):
        print(d)
PY
)
if ! ls "${cuda_lib_dirs[@]/%//libcudart.so.12}" >/dev/null 2>&1 \
   && ! find "${cuda_lib_dirs[@]}" -maxdepth 1 -name 'libcudart.so.12*' 2>/dev/null | grep -q .; then
  echo "libcudart.so.12 not found; installing the pip CUDA runtime"
  pip install -q nvidia-cuda-runtime-cu12 nvidia-cublas-cu12 nvidia-curand-cu12 >/dev/null 2>&1 || true
  while IFS= read -r d; do cuda_lib_dirs+=("$d"); done < <(python3 -c 'import glob,site; [print(d) for r in set(site.getsitepackages()) for d in glob.glob(f"{r}/nvidia/*/lib")]' 2>/dev/null)
fi
export LD_LIBRARY_PATH="$(IFS=:; echo "${cuda_lib_dirs[*]}")${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
# The SP1 client downloads sp1-gpu-server on first use; if it is already
# present, fail fast with the exact missing libraries instead of a late panic.
if [ -x "$HOME/.sp1/bin/sp1-gpu-server" ]; then
  if ldd "$HOME/.sp1/bin/sp1-gpu-server" | grep -q 'not found'; then
    echo "sp1-gpu-server is missing shared libraries:"
    ldd "$HOME/.sp1/bin/sp1-gpu-server" | grep 'not found'
    exit 1
  fi
  echo "sp1-gpu-server shared libraries resolve"
fi

echo "== gate configuration =="
# Shared memory-conscious worker settings, then CUDA-specific cache dirs that
# must never alias CPU caches.
# shellcheck source=scripts/sp1-cpu-env.sh
source scripts/sp1-cpu-env.sh
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-$(nproc)}"
export NEUTRINO_SP1_CACHE_DIR="$OUT_DIR/cuda-acceptance/sp1"
export NEUTRINO_EVIDENCE_GATE_DIR="$OUT_DIR/cuda-acceptance/stages"
mkdir -p "$NEUTRINO_SP1_CACHE_DIR" "$NEUTRINO_EVIDENCE_GATE_DIR"
env | grep -E '^(SP1_|SHARD_|RAYON_|NEUTRINO_|CARGO_TARGET)' | sort

if [ "${SKIP_CPU:-1}" != "1" ]; then
  echo "== cpu consensus gate (upper bound) =="
  "${MEASURE[@]}" cargo test --locked --release --workspace --test consensus_chunk \
    consensus_guest_real_compressed_recursion -- --ignored --nocapture 2>&1 | tee "$OUT_DIR/cpu-consensus-gate.log"
fi

echo "== cuda evidence/block/chunk/history gate =="
START=$(date +%s)
"${MEASURE[@]}" cargo test --locked --release -p neutrino-runtime-host --features cuda \
  --test evidence_pipeline evidence_block_chunk_cuda_compressed_recursion -- --ignored --exact --nocapture \
  2>&1 | tee "$OUT_DIR/cuda-evidence-gate.log"
echo "cuda gate wall seconds: $(( $(date +%s) - START ))" | tee -a "$OUT_DIR/cuda-evidence-gate.log"

echo "== guest instruction profile (execution only) =="
cargo test --locked --release -p neutrino-runtime-host --test proof_work_profile -- --ignored --nocapture \
  2>&1 | grep -E '^PROFILE' | tee "$OUT_DIR/profile.log"

echo "== done; logs and caches in $OUT_DIR =="
