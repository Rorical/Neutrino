# GPU proving

The node supports SP1 6.8.1 CPU and local NVIDIA CUDA backends. A single selection
routes Fact, Evidence, Block, Chunk and History proving through the same prover. CUDA does
not change the Guest programs, proof format, recursive checks or chain identity.
Proof verification and WASM execution remain local host work.

## Build and configure

CPU is the default, including on macOS. CUDA execution requires Linux x86-64,
an NVIDIA GPU and a driver compatible with the pinned SP1 GPU server. Apple
Silicon/Metal is not supported by this backend. The optional CUDA client can be
compiled on a Mac for integration checks, but cannot run GPU proofs there.

Install the normal [build prerequisites](../README.md#prerequisites), then build:

```sh
cargo build --locked --release -p neutrino-node --features cuda
```

Add this section to the node's existing TOML configuration:

```toml
[proving]
backend = "cuda"
cuda_device = 0
concurrency = 1
capacity = 16
```

```sh
./target/release/neutrino-node --config /path/to/node.toml
```

`cuda_device` defaults to 0 when omitted. CPU configuration omits that field and
uses `backend = "cpu"`; its worker/capacity defaults remain 2/16. Concurrency bounds all proving calls with live Block/Chunk priority; capacity
bounds queued and running block jobs, including restart recovery. The SDK serializes requests
on a device's shared client connection, so one block worker is the starting GPU
configuration; raising it does not establish multi-GPU execution.

SP1 starts a local `sp1-gpu-server`, communicating over a Unix socket. Its SDK
installs the matching server in `$HOME/.sp1/bin` when absent or mismatched, which
requires release download access and a writable SP1 installation directory.
This integration has no remote endpoint or hosted proving-network selection.
`SP1_PROVER` does not override the node's explicit TOML backend.

Unsupported CUDA builds/platforms fail before node services start. Driver,
server or key-setup failures abort startup; they do not switch to CPU. Startup
logs name the backend and configured device. All five programs retain their
backend-specific proving keys; CUDA session handles are never reconstructed
from disk VKs. The server's program VK is checked against the local ELF/circuit
identity. CPU VK caching remains available.

Library callers use `backend::cuda_prover` inside a multithreaded Tokio runtime
and keep that runtime alive through key/prover cleanup. The node and the GPU
acceptance test already provide this runtime.

## Verification gates

Ordinary checks do not need a GPU and never start its server:

```sh
cargo test --locked -p neutrino-node -p neutrino-runtime-host --features neutrino-node/cuda
cargo clippy --locked --all-targets -p neutrino-node -p neutrino-runtime-host --features neutrino-node/cuda -- -D warnings
```

An ignored real-proof test covers Fact → Evidence → Block → Chunk → History compression and
verifies the resulting receipts using an independent local Light prover (the
SDK's real CPU verifier). It uses the same fixture and stage checkpointing as
the CPU gate. On a GPU machine, use fresh directories for the first hardware
acceptance so cached CPU proofs cannot substitute for CUDA proving:

```sh
export NEUTRINO_CUDA_DEVICE=0
export NEUTRINO_SP1_CACHE_DIR="$PWD/target/cuda-acceptance/sp1"
export NEUTRINO_EVIDENCE_GATE_DIR="$PWD/target/cuda-acceptance/stages"
cargo test --locked --release -p neutrino-runtime-host --features cuda \
  --test evidence_pipeline evidence_block_chunk_cuda_compressed_recursion \
  -- --ignored --exact --nocapture
```

`notebooks/neutrino-gpu-gate.ipynb` wraps the same flow for Google Colab (parameters,
Drive mount, clone, gate, summary). `scripts/colab-gpu-gate.sh` performs the whole sequence on a fresh Linux x86-64 GPU
box (dependencies, pinned toolchains, CUDA build, gate, instruction profile) and keeps
caches and logs under `OUT_DIR`, which on Google Colab should be a mounted Drive path so
an interrupted session can resume. SP1's CUDA prover downloads a standalone
`sp1-gpu-server` binary; no Docker is required. Plan for a high-memory runtime: the
CPU-side traces and recursion need well over the 12 GiB of a free-tier instance.

Before measuring, note the only numbers recorded so far are guest instruction counts
from `cargo test -p neutrino-runtime-host --test proof_work_profile -- --ignored --nocapture`
(see design 19): roughly 30 M chunk-guest instructions with in-circuit BLS versus
4 M when Fact receipts cover the chunk's signature checks. Measure both variants.

Keep those directories to resume an interrupted GPU run; use new directories to
measure fresh proving latency. The CUDA hardware gate and speed measurements
remain pending: development here is on a Mac without an NVIDIA GPU. Compilation,
configuration rejection tests and CPU regressions are separate from hardware
acceptance; no speedup has been measured.

Current ELF acceptance must be rerun after the history-tree, compact Chunk and
checkpoint Guest changes. Earlier program hashes and test counts do not certify
this implementation. The additional ignored `history_recursion` CPU/CUDA gates
exercise independent range Merge and a further recursive parent, with fresh stage
caches for hardware acceptance.
