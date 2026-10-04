#!/usr/bin/env bash
# Make the CUDA runtime libraries visible to SP1's prebuilt sp1-gpu-server.
# Source this (do not execute) before any CUDA proving command. Safe to source
# repeatedly. Colab ships the NVIDIA driver but keeps the toolkit libraries in
# pip packages, so every plausible location is collected into LD_LIBRARY_PATH.
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

