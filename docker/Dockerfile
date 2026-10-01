# syntax=docker/dockerfile:1.7
#
# Multi-stage Dockerfile for the `neutrino-node` binary.
#
# Stage 1: builder pinned to the same toolchain CI uses
# (rust-toolchain.toml -> 1.95.0). We compile `neutrino-node` with
# `--locked --release`, then copy the binary into a slim runtime stage.
#
# Stage 2: minimal Debian-slim runtime — libp2p QUIC + RocksDB need
# libstdc++ and libssl from glibc, so we cannot use scratch or distroless
# static. We expose a single 30303/tcp port by convention; tests can
# remap as needed.

ARG RUST_VERSION=1.95.0

# --- builder ------------------------------------------------------------------
FROM rust:${RUST_VERSION}-slim-bookworm AS builder

# RocksDB build prerequisites + git for cargo metadata.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        git \
        libclang-dev \
        libssl-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.sp1/bin:${PATH}"
RUN curl -fsSL https://sp1up.succinct.xyz | bash \
    && /root/.sp1/bin/sp1up --version 6.2.1 \
    && rustup target add wasm32-unknown-unknown

WORKDIR /src
# Copy the entire workspace; cargo will figure out the dependency graph.
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release -p neutrino-node \
    && cp /src/target/release/neutrino-node /usr/local/bin/neutrino-node

# --- runtime ------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 65532 neutrino

COPY --from=builder /usr/local/bin/neutrino-node /usr/local/bin/neutrino-node

# Persistent state directory. `data_dir` in the node config points
# here; mount a persistent volume so restarts resume from disk.
RUN mkdir -p /var/lib/neutrino \
    && chown neutrino:neutrino /var/lib/neutrino

USER neutrino
WORKDIR /home/neutrino

# Default node network ports.
EXPOSE 30303/tcp 30303/udp

ENV RUST_LOG="info,libp2p=warn,libp2p_swarm=info"

ENTRYPOINT ["/usr/local/bin/neutrino-node"]
CMD ["--config", "/etc/neutrino/config.toml"]
