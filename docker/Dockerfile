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
        clang \
        cmake \
        git \
        libclang-dev \
        libssl-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# Copy the entire workspace; cargo will figure out the dependency graph.
# Test crates and rv32im runtimes are skipped at build time because we
# only ask for `-p neutrino-node`.
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

USER neutrino
WORKDIR /home/neutrino

# Default port mapping aligned with docker-compose.yml.
EXPOSE 30303/tcp 30303/udp

ENV RUST_LOG="info,libp2p=warn,libp2p_swarm=info"

ENTRYPOINT ["/usr/local/bin/neutrino-node"]
CMD ["--config", "/etc/neutrino/config.toml"]
