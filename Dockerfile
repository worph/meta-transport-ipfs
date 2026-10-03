# syntax=docker/dockerfile:1
# =============================================================================
# meta-transport-ipfs — a MetaMesh transport plugin for meta-share.
#
# Build context: this repo. The transport-plugin SDK is pinned by git tag in
# Cargo.toml; to build against an unreleased local SDK pass it as a named
# context and it replaces the tag:
#   docker build --build-context sdk=../meta-feeder-sdk .
# =============================================================================

FROM scratch AS sdk

FROM rust:1.89-slim-bookworm AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config cmake libssl-dev ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Content-derived cache barrier (see meta-share's Dockerfile): BuildKit can miss
# edits on WSL bind-mounts; a changing SRC_REV re-evaluates the COPYs below.
ARG SRC_REV=dev
RUN echo "source revision: ${SRC_REV}"

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src src
COPY --from=sdk / /sdk/
RUN if [ -f /sdk/Cargo.toml ]; then \
        echo "building against the local SDK (named context)"; \
        sed -i 's|meta-feeder-sdk = { git = "https://github.com/worph/meta-feeder-sdk", tag = "v[0-9.]*",|meta-feeder-sdk = { path = "/sdk",|' Cargo.toml; \
    fi

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=meta-transport-ipfs-target,target=/build/target \
    cargo build --release --bin meta-transport-ipfs \
    && cp target/release/meta-transport-ipfs /meta-transport-ipfs

# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /meta-transport-ipfs /usr/local/bin/meta-transport-ipfs

# Same uid as meta-share: the plugins share its /data volume.
RUN useradd --system --uid 10001 --no-create-home metashare \
    && mkdir -p /data/meta-share \
    && chown metashare:metashare /data/meta-share
USER metashare
WORKDIR /data/meta-share

# 3000: the transport contract + the /ipfs/:cid gateway the hull relays (internal
# network only). 4001: libp2p (P2P_LISTEN) — publish it on the host; PUBLIC_ADDR
# announces it.
EXPOSE 3000 4001

ENV HTTP_LISTEN=0.0.0.0:3000 \
    P2P_LISTEN=/ip4/0.0.0.0/tcp/4001 \
    META_SHARE_DATA=/data/meta-share \
    META_SHARE_CONFIG_DIR=/config \
    RUST_LOG=info,meta_transport_ipfs=info,libp2p=warn,beetswap=warn,yamux=warn

ENTRYPOINT ["/usr/local/bin/meta-transport-ipfs"]
