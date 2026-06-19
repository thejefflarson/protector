# protector-agent image (ADR-0014). Build context is `agent/`.
#
# Current build: the USERSPACE agent (default features = no-op observer). It's a
# real, deployable arm64 image — useful for shadow bring-up: it validates scheduling,
# the scoped caps, hostPID, and that the report path reaches the engine's /behavior.
#
# The eBPF builder stage lands with the completed probe: a stage with `bpf-linker`
# + the `bpfel-unknown-none` target compiling `protector-agent-ebpf` to a BPF object
# (CO-RE bytecode — architecture-neutral, relocated against the node's BTF at load),
# then the userspace built `--features ebpf` with that object `include_bytes!`'d in.
# Until the probe's kernel wiring is done (agent/README.md), the shipped agent runs
# the no-op observer rather than crash-looping a half-wired loader.

# --- eBPF compile (ADR-0014) --------------------------------------------------
# Compiles the BPF probe to bytecode. nightly + rust-src for the bpf target's
# build-std, and bpf-linker installed from its PREBUILT aarch64-musl binary (building
# it from source pulls LLVM — the heavy step we avoid). The BPF object is
# architecture-neutral; the kernel CO-RE-relocates it at load. The userspace image
# below doesn't depend on this stage yet — the loader is wired once it's green.
FROM rust:1-bookworm AS ebpf
ARG BPF_LINKER_VERSION=0.10.4
ARG BPF_LINKER_SHA256=c3638cd3cb735ff85705905a07e0df61c0f9426480334c8e2efe5cb92fd9d3de
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates zstd \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /tmp/bl.tar.zst "https://github.com/aya-rs/bpf-linker/releases/download/v${BPF_LINKER_VERSION}/bpf-linker-aarch64-unknown-linux-musl.tar.zst" \
    && echo "${BPF_LINKER_SHA256}  /tmp/bl.tar.zst" | sha256sum -c - \
    && tar --zstd -xf /tmp/bl.tar.zst -C /tmp \
    && install -m 0755 "$(find /tmp -maxdepth 2 -name bpf-linker -type f | head -1)" /usr/local/bin/bpf-linker \
    && rm /tmp/bl.tar.zst
RUN rustup toolchain install nightly --component rust-src --profile minimal
WORKDIR /app
COPY protector-agent-ebpf/ protector-agent-ebpf/
WORKDIR /app/protector-agent-ebpf
RUN --mount=type=cache,target=/app/protector-agent-ebpf/target,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry \
    cargo +nightly build --release

# --- userspace agent ----------------------------------------------------------
# bookworm-based to match the bookworm-slim runtime's glibc 2.36.
FROM rust:1-bookworm AS builder
WORKDIR /app
# reqwest's rustls provider (aws-lc-rs → aws-lc-sys) is a C build needing cmake; pin
# the C standard to gnu17 so a C23-defaulting gcc doesn't emit glibc-2.38 `__isoc23_*`
# symbols that fail to link against the 2.36 runtime (same fix as the engine image).
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*
ENV CFLAGS=-std=gnu17
COPY protector-agent/ protector-agent/
WORKDIR /app/protector-agent
RUN --mount=type=cache,target=/app/protector-agent/target,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release && cp target/release/protector-agent /app/protector-agent-bin

# Slim runtime. The image runs as non-root; the eBPF capabilities it will need are
# granted at RUNTIME by the DaemonSet's securityContext (chart), not baked in.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 65532 --user-group --no-create-home --shell /usr/sbin/nologin nonroot
COPY --from=builder --chown=65532:65532 /app/protector-agent-bin /app/protector-agent
USER 65532:65532
HEALTHCHECK NONE
ENTRYPOINT ["/app/protector-agent"]
