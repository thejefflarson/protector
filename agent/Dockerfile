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

# --- eBPF compile validation (ADR-0014) ---------------------------------------
# Compiles the BPF probe to bytecode. Needs nightly (build-std for the bpf target,
# which has no prebuilt core), rust-src, and bpf-linker — which links against an LLVM
# matching nightly's (LLVM 19), installed from apt.llvm.org since bookworm's default is
# older. The BPF object is architecture-neutral; the kernel CO-RE-relocates it at load.
# Built as a CI validation stage (the userspace image below doesn't depend on it yet —
# the loader is wired once this compiles green).
FROM rust:1-bookworm AS ebpf
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl gnupg ca-certificates \
    && curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-19 main" > /etc/apt/sources.list.d/llvm.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends llvm-19-dev libclang-19-dev clang-19 \
    && rm -rf /var/lib/apt/lists/*
ENV LLVM_SYS_191_PREFIX=/usr/lib/llvm-19
RUN rustup toolchain install nightly --component rust-src --profile minimal \
    && cargo +nightly install bpf-linker --locked
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
