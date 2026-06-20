# protector-agent image (ADR-0014). Build context is the REPO ROOT — the agent's
# userspace crate path-depends on ../../behavior (the shared wire crate, used by the
# engine too), which lives outside agent/. Build with `-f agent/Dockerfile .`.
#
# Builds the agent WITH the eBPF probe (`--features ebpf`): the builder stage carries
# the bpf toolchain (prebuilt bpf-linker + nightly + rust-src), and the userspace
# build.rs compiles the sibling protector-agent-ebpf crate to a BPF object and embeds
# it in the loader. The BPF object is architecture-neutral (CO-RE-relocated against the
# node's BTF at load); the elevated caps it needs are granted at RUNTIME by the
# DaemonSet's securityContext, never baked into the image.

# bookworm-based to match the bookworm-slim runtime's glibc 2.36.
FROM rust:1-bookworm AS builder
WORKDIR /app
# cmake: reqwest's rustls provider (aws-lc-rs → aws-lc-sys) is a C build. zstd: unpacks
# the bpf-linker release. CFLAGS=gnu17 keeps aws-lc-sys' emitted libc symbols in step
# with the 2.36 runtime (a C23 gcc would emit glibc-2.38 __isoc23_* — same engine fix).
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake curl ca-certificates zstd \
    && rm -rf /var/lib/apt/lists/*
ENV CFLAGS=-std=gnu17
# Prebuilt bpf-linker (aarch64-musl, sha256-pinned) + nightly/rust-src for the bpf
# target's build-std. Prebuilt so the image build stays light (no LLVM source build).
ARG BPF_LINKER_VERSION=0.10.4
ARG BPF_LINKER_SHA256=c3638cd3cb735ff85705905a07e0df61c0f9426480334c8e2efe5cb92fd9d3de
RUN set -eux; \
    curl -fsSL -o /tmp/bl.tar.zst "https://github.com/aya-rs/bpf-linker/releases/download/v${BPF_LINKER_VERSION}/bpf-linker-aarch64-unknown-linux-musl.tar.zst"; \
    echo "${BPF_LINKER_SHA256}  /tmp/bl.tar.zst" | sha256sum -c -; \
    tar --zstd -xf /tmp/bl.tar.zst -C /tmp; \
    install -m 0755 "$(find /tmp -maxdepth 2 -name bpf-linker -type f | head -1)" /usr/local/bin/bpf-linker; \
    rm /tmp/bl.tar.zst
RUN rustup toolchain install nightly --component rust-src --profile minimal
# The agent workspace (protector-agent + common + the excluded ebpf crate) and the shared
# behavior crate it depends on. build.rs compiles agent/protector-agent-ebpf during the
# userspace build.
COPY agent/ agent/
COPY behavior/ behavior/
WORKDIR /app/agent
# Workspace target is /app/agent/target; the excluded ebpf crate keeps its own.
RUN --mount=type=cache,target=/app/agent/target,sharing=locked \
    --mount=type=cache,target=/app/agent/protector-agent-ebpf/target,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release -p protector-agent --features ebpf \
    && cp target/release/protector-agent /app/protector-agent-bin

# Slim runtime. The image runs as non-root; the eBPF capabilities it needs are granted
# at RUNTIME by the DaemonSet's securityContext (chart), not baked in.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 65532 --user-group --no-create-home --shell /usr/sbin/nologin nonroot
COPY --from=builder --chown=65532:65532 /app/protector-agent-bin /app/protector-agent
USER 65532:65532
HEALTHCHECK NONE
ENTRYPOINT ["/app/protector-agent"]
