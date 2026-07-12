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
# Via mirror.gcr.io (Docker Hub pull-through) to dodge the anonymous 429 (JEF-78).
FROM mirror.gcr.io/library/rust:1-bookworm AS builder
WORKDIR /app
# cmake: reqwest's rustls provider (aws-lc-rs → aws-lc-sys) is a C build. zstd: unpacks
# the bpf-linker release. CFLAGS=gnu17 keeps aws-lc-sys' emitted libc symbols in step
# with the 2.36 runtime (a C23 gcc would emit glibc-2.38 __isoc23_* — same engine fix).
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake curl ca-certificates zstd \
    && rm -rf /var/lib/apt/lists/*
ENV CFLAGS=-std=gnu17
# sccache (JEF-84) is the dep-caching layer — it shares the rustc object cache with the in-cluster
# Redis (cluster repo charts/sccache), reached via the meshed BuildKit's own identity, so a
# workspace dep compiled by ANY repo's image build (or the CI test build) is reused here. sccache
# is a HARD GATE — if it can't start against Redis the build FAILS (no fallback). The build
# sandboxes share a netns, so concurrent matrix builds clash on sccache's fixed default port 4226
# ("Address in use"); the build RUN below sets a unique random SCCACHE_SERVER_PORT to avoid that.
# CARGO_INCREMENTAL=0 is required (sccache can't cache incremental). The musl sccache binary is
# static, so it runs on this glibc base (mozilla/sccache ships no x86_64/aarch64 linux-gnu build).
RUN set -eux; ver=0.16.0; \
    case "$(uname -m)" in x86_64) a=x86_64 ;; aarch64) a=aarch64 ;; *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;; esac; \
    wget -qO- "https://github.com/mozilla/sccache/releases/download/v${ver}/sccache-v${ver}-${a}-unknown-linux-musl.tar.gz" \
      | tar -xz -C /usr/local/bin --strip-components=1 "sccache-v${ver}-${a}-unknown-linux-musl/sccache"
ENV RUSTC_WRAPPER=sccache CARGO_INCREMENTAL=0 \
    SCCACHE_REDIS=redis://sccache-redis.dev.svc.cluster.local:6379
# Prebuilt bpf-linker (sha256-pinned, per-arch) + nightly/rust-src for the bpf target's
# build-std. Prebuilt so the image build stays light (no LLVM source build).
# ARCH-AWARE: with native multi-arch builders (JEF-295/#161) this builder stage runs on
# the TARGET arch, so a hardcoded aarch64 bpf-linker Syntax-errors when run on the amd64
# build leg ("bpf-linker: 1: Syntax error"). Pick the musl build by TARGETARCH
# (arm64->aarch64, amd64->x86_64), keeping the per-arch SHA-256 pin.
ARG BPF_LINKER_VERSION=0.10.4
ARG BPF_LINKER_SHA256_ARM64=c3638cd3cb735ff85705905a07e0df61c0f9426480334c8e2efe5cb92fd9d3de
ARG BPF_LINKER_SHA256_AMD64=4dda77daab6c5f120a468e6d3ede2498f5bd47ece712172cfb7290176d93d015
ARG TARGETARCH
RUN set -eux; \
    case "$TARGETARCH" in \
      arm64) bl_arch=aarch64; bl_sum="$BPF_LINKER_SHA256_ARM64" ;; \
      amd64) bl_arch=x86_64;  bl_sum="$BPF_LINKER_SHA256_AMD64" ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/bl.tar.zst "https://github.com/aya-rs/bpf-linker/releases/download/v${BPF_LINKER_VERSION}/bpf-linker-${bl_arch}-unknown-linux-musl.tar.zst"; \
    echo "${bl_sum}  /tmp/bl.tar.zst" | sha256sum -c -; \
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
    set -e; \
    export SCCACHE_SERVER_PORT=$(awk 'BEGIN{srand(); print int(20000+rand()*40000)}'); \
    timeout 10 sccache --start-server; \
    cargo build --release -p protector-agent --features ebpf; \
    cp target/release/protector-agent /app/protector-agent-bin; \
    sccache --show-stats

# Slim runtime. The image runs as non-root; the eBPF capabilities it needs are granted
# at RUNTIME by the DaemonSet's securityContext (chart), not baked in.
FROM mirror.gcr.io/library/debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 65532 --user-group --no-create-home --shell /usr/sbin/nologin nonroot
COPY --from=builder --chown=65532:65532 /app/protector-agent-bin /app/protector-agent
USER 65532:65532
HEALTHCHECK NONE
ENTRYPOINT ["/app/protector-agent"]
