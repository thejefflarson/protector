# Builder must match the runtime's glibc. debian:bookworm-slim ships glibc 2.36;
# the rust:1-bookworm builder is built on bookworm so the two stay in sync and the
# dynamically-linked binary loads on the slim runtime.
# Pulled via mirror.gcr.io (Google's Docker Hub pull-through cache) — the homelab
# buildkit's shared IP exhausts Docker Hub's anonymous quota → 429 (JEF-78).
# Node stage (ADR-0025): build the Preact dashboard bundle from source. The Rust builder
# `include_str!`s engine/web/dist/dashboard.js, which is gitignored (built, never
# committed) — so it must be produced here and COPYed in before `cargo build`. This
# fetches preact+esbuild-wasm from npm exactly as the cargo stages fetch crates from
# crates.io; zero-egress is scoped to the RUNNING engine, not the build (ADR-0025). Pulled
# via mirror.gcr.io for the same Docker Hub quota reason as the cargo base (JEF-78).
# `npm ci --ignore-scripts` kills install hooks; the build uses esbuild-WASM (arch-neutral,
# so the same command works on the amd64 and arm64 native builders — no per-arch esbuild
# binary to resolve).
FROM mirror.gcr.io/library/node:26-bookworm-slim AS web
WORKDIR /web
COPY engine/web/package.json engine/web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY engine/web/ ./
RUN npm run build

FROM mirror.gcr.io/library/rust:1-bookworm AS builder
WORKDIR /app
# sigstore-rs pulls aws-lc-sys (the rustls crypto provider via rustls-webpki),
# which is a C library built with cmake — not present in the base image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*
# Pin the C standard for aws-lc-sys' C build. A C23-defaulting gcc (which newer
# base images now ship) rewrites sscanf/strtol to the glibc-2.38 `__isoc23_*`
# variants; linked against the bookworm-slim runtime's glibc 2.36 those are
# undefined references and the release link fails ("undefined reference to
# __isoc23_sscanf"). gnu17 keeps the emitted libc symbols in step with the runtime
# glibc. (Changing CFLAGS also reruns aws-lc-sys' build script, rebuilding a stale,
# toolchain-mismatched object left in the build cache.)
ENV CFLAGS=-std=gnu17
# sccache (JEF-84) is the dep-caching layer now — it shares the rustc object cache with the
# in-cluster Redis (cluster repo charts/sccache), reached via the meshed BuildKit's own identity,
# so a workspace dep compiled by ANY repo's image build (or the CI test build) is reused here.
# cargo-chef was REMOVED: sccache + cargo-chef's `cook` fight over the shared /app/target dir and
# abort with "Failed to open file for hashing: …/lib*.rmeta" (JEF-389) — a conflict that is
# backend-independent (it fails on the local fallback too). A single plain `cargo build` compiles
# deps then workspace crates in dependency order, so every `--extern` .rmeta exists when sccache
# hashes it. sccache is a HARD GATE here — if it can't start against Redis the build FAILS (no
# fallback). The earlier arm64 failures were a sccache PORT COLLISION, not a network problem: the
# build sandboxes share a netns, so concurrent matrix builds clashed on sccache's fixed default
# port 4226 ("Address in use"). The RUN below sets a unique random SCCACHE_SERVER_PORT to avoid
# that. CARGO_INCREMENTAL=0 is required (sccache can't cache incremental); the 10s guard only
# bounds a genuinely-down Redis (a normal start is ~0.4s). The musl sccache binary is static, so
# it runs on this glibc base (mozilla/sccache ships no x86_64/aarch64 linux-gnu build).
RUN set -eux; ver=0.16.0; \
    case "$(uname -m)" in x86_64) a=x86_64 ;; aarch64) a=aarch64 ;; *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;; esac; \
    wget -qO- "https://github.com/mozilla/sccache/releases/download/v${ver}/sccache-v${ver}-${a}-unknown-linux-musl.tar.gz" \
      | tar -xz -C /usr/local/bin --strip-components=1 "sccache-v${ver}-${a}-unknown-linux-musl/sccache"
ENV RUSTC_WRAPPER=sccache CARGO_INCREMENTAL=0 \
    SCCACHE_REDIS=redis://sccache-redis.dev.svc.cluster.local:6379
# Opt-out for builds that CANNOT reach the in-cluster redis. The github-hosted e2e
# (scripts/e2e.sh, runs-on: ubuntu-latest) does a plain `docker build` of this Dockerfile and can
# never reach sccache-redis.dev, so the hard gate would always trip there. Default empty => sccache
# stays a HARD GATE for the real deploy build on the meshed BuildKit; the e2e passes
# `--build-arg SCCACHE_DISABLE=1` to build plain (uncached) instead of failing.
ARG SCCACHE_DISABLE=""

# Build application
COPY . .
# The Preact bundle is gitignored (built, never committed), so `COPY . .` doesn't carry
# it — copy it from the node stage so `include_str!("../../../web/dist/dashboard.js")`
# resolves during `cargo build` (ADR-0025).
COPY --from=web /web/dist/dashboard.js engine/web/dist/dashboard.js
# BuildKit cache mounts persist the cargo registry/git + the compiled target dir across builds on
# the shared in-cluster BuildKit daemon; sccache adds the cross-repo/cross-daemon object cache on
# top. sharing=locked serialises concurrent matrix builds through one target dir (cargo can't share
# it concurrently); the ephemeral target mount means the binary is cp'd out to /app.
RUN --mount=type=cache,target=/app/target,id=protector-target-v2,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry \
    set -e; \
    if [ -n "$SCCACHE_DISABLE" ]; then \
      echo "sccache disabled (SCCACHE_DISABLE set) — plain build, no redis"; unset RUSTC_WRAPPER; \
    else \
      export SCCACHE_SERVER_PORT=$(awk 'BEGIN{srand(); print int(20000+rand()*40000)}'); \
      timeout 10 sccache --start-server; \
    fi; \
    cargo build --release; \
    cp /app/target/release/protector ./protector; \
    (sccache --show-stats 2>/dev/null || true)

# Slim runtime. Fixed-UID non-root user (65532) matches the chart's
# securityContext.runAsUser/runAsGroup so the pod satisfies runAsNonRoot.
# ca-certificates is needed for TLS to the API server (inbound), and to the
# registry, Rekor, and the sigstore TUF root (outbound signature verification).
FROM mirror.gcr.io/library/debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 65532 --user-group --no-create-home --shell /usr/sbin/nologin nonroot
COPY --from=builder --chown=65532:65532 /app/protector /app/protector
USER 65532:65532
HEALTHCHECK NONE
EXPOSE 8443
ENTRYPOINT ["/app/protector"]
