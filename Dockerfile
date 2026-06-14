# Builder must match the runtime's glibc. debian:bookworm-slim ships glibc 2.36;
# the -bookworm cargo-chef tag is built on bookworm so the two stay in sync and
# the dynamically-linked binary loads on the slim runtime.
FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN --mount=type=cache,target=/app/target,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry \
    cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
# sigstore-rs pulls aws-lc-sys (the rustls crypto provider via rustls-webpki),
# which is a C library built with cmake — not present in the base image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*
# Pin the C standard for aws-lc-sys' C build. A C23-defaulting gcc (which newer
# cargo-chef base images now ship) rewrites sscanf/strtol to the glibc-2.38
# `__isoc23_*` variants; linked against the bookworm-slim runtime's glibc 2.36 those
# are undefined references and the release link fails ("undefined reference to
# __isoc23_sscanf"). gnu17 keeps the emitted libc symbols in step with the runtime
# glibc. (Changing CFLAGS also reruns aws-lc-sys' build script, rebuilding a stale,
# toolchain-mismatched object left in the build cache.)
ENV CFLAGS=-std=gnu17
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN --mount=type=cache,target=/app/target,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry \
    cargo chef cook --release --recipe-path recipe.json

# Build application
COPY . .
RUN --mount=type=cache,target=/app/target,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release

RUN --mount=type=cache,target=/app/target,sharing=locked \
    cp /app/target/release/protector ./protector

# Slim runtime. Fixed-UID non-root user (65532) matches the chart's
# securityContext.runAsUser/runAsGroup so the pod satisfies runAsNonRoot.
# ca-certificates is needed for TLS to the API server (inbound), and to the
# registry, Rekor, and the sigstore TUF root (outbound signature verification).
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 65532 --user-group --no-create-home --shell /usr/sbin/nologin nonroot
COPY --from=builder --chown=65532:65532 /app/protector /app/protector
USER 65532:65532
HEALTHCHECK NONE
EXPOSE 8443
ENTRYPOINT ["/app/protector"]
