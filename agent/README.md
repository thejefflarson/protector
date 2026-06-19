# protector-agent

protector's **first-party eBPF behavioral collector** — the default provider for the
behavioral-evidence port ([ADR-0014](../docs/adr/0014-behavioral-telemetry-ebpf.md)).
It runs as a DaemonSet, observes what workloads *actually do* (outbound connections,
secret reads, library loads), resolves each event's cgroup→pod, and POSTs normalized
observations to the engine's ingest (`POST /behavior`). Passive and read-only — it
observes, it never blocks or rewrites; enforcement stays the engine's reversible cut.

This makes protector self-sufficient (no dependency on Falco/Tetragon), while the
engine can still ingest those tools through a translation adapter — depend on the
*signal*, not the source ([ADR-0003](../docs/adr/0003-capability-ports.md)).

## Layout

- `protector-agent/` — **userspace** (compiles + unit-tests without a kernel). The
  report path, batching, cgroup→pod resolution, and the wire contract. The aya loader
  is behind the `ebpf` feature; the default build uses a no-op observer so the skeleton
  is verifiable in normal CI.
- `protector-agent-ebpf/` — the **eBPF programs** (`no_std`, bpf target). Built
  separately with bpf-linker; **not** part of the userspace `cargo build` or the engine
  repo's CI.

## Build

Userspace skeleton (no kernel needed — this is what's verified in this repo):

```sh
cd agent/protector-agent
cargo build          # no-op observer; report path + batcher + pod resolution
cargo test           # wire-contract + cgroup→pod parsing tests
```

Full agent with real probes (on a Linux node, ideally aarch64 to match the cluster):

```sh
# one-time toolchain
rustup toolchain install stable
cargo install bpf-linker
rustup target add bpfel-unknown-none      # little-endian bpf

# build the eBPF object, then the userspace with the loader
cd agent/protector-agent-ebpf && cargo build --release --target bpfel-unknown-none
cd ../protector-agent          && cargo build --release --features ebpf
```

The eBPF loader (`observer.rs`, `ebpf` feature) and the connection probe
(`protector-agent-ebpf`) are deliberately marked **NODE-BUILT**: their concrete kernel
wiring (sockaddr CO-RE reads, ring-buffer drain, attach) must be completed and
load-tested on a real kernel — it can't be exercised in the engine's CI — and they
fail loudly rather than pretend to observe until that lands.

## Configuration

| Env | Default | Meaning |
|-----|---------|---------|
| `PROTECTOR_AGENT_ENDPOINT` | `http://protector.protector.svc.cluster.local:9999` | engine runtime ingest base; the agent POSTs `{base}/behavior` |
| `RUST_LOG` | `protector_agent=info` | tracing filter |

## Deploy (phase 3)

A DaemonSet in the Helm chart, **scoped hard** ([ADR-0014](../docs/adr/0014-behavioral-telemetry-ebpf.md)):
`CAP_BPF` + `CAP_PERFMON` (or privileged on older kernels), its own minimal-RBAC
ServiceAccount, hostPID for cgroup→pod, no egress but to the engine, **no cluster-API
write**. Ships in shadow — signals only enrich the dashboard and the model's prompt —
before any behavior feeds the action-bar corroboration that can promote a cut.
