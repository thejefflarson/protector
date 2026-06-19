# 0014. First-party behavioral telemetry via eBPF, behind a tool-agnostic port

- Status: Accepted
- Date: 2026-06-19

## Context

The engine reasons about **structure**: who can reach whom (NetworkPolicy + mesh
authz), who can read which secret (mounts + RBAC), who can escalate, which CVEs an
image *carries* (the Vulnerability port), and which workloads are data stores (T1213,
[ADR-0005](0005-attack-objectives.md)). The model then judges exploitability on that
proven candidate ([ADR-0013](0013-proof-winnows-model-decides.md)). But structure is
*potential*, not *behavior* — and the gap is exactly where false positives and false
negatives live:

- A CVE is **present** on an image (trivy) but we never check whether its vulnerable
  code path is ever **loaded/invoked** (log4shell in the image, `JndiLookup` never on
  the classpath).
- A workload **can reach** a secret / a database / the internet, but we don't know if
  it **actually does** — reach is not use.
- A workload **mounts** a secret but we don't know if it ever **reads** it.

Today the only behavioral input is the RuntimeEvidence port ([`runtime.rs`](../../src/engine/runtime.rs)):
Falco critical alerts, POSTed via falcosidekick, normalized to a single
`{namespace, pod, rule}` observation that supplies the action bar's `corroborated-now`
predicate ([ADR-0009](0009-asymmetric-action-bar.md)). Two limits: it is **coarse** (a
rule fired, critical-only, boolean) and it **ties us to one sensor**. The second
violates the spirit of [ADR-0003](0003-capability-ports.md) — *depend on what a tool
answers, not which tool it is*. We want richer behavioral facts (actual connections,
secret reads, library loads) **and** to not depend on any particular sensor being
installed.

Constraints (unchanged from [ADR-0001](0001-async-mitigation-engine.md)): small,
CPU-only, aarch64 nodes; passive/read-only observation; the data stays **in-cluster**
(who-talks-to-whom and secret-access patterns are a blueprint for attacking the cluster
— the local-first conviction); the **webhook stays zero-access** (the floor is
untouched); the engine **never executes** anything. Behavioral facts are **observations
with a TTL**, like the existing runtime evidence — "happening now" is true only for a
window, so they can *sharpen* a proven candidate but never *fabricate* one.

## Decision

We will add behavioral telemetry as a **tool-agnostic evidence port** with a
**first-party eBPF collector** as its default provider.

**1. A normalized behavioral-evidence port (the contract).** Generalize the
RuntimeEvidence port from a Falco-shaped alert to a typed `BehavioralSignal`,
attributed to a pod and carrying an observation time (TTL'd by the existing
`RuntimeEvents` store). The initial signal vocabulary:

- `NetworkConnection { peer, scope: InCluster(workload) | Internet }` — an actual
  egress/peer connection the workload made.
- `SecretRead { secret }` — an actual read of a mounted secret's file.
- `LibraryLoaded { name }` — an actual load of a shared object / dependency artifact.
- `ProcessExec { exe }` — retained for parity with Falco's existing signal.

Any sensor feeds this port through a **thin translation adapter**; the engine depends
on the `BehavioralSignal`, not the source ([ADR-0003](0003-capability-ports.md)). The
current Falco/falcosidekick ingest becomes *one* such adapter (`ProcessExec` from its
rule alerts), no longer load-bearing — if it is absent, the port is simply fed by the
first-party collector instead. The ingest endpoint accepts the normalized schema
directly; sensor-specific shapes are translated at their adapter.

**2. A first-party eBPF collector (`protector-agent`).** A DaemonSet, written in Rust
with **[aya](https://aya-rs.dev)** (pure-Rust eBPF, CO-RE, no libbpf/C toolchain — it
fits our existing Rust + aarch64 cross-compile story and keeps the build self-contained).
It attaches to **stable kernel hooks** — LSM / tracepoints / kprobes such as
`security_socket_connect`, `security_file_open`, and shared-object `mmap` — aggregates
events **in-kernel** (BPF maps, per-pod counters, deduplicated peers) to keep overhead
bounded, resolves the originating **cgroup → pod** in userspace, and POSTs the rolled-up
`BehavioralSignal`s to the engine's behavioral ingest. It ships protector's behavioral
telemetry without requiring any third-party sensor.

**3. Consumers.** The behavioral signals feed both halves of the loop:

- **The model (sharper judgement).** The adjudication prompt gains an *Observed
  behavior* block. "Actually egresses to the internet" hardens an exfil (T1041) call;
  "the vulnerable library is actually loaded" hardens a foothold; "never connects to the
  database it can reach" is evidence the model can use to refute a T1213 reach. The
  model still decides — behavior is evidence, not a verdict.
- **The action bar (corroboration).** Specific behaviors are **live corroboration**,
  the same role Falco criticals play today ([ADR-0009](0009-asymmetric-action-bar.md)):
  actual internet egress on a workload corroborates an exfil chain; an actual
  vuln-library load on an exposed entry corroborates a foothold. Corroboration only ever
  *promotes* toward action behind the existing reversible, self-reverting cut — never a
  new kind of action.

Behavioral signals are **never graph structure**: they don't mint edges or nodes, so
the proof layer's "reach is proven, not guessed" invariant is untouched. They are TTL'd
corroboration/evidence layered onto chains the proof already winnowed.

## Consequences

Easier:

- **Closes the potential-vs-actual gap** — the biggest source of both false positives
  (CVE present but never loaded; reach never used) and missed corroboration (an attack
  actually in flight). Directly sharpens the T1041 and T1213 outcomes just added.
- **Tool independence (ADR-0003 honored).** protector is self-sufficient via its own
  collector, *and* can ingest Falco / Tetragon / any sensor through a translation
  adapter. No hard dependency on a specific tool.
- **Richer, structured corroboration** than rule-fired booleans, expanding what the
  action bar can safely act on — still only via the reversible network cut.

Harder / accepted downsides:

- **A privileged DaemonSet is new footprint.** Loading eBPF needs elevated capability
  (`CAP_BPF` + `CAP_PERFMON`, or privileged on older kernels) on every node — a real
  increase in protector's own attack surface. We accept it deliberately and **scope it
  hard**: read-only eBPF (observe, never modify kernel state or traffic), its own
  minimal-RBAC ServiceAccount, no egress except to the engine ingest, no cluster-API
  write. It is part of the **engine layer's evidence gathering** — the webhook floor
  keeps its zero-access property.
- **eBPF portability.** Kernel-version/CO-RE variance means a hook may be unavailable.
  The agent **degrades gracefully** — a missing hook means fewer signals, never a crash
  or a blocked node. Behavioral evidence is additive, so partial coverage still helps.
- **Per-node cost on Pis.** Bounded by in-kernel aggregation, peer dedup, sampling, and
  rate limits; the agent is observe-and-roll-up, not stream-every-packet.
- **Pod attribution.** cgroupv2 path → pod-UID resolution is fiddly and node-runtime
  specific; mis-attribution drops the signal rather than mislabeling it.
- **The data is sensitive.** Connection graphs and secret-access patterns are a map for
  an attacker; they **stay in-cluster** (agent → engine, same as the local model), never
  exported off-cluster beyond the existing OTLP metrics (which carry no per-peer detail).
- **Observation only.** The agent never blocks, kills, or rewrites — enforcement remains
  the engine's reversible, self-reverting NetworkPolicy cut
  ([ADR-0010](0010-flannel-actuator-workload-isolation.md)), unchanged.

Alternatives considered:

- **Depend on Falco/Tetragon directly.** Rejected: tool lock-in (against ADR-0003), and
  the signals we want (per-peer connection rollups, library loads) are awkward to express
  as another tool's rules. We still *consume* them when present.
- **eBPF via libbpf-rs / C.** Rejected: a C toolchain + BTF/cross-compile burden on
  aarch64; aya is Rust-native and matches the existing build.
- **Userspace-only (`/proc`, ptrace).** Rejected: racy, high-overhead, and misses
  short-lived events eBPF catches at the source.

## Rollout

Shadow-first, mirroring the engine's posture ([ADR-0001](0001-async-mitigation-engine.md)):

1. **Port + consumption.** Land the `BehavioralSignal` schema, the normalized ingest,
   the TTL store generalization, the prompt block, and the corroboration hook. Re-point
   the Falco adapter onto it. (Engine-only; unit-tested; no node access needed.)
2. **The agent.** Build `protector-agent` (aya) — network connections first, then secret
   reads and library loads — emitting normalized signals. Graceful degradation per hook.
3. **Deploy.** Add the DaemonSet to the chart with the scoped capabilities, **in shadow**
   — signals only enrich the dashboard and the model's prompt. Only after a bake does any
   behavioral signal feed the action-bar corroboration that can promote a cut.
