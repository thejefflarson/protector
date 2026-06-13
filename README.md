# protector

An **incident prevention, response, and remediation engine** for Kubernetes.

protector watches the cluster's *observed* state, continuously reasons about how
the facts already present chain into a real attack, **proves** the dangerous
chains deterministically, and — when a chain is proven and live — proposes (or,
once enabled, applies) a minimal, reversible cut that breaks it, while the
workload keeps running.

It has two layers:

- **The engine** (the product). An asynchronous, out-of-band loop with cluster
  access. It builds a security graph, proves ATT&CK-tagged attack chains, and
  manages mitigations as self-retiring debt. This is where the value is.
- **The webhook** (the floor). A synchronous validating admission webhook with
  *no* cluster access. It enforces a few structural invariants (image signing,
  mesh injection) at admission time — the boring, reliable guardrails the engine
  builds on. It is intentionally small and frozen; all ambition lives in the
  engine.

See [`docs/VISION.md`](docs/VISION.md) for the narrative and
[`docs/adr/`](docs/adr/) for the decisions behind every part of this.

## The engine

On every change to observed cluster state — a deploy, a new CVE disclosure, an
RBAC edit, an ephemeral CI runner, a Falco alert — the engine answers five
questions:

1. **How does the threat model change?** A deterministic diff of the cluster
   security graph emits a *threat delta* — the capabilities a change added or
   removed.
2. **Are there new, provable, real attack chains?** The proof layer walks the
   graph over **proof-grade edges only** and reports chains from an entry to an
   objective, each tagged with the MITRE ATT&CK technique it realizes, with the
   single edge that severs it (the minimal cut).
3. **Is production alive / degraded / halted, and can we trust the levers?** A
   health model gates and verifies every action: predict the blast radius, act,
   measure against the prediction, and revert if a protected workload regressed.
4. **What config change prevents this going forward?** A proposed durable fix
   (a GitOps PR) and, in hard mode, an immediate additive cut.
5. **As posture improves, what mitigating controls roll back?** A ledger retires
   any control whose justifying chain is no longer proven — the active control
   set is exactly the set of currently-proven chains.

A read-only **dashboard** (`/` HTML, `/findings` JSON) surfaces every proven
chain and its disposition — most usefully the latent-foothold proposals a human
acts on.

### The pipeline

```
observe (watch + Falco)
  → build the security graph
  → diff           (Q1: threat delta)
  → assess health  (Q3: alive / degraded / halted)
  → prove          (Q2: ATT&CK chains + minimal cuts + the action bar)
      └─ a model may *propose* candidate chains; only deterministic proof confirms them
  → reconcile mitigations (Q4 propose / Q5 retire) as self-retiring debt
  → decide → apply (additive, reversible) → verify → self-revert
```

The graph's nodes are workloads, identities, secrets, network endpoints, images,
hosts, and dangerous capabilities; its edges are *reaches* (network), *can-do*
(RBAC), *can-read* (data), *escapes-to* (container escape), and the structural
links between them. Each edge carries provenance and a **grade**: `Proof`
(deterministic — eligible to move privilege) or `Hypothesis` (a model's guess —
may inform a proposal, never an action).

### The action bar (asymmetric)

Nothing privileged happens on a model's say-so, and the bar is deliberately
**asymmetric** (ADR-0009): the evidence required to *automatically act* is higher
than the evidence required to *propose to a human*. Two cases, and **either is
enough on its own** — a Falco event and a KEV are independent inputs, not an AND:

- **Live → auto-eligible.** A proven privileged chain whose entry shows a
  **runtime signal right now** (a Falco event) clears the bar by itself — live
  corroboration is sufficient, a CVE foothold is *not* required. Subject to the
  adjudicator's veto, no live collateral, and the action class being enabled, it
  is auto-applied.
- **Latent foothold → propose only.** A proven chain whose entry is a real
  foothold — internet-exposed **and** running an **exploited-in-wild or
  critical-severity** CVE (think log4shell) — but with *no* live activity is the
  weaker case: surfaced on the dashboard as a proposal, never auto-cut.

| Signal | Source |
|--------|--------|
| internet-exposed entry | Services (LoadBalancer/NodePort) → `Exposure::Internet` |
| foothold | a KEV-listed **or** critical-severity CVE on the entry's image (the ExploitIntel + Vulnerability ports) |
| privileged path to an objective | the proof-grade graph walk, tagged with its ATT&CK technique |
| happening now | a Falco runtime signal on the entry workload |

So a foothold makes a chain *latent* (propose); a live runtime signal makes it
*auto-eligible*.

### Where the model fits

A model never decides to act. It has two safe roles (ADR-0008):

- **Adjudicate** (its primary job): when a chain meets the full bar, the model
  judges whether it's *contextually real* — is the CVE actually exploitable in
  *this* deployment, is that Falco shell an attacker or a benign exec? Its verdict
  is **one-way**: it can only *veto* (downgrade an eligible auto-cut to a human
  proposal), never authorize. A wrong model causes at worst a missed auto-action,
  never a bad cut. It defaults to skeptic, and it never *exercises* an exploit —
  we prove preconditions, not exploitation.
- **Propose** (secondary): suggest candidate chains, which the deterministic gate
  accepts only if every link is a real proof-grade edge.

Both run local-first (an in-cluster Ollama by default) so the graph never leaves
the cluster; a frontier model is the escalation for high-stakes, ambiguous chains.

### Easy mode (default) and hard mode

The engine ships **shadow-first**. By default nothing is enabled and the actuator
is dry-run: every finding is reported and every mitigation is a *proposal for a
human* — **nothing touches the cluster.**

Hard mode is opt-in, one reversible action class at a time, via
`PROTECTOR_ENGINE_ENABLE`. Even then, a cut is auto-applied only when it is
**additive** (a new object, so it doesn't fight GitOps), reversible, runtime-
corroborated, adjudicator-confirmed, and has no live collateral — no *other*
alive workload loses reachability (the cut's own endpoints are its intended
subjects). In practice that is **network denials only**, rendered by whichever
mechanism the CNI supports (`PROTECTOR_ENGINE_ACTUATOR`):

- `adminnetworkpolicy` — a surgical, pod-granular additive `AdminNetworkPolicy`
  Deny rule (ADR-0007), on a CNI that implements ANP (Cilium/Calico).
- `networkpolicy` — a default-deny `NetworkPolicy` that quarantines the
  compromised *source* workload, for flannel/kube-router — **this cluster** —
  where ANP isn't available (ADR-0010).

RBAC / mount / escape remediations are subtractive and so are durable-fix-PR
territory, never live actuation. Container-escape removal is never auto-enabled.

Applied cuts **self-revert**: if a protected workload regresses (health
divergence) or the justifying chain stops being proven (posture improved), the
engine deletes the object it created.

### Capability ports (swap any tool)

The engine depends on *what a tool answers*, not which tool. Each port has a
default adapter and is swappable: Observer (Kubernetes API watch), Reachability
(NetworkPolicy), Privilege (RBAC), Vulnerability (trivy-operator), ExploitIntel
(CISA KEV), RuntimeEvidence (Falco), Health (pod status; SLO source pluggable),
Actuator (AdminNetworkPolicy or default-deny NetworkPolicy), and the hypothesis
source (a local Ollama model by default). Evidence is pluggable; the rules — the
chain grammar and the action bar — are not.

## The webhook (the floor)

A small, focused set of Rust policies behind a registry — not a generic rules
engine (no Kyverno/OPA re-implementation).

| Policy | What it does | Default |
|--------|--------------|---------|
| `image-signature` | Rejects Pods whose **first-party** images (`ghcr.io/thejefflarson/…`) aren't keyless cosign-signed by our GitHub Actions identity, verified in-process with [sigstore-rs](https://github.com/sigstore/sigstore-rs). | audit (allow + log) |
| `mesh-injection` | Rejects Pods that aren't Linkerd-meshed, outside an exempt namespace set (which **must** include the unmeshed runner namespace and control plane). | audit (allow + log) |

The webhook terminates its own TLS (the kube-apiserver caller isn't in the mesh,
and Kubernetes requires webhooks to be HTTPS), keeps **zero cluster access**, and
ships fail-safe (`failurePolicy: Ignore`, empty enforce allowlists = audit
everywhere). Enforcement is opt-in per policy, one namespace/label at a time.

## Configuration (env)

### Engine

| Var | Default | Meaning |
|-----|---------|---------|
| `PROTECTOR_ENGINE` | `on` | set `off`/`0`/`false` to run the bare webhook floor with no engine |
| `PROTECTOR_ENGINE_ENABLE` | — | comma list of auto-applied action classes (`network`,`rbac`,`mount`,`identity`); empty = propose-only. Only `network` is live-actuatable today; `escape` is never enableable |
| `PROTECTOR_ENGINE_ACTUATOR` | `dryrun` | live-cut mechanism when a class is enabled: `networkpolicy` (flannel/kube-router — this cluster), `adminnetworkpolicy` (ANP-capable CNI), or `dryrun` (log only) |
| `PROTECTOR_DASHBOARD_ADDR` | — | listen address for the read-only findings dashboard (`/` HTML, `/findings` JSON); unset = no dashboard |
| `PROTECTOR_FALCO_ADDR` | — | listen address for the Falco/falcosidekick ingest endpoint (the runtime-corroboration feed); unset = no runtime feed |
| `PROTECTOR_KEV_FILE` | — | path to a CISA KEV catalogue (JSON or newline CVE list, e.g. a synced ConfigMap); unset = no exploit intel |
| `PROTECTOR_ENGINE_MODEL` | — | OpenAI-compatible chat endpoint for the adjudicator + hypothesis source (e.g. a local Ollama); unset = deterministic enumerator only, no adjudication |
| `PROTECTOR_ENGINE_MODEL_NAME` | `qwen2.5:3b` | model name for the above |

The engine needs cluster **read** access (pods, services, secrets *metadata*,
NetworkPolicies, RBAC) plus, in hard mode, **write** to its chosen deny object
(NetworkPolicy or AdminNetworkPolicy). The webhook needs none of this — the
engine uses its own kube client.

### Webhook

| Var | Default | Meaning |
|-----|---------|---------|
| `PROTECTOR_ADDR` | `0.0.0.0:8443` | listen address |
| `PROTECTOR_TLS_CERT` / `PROTECTOR_TLS_KEY` | `/etc/protector/tls/tls.{crt,key}` | serving cert/key (cert-manager) |
| `PROTECTOR_IDENTITY_REGEXP` | `^https://github\.com/thejefflarson/` | trusted signing identity |
| `PROTECTOR_OIDC_ISSUER` | `https://token.actions.githubusercontent.com` | expected OIDC issuer |
| `PROTECTOR_GATED_PREFIXES` | `ghcr.io/thejefflarson/` | image prefixes to enforce signing on |
| `PROTECTOR_ENFORCE_NAMESPACES` / `PROTECTOR_ENFORCE_LABELS` | — | where signature enforcement is **denied** vs audited |
| `PROTECTOR_MESH_ENFORCE_NAMESPACES` / `PROTECTOR_MESH_ENFORCE_LABELS` | — | where mesh enforcement is **denied** (never the runner ns) |
| `PROTECTOR_REGISTRY_USERNAME` / `PROTECTOR_REGISTRY_PASSWORD` | — | registry auth for private gated images |
| `RUST_LOG` | — | tracing filter (e.g. `protector=info`) |

## Endpoints

- `POST /validate` — the AdmissionReview endpoint (webhook, `:8443`)
- `GET /healthz`, `GET /readyz` — probes
- `GET /metrics` — Prometheus exposition
- `GET /`, `GET /findings` — read-only findings dashboard (engine, `:8080`)
- `POST /` — Falco/falcosidekick runtime-evidence ingest (engine, `:9999`)

## Scope and honesty

- **Small clusters.** Multi-hop chain proving is tractable because the cluster is
  small and deterministic pre-filters keep the search space tiny. This does not
  scale to thousands of workloads, by design.
- **Preconditions, not exploitation.** The engine proves a path is *reachable,
  exploitable-in-wild, privileged, and runtime-corroborated* — not that RCE
  occurred. The action is justified by severing a proven privileged path, a
  deliberately-named bound.
- **Tested logic + an end-to-end test.** The analysis — graph, proof, ATT&CK
  objectives, the action bar, mitigation ledger, decision/self-revert logic,
  blast-radius prediction, and every normalizer (trivy/KEV/Falco/ANP) — is
  covered by unit tests. The cluster- and model-facing I/O (watch streams, the
  kube actuator's apply/delete, the Falco HTTP receiver, the model call) is
  exercised by an automated end-to-end test, [`scripts/e2e.sh`](scripts/e2e.sh),
  which stands up a throwaway k3d cluster (k3s — the **same** flannel +
  kube-router CNI as production), drives a real exposed→reaches→secret chain,
  corroborates it through the Falco ingest, and asserts the engine quarantines
  the workload and then **self-reverts** once the chain stops being proven.

## Develop

```sh
cargo nextest run            # unit tests
cargo clippy --all-targets
scripts/e2e.sh               # full engine e2e on a throwaway k3d cluster
                             # (needs docker, k3d, kubectl, helm, jq)
```
