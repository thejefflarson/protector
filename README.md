# protector

An **incident prevention, response, and remediation engine** for Kubernetes. It
watches the cluster's *observed* state, **proves** how the facts already present
chain into a real ATT&CK attack, and — when a chain is proven and live — proposes
(or, once enabled, auto-applies) a minimal, reversible cut that breaks it while the
workload keeps running.

Two layers:

- **The engine** (the product) — an async, out-of-band loop with cluster read
  access (and, in hard mode, narrow write). Builds a security graph, proves
  attack chains, and manages mitigations as self-retiring debt.
- **The webhook** (the floor) — a synchronous validating admission webhook with
  *zero* cluster access, enforcing image signing + mesh injection at admission. Small and frozen.

On every observed change the engine answers five questions: (1) how the threat
model changed, (2) which new attack chains are provable and their minimal cut, (3)
whether production is alive/degraded/halted and whether the levers can be trusted,
(4) the durable config fix, (5) which compensating controls to retire as posture
improves. The **why** behind each part lives in the ADRs (below); this README is
how to run it.

## Run it

```sh
cargo nextest run            # unit tests (the analysis logic — graph/proof/action bar/ledger)
cargo clippy --all-targets
scripts/e2e.sh               # full engine e2e on a throwaway k3d cluster
                             # (needs docker, k3d, kubectl, helm, jq)
```

`scripts/e2e.sh` stands up k3d (k3s — the same flannel + kube-router CNI as prod),
drives a real exposed→reaches→secret chain, exercises both the runtime-corroborated
and deterministic-foothold (log4j) action paths, and asserts the engine quarantines the workload and
then **self-reverts**. A gated real-model check lives in `cargo test … --ignored`
(see `engine::adjudicate` — point `PROTECTOR_E2E_MODEL` at an Ollama).

## Deploy

Shipped via the Helm chart in the cluster repo (`charts/protector`), Argo-synced.
**Shadow-first:** with no action class enabled the engine only detects + proposes —
it never touches the cluster. Enable hard mode one reversible class at a time
(`PROTECTOR_ENGINE_ENABLE`); the only live action today is an additive, reversible,
self-reverting network deny (`networkpolicy` on flannel, `adminnetworkpolicy` on
ANP-capable CNIs). A read-only dashboard (`/` HTML, `/findings` JSON) surfaces every
chain and its disposition.

## Configuration (env)

### Engine

| Var | Default | Meaning |
|-----|---------|---------|
| `PROTECTOR_ENGINE` | `on` | `off`/`0`/`false` runs the bare webhook floor, no engine |
| `PROTECTOR_ENGINE_ENABLE` | — | comma list of auto-applied action classes (`network`,`rbac`,`mount`,`identity`); empty = propose-only. Only `network` is live-actuatable; `escape` is never enableable. Add `judgement` to let a proven foothold (internet-exposed + KEV/critical CVE, e.g. log4shell) auto-promote to a cut, with the model as an optional veto (ADR-0011; needs `network` to cut) |
| `PROTECTOR_ENGINE_ACTUATOR` | `dryrun` | live-cut mechanism: `networkpolicy` (flannel — this cluster), `adminnetworkpolicy` (Cilium/Calico), `dryrun`. Unknown/empty fails safe to dry-run |
| `PROTECTOR_DASHBOARD_ADDR` | — | findings dashboard listen addr; unset = off |
| `PROTECTOR_FALCO_ADDR` | — | Falco/falcosidekick runtime-evidence ingest addr; unset = no runtime feed |
| `PROTECTOR_KEV_FILE` | — | CISA KEV catalogue path (JSON or newline CVE list); unset = no exploit intel |
| `PROTECTOR_ENGINE_MODEL` | — | OpenAI-compatible endpoint for the adjudicator/hypothesis source (a local Ollama); unset = deterministic only, no adjudication |
| `PROTECTOR_ENGINE_MODEL_NAME` | `qwen2.5:3b` | model name for the above |

The engine uses its own ServiceAccount: cluster **read** (pods, services, secret
*metadata*, NetworkPolicies, RBAC) plus, in hard mode, **write** on its deny object.

### Webhook

| Var | Default | Meaning |
|-----|---------|---------|
| `PROTECTOR_ADDR` | `0.0.0.0:8443` | listen address |
| `PROTECTOR_TLS_CERT` / `PROTECTOR_TLS_KEY` | `/etc/protector/tls/tls.{crt,key}` | serving cert/key (cert-manager) |
| `PROTECTOR_IDENTITY_REGEXP` | `^https://github\.com/thejefflarson/` | trusted signing identity |
| `PROTECTOR_OIDC_ISSUER` | `https://token.actions.githubusercontent.com` | expected OIDC issuer |
| `PROTECTOR_GATED_PREFIXES` | `ghcr.io/thejefflarson/` | image prefixes to enforce signing on |
| `PROTECTOR_ENFORCE_NAMESPACES` / `PROTECTOR_ENFORCE_LABELS` | — | where signature enforcement *denies* vs audits |
| `PROTECTOR_MESH_ENFORCE_NAMESPACES` / `PROTECTOR_MESH_ENFORCE_LABELS` | — | where mesh enforcement *denies* (never the runner ns) |
| `PROTECTOR_REGISTRY_USERNAME` / `PROTECTOR_REGISTRY_PASSWORD` | — | registry auth for private gated images |
| `RUST_LOG` | — | tracing filter (e.g. `protector=info`) |

### Endpoints

`POST /validate` (webhook `:8443`) · `GET /healthz` `/readyz` `/metrics` ·
`GET /` `/findings` (dashboard `:8080`) · `POST /` (Falco ingest `:9999`)

## Honest bounds

- **Small clusters by design** — multi-hop proving is tractable because the cluster
  is small; it doesn't scale to thousands of workloads.
- **Preconditions, not exploitation** — the engine proves a path is reachable,
  exploitable-in-wild, privileged, and corroborated; it never *runs* an exploit. A
  cut is justified by severing a proven privileged path, a deliberately-named bound.

## Design & decisions

The narrative is in [`docs/VISION.md`](docs/VISION.md); every consequential decision
is an ADR in [`docs/adr/`](docs/adr/) — the change-driven loop (0002), capability
ports (0003), the graph (0004), ATT&CK objectives (0005), live cuts (0007/0010), the
model's role as veto + positive judgement (0008/0011), and the asymmetric action bar
(0009).
