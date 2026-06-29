# protector

**protector finds the attack paths an internet-facing attacker could actually walk
to something sensitive in your Kubernetes cluster, checks which ones are genuinely
exploitable, and breaks them with a small, reversible network cut — without taking
the workload down.**

It works in two independent layers:

- **The webhook (the floor).** A validating admission webhook that rejects Pods at
  creation time unless their images are signed and they're injected into the service
  mesh. It makes *zero* calls to the cluster API — it only inspects the request in
  front of it — so it's small, fast, and safe to run everywhere. This is the
  always-on baseline.
- **The engine (the product).** A background loop that *reads* the live cluster,
  builds a graph of how everything connects (who can reach whom, who can read which
  secret, who can escalate), and continuously asks: *if an attacker got into an
  internet-facing pod, what could they actually get to?* For each real path it finds,
  it asks a local LLM whether the path is genuinely exploitable, and — when it is —
  proposes (or, once you opt in, applies) a minimal fix.

## How the engine decides

The hard part of cluster security isn't *listing* problems — any scanner floods you
with thousands. It's telling the handful that matter from the noise. protector splits
that into two jobs:

1. **Deterministic proof winnows.** A graph walk enumerates only the paths that
   actually connect the internet to something an attacker wants (a secret, the host
   node, a privileged capability). Reachability is proven, not guessed — and merely
   *reaching* a workload isn't *controlling* it, so contrived chains are pruned.
2. **A local model decides.** For each surviving path, an LLM makes the call a human
   analyst would: is this genuinely exploitable end-to-end, or is it legitimate for
   this workload (an app reading its own secret)? The model is the judge of
   exploitability; it never runs an exploit. ([ADR-0013](docs/adr/0013-proof-winnows-model-decides.md).)

Only when both agree — a proven path *and* an affirmative judgement (or a live
runtime alert corroborating an attack in progress) — does the engine move to act. And
the only action it takes is **additive, reversible, and self-reverting**: a network
deny that quarantines the source. When the underlying path stops being provable
(someone fixed the real misconfiguration), the engine removes its own deny.

**Shadow-first:** out of the box the engine only *detects and proposes* — it never
touches the cluster. You enable enforcement one reversible class at a time, after
watching its proposals in shadow.

## What it looks for (ATT&CK)

Every finding is an adversary **outcome** reachable from an internet-facing front
door, named in [MITRE ATT&CK](https://attack.mitre.org/) terms:

- **Credential Access** (T1552) — reaching a Secret, by mount (`can-read`) or RBAC
  (`can-do/get/secrets`).
- **Lateral Movement** (TA0008) — network hops (NetworkPolicy *and* mesh authz),
  gated by compromise: reaching a workload isn't controlling it ([ADR-0002](docs/adr/0002-change-driven-ir-loop.md)).
- **Privilege Escalation** — Escape to Host (T1611) and RBAC self-escalation (T1098.006).
- **Execution** — Deploy Container (T1610), Container Admin Command (T1609).
- **Persistence** — Container Orchestration Job (T1053.007).
- **Impact** — Data Destruction (T1485).
- **Collection** — Data from Information Repositories (T1213) — reaching a **data store**
  (a workload mounting persistent storage: a database, cache, object store) so its data
  could be mined.
- **Exfiltration** (T1041) — a compromised workload with an internet-egress channel
  (declared, or an open `0.0.0.0/0` egress allow) can ship accessed data out.

Only *breach-relevant* chains — those starting from an internet-facing entry — are
findings. Purely internal access is kept as assume-breach context, not surfaced as a
finding.

## Engine output state

The engine maintains a read-only, in-memory output state — the findings snapshot (proven
chains + the model's per-entry verdicts), the judgement record, the reversion log, the
behavioral-bake snapshot, and the would-have-acted report and readiness aggregations it
mirrors to OTLP each pass. This state is **derived from** the engine's findings and decisions
and never gates them (shadow-by-default). A presentation layer over it is being redesigned.

## Run it

```sh
cargo nextest run            # unit tests — the analysis logic (graph / proof / action bar / ledger)
cargo clippy --all-targets
scripts/e2e.sh               # full engine e2e on a throwaway k3d cluster
                             # (needs docker, k3d, kubectl, jq, curl)
```

`scripts/e2e.sh` stands up a disposable k3d cluster (k3s — the same flannel +
kube-router CNI a typical k3s install ships), drives a real
`exposed → reaches → secret` chain, and exercises both action paths: the
runtime-corroborated cut, and the **proof-winnows→model-decides** foothold (a critical
CVE like log4shell is *propose-only* on mere presence; the model's `exploitable`
verdict is what cuts). It asserts the engine quarantines the workload and then
**self-reverts**. The model phase points at a local LLM via `PROTECTOR_E2E_MODEL`
(skipped if none is reachable); a gated competence probe lives in
`cargo test … --ignored` (see `engine::adjudicate`).

## Deploy

protector ships as a container image; deploy it however you run workloads (a Helm
chart, plain manifests, your GitOps tool of choice). It needs:

- a serving certificate for the webhook (e.g. from cert-manager),
- a ServiceAccount with cluster **read** (pods, services, secret *metadata*,
  NetworkPolicies, RBAC) — plus, only in hard mode, **write** on the one
  NetworkPolicy object it manages.

**Shadow-first:** with no action class enabled (`PROTECTOR_ENGINE_ENABLE` empty) the
engine only detects and proposes. Turn on enforcement one reversible class at a time.
The only live action today is the additive, self-reverting network deny
(`networkpolicy` on flannel/kube-router, `adminnetworkpolicy` on ANP-capable CNIs
like Cilium/Calico).

## Configuration (env)

### Engine

| Var | Default | Meaning |
|-----|---------|---------|
| `PROTECTOR_ENGINE` | `on` | `off`/`0`/`false` runs the bare webhook floor, no engine |
| `PROTECTOR_ENGINE_ENABLE` | — | comma list of auto-applied action classes (`network`,`rbac`,`mount`,`identity`); empty = propose-only. Only `network` is live-actuatable; `escape` is never enableable. Add `judgement` to let the **model decide** a proven foothold (internet-exposed + KEV/critical CVE, e.g. log4shell): a cut requires the model's affirmative `exploitable` verdict — CVE *presence* alone is propose-only ([ADR-0013](docs/adr/0013-proof-winnows-model-decides.md); needs `network` to cut) |
| `PROTECTOR_ENGINE_ACTUATOR` | `dryrun` | live-cut mechanism: `networkpolicy` (flannel/kube-router, e.g. k3s/k3d), `adminnetworkpolicy` (Cilium/Calico), `dryrun`. Unknown/empty fails safe to dry-run |
| `PROTECTOR_ENGINE_JOURNAL_PATH` | — | decision-journal file on a mounted volume (PVC/hostPath). Appends each pass's breach verdicts + ledger apply/revert deltas (with revert reason) as JSON lines, size-rotated; replayed on boot so the findings snapshot, the judgement record, and the reversion log populate immediately after a restart. Unset/unwritable = in-memory only, no crash ([ADR-0015](docs/adr/0015-advisory-evidence-egress.md) mounted-volume posture) |
| `PROTECTOR_FALCO_ADDR` | — | Falco runtime-evidence ingest addr (Falco posts alerts here, e.g. via falcosidekick); unset = no runtime feed |
| `PROTECTOR_KEV_FILE` | — | CISA KEV catalogue path (JSON or newline CVE list); unset = no exploit intel |
| `PROTECTOR_ENGINE_MODEL` | — | OpenAI-compatible chat-completions endpoint for the adjudicator (e.g. a local Ollama); unset = deterministic only, no adjudication |
| `PROTECTOR_ENGINE_MODEL_NAME` | `qwen2.5:3b` | model name for the above |
| `PROTECTOR_ENGINE_MODEL_TIMEOUT_SECS` | `30` | per-call model timeout; raise it for slow CPU-only inference (a 3B model on CPU can need ~90–120s, larger models more). The watch loop does not stall while it waits |
| `PROTECTOR_ENGINE_HYPOTHESIS` | — | `model` opts the model *hypothesis* source in (off by default — proof already enumerates every chain at small scale, and the whole-graph prompt is slow on CPU). The model is still used for adjudication regardless |

### Webhook

| Var | Default | Meaning |
|-----|---------|---------|
| `PROTECTOR_ADDR` | `0.0.0.0:8443` | listen address |
| `PROTECTOR_TLS_CERT` / `PROTECTOR_TLS_KEY` | `/etc/protector/tls/tls.{crt,key}` | serving cert/key |
| `PROTECTOR_IDENTITY_REGEXP` | — | trusted keyless signing identity — set to your org (e.g. `^https://github\.com/your-org/`). Required once `PROTECTOR_GATED_PREFIXES` is set |
| `PROTECTOR_OIDC_ISSUER` | `https://token.actions.githubusercontent.com` | expected OIDC issuer |
| `PROTECTOR_GATED_PREFIXES` | — | image-ref prefixes that must be signed (e.g. `ghcr.io/your-org/`); **empty = gating off**, no image is signature-checked |
| `PROTECTOR_ENFORCE_NAMESPACES` / `PROTECTOR_ENFORCE_LABELS` | — | where signature enforcement *denies* vs only audits |
| `PROTECTOR_MESH_ENFORCE_NAMESPACES` / `PROTECTOR_MESH_ENFORCE_LABELS` | — | where mesh enforcement *denies* (never your CI runner namespace) |
| `PROTECTOR_REGISTRY_USERNAME` / `PROTECTOR_REGISTRY_PASSWORD` | — | registry auth for verifying signatures of private gated images |
| `PROTECTOR_REGISTRY_AUTH_FILE` | — | path to a mounted dockerconfigjson (your pull secret); its registry creds are reused for signature verification when username/password aren't set. Without registry auth, private packages 401 |
| `RUST_LOG` | — | tracing filter (e.g. `protector=info`) |

> Signature gating ships **off**: with `PROTECTOR_GATED_PREFIXES` empty, no image is
> checked. Set it to your registry/org *and* `PROTECTOR_IDENTITY_REGEXP` to your
> trusted signer to turn it on — protector refuses to start if prefixes are set
> without an identity (gating without a trusted signer would accept any signature).

### Endpoints

`POST /validate` (webhook `:8443`) · `GET /healthz` `/readyz` `/metrics` ·
`POST /` (Falco ingest `:9999`)

## Honest bounds

- **Small to mid-size clusters by design** — multi-hop proving is tractable because
  the graph is small; it is not built to scale to thousands of workloads.
- **Preconditions proven, exploitability judged, never exploited** — deterministic
  proof establishes the *preconditions* (reachable, privileged, CVE present,
  internet-facing); the model makes the *exploitability* call on that proven
  candidate; the engine never *runs* an exploit. Only the conjunction of a proven path
  and an affirmative judgement moves privilege ([ADR-0013](docs/adr/0013-proof-winnows-model-decides.md)).

## Design & decisions

The narrative is in [`docs/VISION.md`](docs/VISION.md); every consequential decision
is an ADR in [`docs/adr/`](docs/adr/) — the change-driven loop (0002), capability
ports (0003), the graph (0004), ATT&CK objectives (0005), live cuts (0007/0010), the
asymmetric action bar (0009), and the model's role — **proof winnows, the model
decides** (0013), via positive judgement (0011).
