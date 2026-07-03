# protector Helm chart

Install [protector](../../README.md) — the admission webhook (first-party
image-signature verification + mesh-injection policy) and the async mitigation
engine (proves ATT&CK attack chains over observed cluster state and proposes, or
once armed auto-applies, reversible minimal cuts) — with one `helm install` instead
of hand-assembling RBAC, the webhook serving cert, the journal PVC, the agent
DaemonSet, and ~30 env vars.

## Safe by default

Out of the box the chart is in its most conservative posture for **acting on** the
cluster. **Every step toward acting on the cluster is a single, documented value change
— nothing that writes to or blocks your workloads is default-on.**

One thing *is* default-on for egress: the **feed-fetcher sidecar** (`feedSync.enabled:
true`). It is the single component the chart grants network egress to, and it only
GETs **public, read-only** exploitation-intel feeds (CISA KEV + FIRST.org EPSS) into a
shared volume the engine reads — it never
reads or transmits any cluster data, and the **engine itself stays zero-egress**
(ADR-0015). For a fully air-gapped / zero-egress install, set `feedSync.enabled=false`
(see [Air-gapped / zero-egress](#air-gapped--zero-egress)).

| Property            | Default                                | Why                                                              |
| ------------------- | -------------------------------------- | --------------------------------------------------------------- |
| Operating posture   | **`mode: audit`** (`enforceScope` empty) | Everything observes & proposes; nothing blocks or acts (ADR-0021). Signature + mesh audit-only, engine shadow. Flip `mode: enforce` + `enforceScope` to arm all three surfaces at once. |
| Webhook scope       | **audit every namespace** (`webhook.excludeNamespaces: []`) | The fail-open audit webhook observes Pod creates cluster-wide, including kube-system / cert-manager / linkerd / argocd / protector. List names in `excludeNamespaces` to opt some out. |
| Webhook failure     | audit `failurePolicy: Ignore`; enforcing webhook `Fail` but **scoped to nothing** | The audit webhook never blocks API writes (so auditing every namespace is safe even for kube-system); the fail-closed enforcing webhook matches no namespace until `mode: enforce` + `enforceScope` opt one in. |
| Ingest auth         | **on** (`ingestAuth.enabled: true`)    | The :9999 runtime ingest requires a bearer token (mounted file only); engine + agent share a chart-provisioned Secret. |
| Engine              | **shadow** (`mode: audit`)             | Detects + proposes; the engine is dry-run until `mode: enforce`. |
| Actuator            | `networkpolicy`                        | The CNI mechanism used *if* it actuates (only under `mode: enforce`); inert in audit. |
| Engine egress       | **none** (zero-egress, ADR-0015)       | The engine makes no breach-notify call, no OTLP export, no live feed fetch — it only reads mounted feed files; the security graph never leaves the cluster. |
| Feed-fetcher egress | **on** (`feedSync.enabled: true`)      | The ONE component with egress: a co-located sidecar that GETs public, read-only exploitation-intel feeds (CISA KEV + FIRST.org EPSS) into a shared volume the engine reads. It never reads or transmits cluster data. Set `feedSync.enabled=false` for a fully air-gapped install. |
| Model               | **off** (`engine.model.endpoint` empty) | Engine runs the deterministic enumerator only; no model required. |
| eBPF agent          | **off** (`agent.enabled: false`)       | Needs the agent image + probes load-tested on your kernel.      |
| RBAC                | read-only                              | No write grants unless `mode: enforce` (derived — arms the cut and its RBAC together). |

## Prerequisites

- Kubernetes 1.25+.
- [cert-manager](https://cert-manager.io/) (with cainjector) — the chart provisions a
  self-signed `Issuer` + `Certificate` for the webhook's serving cert and lets
  cainjector fill the webhook `caBundle`. Set `cert.create=false` to manage the
  serving Secret (`<release>-tls`) and `caBundle` yourself instead.

## Install

```sh
helm install protector ./charts/protector --namespace protector --create-namespace
```

Set your own first-party signing identity (otherwise the defaults gate the protector
project's own `ghcr.io/thejefflarson/` images):

```sh
helm install protector ./charts/protector -n protector --create-namespace \
  --set signature.gatedPrefixes="ghcr.io/your-org/" \
  --set 'signature.identityRegexp=^https://github\.com/your-org/'
```

Then **watch the audit log** before arming anything:

```sh
kubectl -n protector logs -l app.kubernetes.io/name=protector -f
```

The engine's proposals, adjudications, and applied/reverted cuts are in those logs; its
would-have-acted and readiness aggregations are mirrored to OTLP each pass.

## Opt-ins (each is one value change)

Nothing below that **acts on or blocks** your workloads is enabled by default (the one
default-on item is the read-only **feed-fetcher** egress, covered below). Arm in this order
and review the decision journal / audit log at each step.

### Enforce: one scope arms all three surfaces (ADR-0021)

Enforcement is **two settings**: `mode` + `enforceScope`. Flipping `mode: enforce`
arms all three enforcement surfaces together — signature-webhook deny, mesh-webhook
deny, and the engine's reversible network cut — each confined to *exactly*
`enforceScope`:

```sh
helm upgrade protector ./charts/protector --namespace protector --reuse-values \
  --set mode=enforce \
  --set 'enforceScope.namespaces={payments,ingress}'
```

Now in `payments`/`ingress`: unsigned/regressed gated images and unmeshed Pods are
**denied**, and the engine applies its reversible cut on a corroborated attack path —
everywhere else stays audit. Pod labels behave like namespaces (a Pod carrying one is
enforced in any namespace):

```sh
--set 'enforceScope.labels.tier=prod'
```

There is **no enforce-everywhere wildcard**: `mode: enforce` with an empty
`enforceScope` is refused (by both helm and the engine at startup).

**The fail-closed webhook and the actuation RBAC are derived from the same
`enforceScope`** — they can no longer drift from what the gates enforce. By default the
audit webhook **fails open** (`failurePolicy: Ignore`, so a protector outage never
blocks Pod creation); the derived `pods-enforce.protector.dev` webhook
(`failurePolicy: Fail`) is scoped to `enforceScope` (namespaces → `namespaceSelector`,
labels → `objectSelector`) so that in scope, if protector is down or a Pod spec is
oversized, Pod **CREATE is blocked** rather than admitting a possibly-unsigned image.
**Tradeoff:** while protector is unavailable, new Pods (rollouts, HPA scale-ups) cannot
be created in the enforced scope until it recovers. Bake a scope in `mode: audit`
(watch the would-deny findings) before flipping.

### Ingest authentication (on by default) — rollout ordering

The engine's runtime/behavioral ingest (the `:9999` falco-ingest port) accepts
observations that can make a proven attack chain *actionable*. App-layer
authentication is **on by default** (`ingestAuth.enabled: true`): the chart
provisions a Secret with a random bearer token, the engine **requires** it, and the
agent **presents** it. (This is authentication — *who may post*. The cluster's
Linkerd mesh authorization — *which identities may connect* — is layered separately
in the cluster repo; the two are complementary.)

Because a token is set by default, a fresh install is authenticated end-to-end. If
you are introducing the token onto a **running** deployment, roll it out in this
order so the agent is never rejected mid-upgrade:

1. **Engine accepts token-or-none.** The engine only *requires* a token when one is
   configured; with none it logs a startup warning and accepts unauthenticated posts.
   So you can deploy a build that *would* enforce without yet setting the Secret.
2. **Deploy the Secret + agent.** Provision the ingest Secret and roll the agent so it
   presents the token (`ingestAuth.enabled: true`, the default — both engine and agent
   mount the same Secret).
3. **Token enforced.** With the Secret mounted, the engine now rejects any post lacking
   the correct bearer with `401`, before deserialization.

Bring your own Secret (e.g. for rotation) with `ingestAuth.existingSecret=<name>` (it
must have a `token` key). To run the ingest unauthenticated, set
`ingestAuth.enabled=false` — the engine then logs a warning that the port is open.

### Enable the local-first model (recommended before arming the engine)

Point at an **in-cluster** OpenAI-compatible endpoint so the cluster graph never
leaves the cluster. The adjudicator's veto is load-bearing once a class is armed.

```sh
--set engine.model.endpoint="http://ollama.smarts.svc.cluster.local:11434/v1/chat/completions" \
--set engine.model.name="qwen2.5:3b-instruct"
```

### Exploitation-intel feeds (KEV + EPSS) — feed-fetcher sidecar (on by default)

The engine reasons over two exploitation-intel feeds: the CISA KEV catalogue
(actively-exploited-**now** CVEs) and the FIRST.org EPSS scores (the **predictive** per-CVE
probability of exploitation in the next 30 days). Together with Trivy's CVSS score (static
severity) these are the **three exploitation axes** the breach model weighs (ADR-0016).
**The engine never fetches either over the network** — it only reads them from files
(ADR-0015), so the engine stays zero-egress.

By default the chart keeps those files fresh for you with a co-located **feed-fetcher
sidecar** (`feedSync.enabled: true`) on the engine pod: a [native
sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/) (an
`initContainer` with `restartPolicy: Always`) that downloads the **full** public CISA KEV
feed and the FIRST.org EPSS feed into a shared `emptyDir`, then re-fetches on
`feedSync.interval`. The engine container mounts the **same** volume read-only and reads
`/var/lib/protector/feeds/kev.json` and `/var/lib/protector/feeds/epss.csv` — both wired
automatically, no further configuration. The engine degrades gracefully if either file is
missing or empty (the first-boot race before the sidecar's first fetch).

**Two feeds, not the retired advisory feed.** The NVD advisory feed was retired (JEF-242):
it was redundant with Trivy's CVE metadata (Trivy already supplies `title`, `severity`,
`fixedVersion`, and the CVSS `score` per vulnerability), the only net-new field (`cwe[]`) was
one trivy-operator omits anyway, and the NVD "recent" feed had a poor hit-rate against the
old base-image CVEs Trivy actually finds. KEV and EPSS stay — `exploited_in_wild` (KEV) and
the `epss` probability are the two exploitation signals Trivy does **not** supply, and both
drive the breach model.

**EPSS is the FIRST.org CSV.** The feed ships gzipped (`epss_scores-current.csv.gz`); the
sidecar gunzips it in place, and the engine's `EpssStore` parses the `cve,epss,percentile`
rows (skipping the leading metadata comment and the header). Only the parsed probability is
retained — no untrusted free-text from the feed reaches the model prompt.

**Why a sidecar, not a ConfigMap?** Raw CISA KEV JSON is ~1.5 MiB — over Kubernetes'
1 MiB ConfigMap limit (the retired CronJob path had to lossily strip it to CVE IDs); the
EPSS feed is similarly large. An `emptyDir` has no size limit, so the sidecar fetches and
the engine reads both feeds in **full**. This supersedes the JEF-228 CronJob and the
cancelled JEF-110 engine-fetch (see ADR-0015).

Override the cadence with `feedSync.interval` (e.g. `12h`), the sources with
`feedSync.kevUrl` / `feedSync.epssUrl`, and the curl image with `feedSync.image.*`.

**Egress boundary.** The sidecar is the **only** component the chart gives network egress
to, and it is **on by default**. It makes outbound GETs to **public, read-only** feed
URLs and writes them to the shared volume — it makes **no apiserver call** (no ServiceAccount
grant, no RBAC), never reads cluster state, and never transmits any cluster data outward.
The **engine stays zero-egress** (ADR-0015): it only reads the resulting files and makes no
feed network call of its own. The sidecar runs unprivileged (uid 100 / gid 101,
`allowPrivilegeEscalation: false`, read-only root filesystem, all capabilities dropped).

**Framing:** *engine zero-egress is preserved; the sidecar egresses to the public KEV + EPSS
feeds by default — disable it for air-gapped.*

#### Air-gapped / zero-egress

To run with **no chart egress at all**, disable the feed-fetcher sidecar:

```sh
--set feedSync.enabled=false
```

With `feedSync.enabled=false`, no sidecar, no shared volume, and no feed env are
templated, and **no component in the chart egresses**. To keep enrichment offline, mount
your own `kev.json` / `epss.csv` into the engine container at `/var/lib/protector/feeds`
(e.g. via a ConfigMap/Secret/PVC you manage) and set `PROTECTOR_KEV_FILE` /
`PROTECTOR_EPSS_FILE` accordingly.

### The engine's live cut is armed by `mode: enforce`

The engine's reversible network cut is one of the three surfaces `mode: enforce` arms
(above) — there is no separate engine arming switch. In `mode: audit` the engine is
always dry-run; under `mode: enforce` it applies its cut on a corroborated attack path
whose endpoints are within `enforceScope`, and the NetworkPolicy write grant is derived
from the same `mode` (they arm together). Choose the CNI mechanism the cut renders with:

```sh
--set engine.actuator=networkpolicy      # default — any NetworkPolicy-enforcing CNI (ADR-0010)
# --set engine.actuator=adminnetworkpolicy  # surgical ANP edge-cut; needs Cilium/Calico (ADR-0007)
# --set engine.actuator=dryrun              # force shadow even under mode: enforce
```

The cut keeps all its own safety gates (live corroboration, blast-radius guard,
adjudicator veto, self-revert); `enforceScope` only bounds *where* it may land.

### Enable the breach notifier (opts you into egress)

```sh
--set engine.notify.url="https://your-sink.example/hook"
# --set engine.notify.verbose=true   # non-redacted detail; only for a trusted sink
```

### Export telemetry (opts you into egress)

```sh
--set otelEndpoint="http://otel-collector.observability.svc.cluster.local:4318"
```

### Enable the eBPF behavioral agent (ADR-0014)

Requires the `protector-agent` image and probes load-tested on your kernel (see
`agent/README.md`). Runs observe-only, in shadow.

```sh
--set agent.enabled=true
```

## Notable values

| Key                          | Default                              | Notes                                              |
| ---------------------------- | ------------------------------------ | -------------------------------------------------- |
| `mode`                       | `audit`                              | **The posture switch** (ADR-0021). `enforce` arms all three surfaces in `enforceScope`. |
| `enforceScope.namespaces`    | `[]`                                 | Namespace names to enforce (used only under `mode: enforce`). No wildcard. |
| `enforceScope.labels`        | `{}`                                 | Pod labels (`key: value`) to enforce anywhere; labels behave like namespaces. |
| `image.tag`                  | `""` → chart `appVersion`            | Pin a cosign-signed semver tag.                    |
| `imagePullSecrets`           | `[]`                                 | protector publishes to a public ghcr repo.         |
| `engine.enabled`             | `true`                               | The mitigation engine (the product).               |
| `engine.actuator`            | `networkpolicy`                      | CNI mechanism for the cut (used only under `mode: enforce`); `adminnetworkpolicy` / `dryrun`. |
| `rekor.enabled`              | `false`                              | Opt-in transparency-log egress carve-out (ADR-0020 §4). |
| `engine.journal.enabled`     | `true`                               | Persistent decision journal (a PVC).               |
| `engine.journal.storageClass`| `""` (cluster default)               | RWO; the Deployment uses the `Recreate` strategy.  |
| `cert.create`                | `true`                               | cert-manager serving cert + caBundle injection.    |
| `ingestAuth.enabled`         | `true`                               | Bearer-token authn on the :9999 ingest (engine + agent share a Secret). |
| `ingestAuth.existingSecret`  | `""`                                 | Bring your own Secret (key `token`) for rotation.  |
| `feedSync.enabled`           | `true`                               | Feed-fetcher sidecar (the one default-on egress); fetches the full CISA KEV + FIRST.org EPSS feeds into a shared volume the engine reads. Set `false` for air-gapped. |
| `feedSync.kevUrl`            | CISA KEV catalogue JSON              | KEV source (plain JSON, fetched in full). See feeds section. |
| `feedSync.epssUrl`           | FIRST.org EPSS scores CSV (gzipped)  | EPSS source (gzipped CSV, gunzipped in place). See feeds section. |
| `feedSync.interval`          | `"12h"`                              | Re-fetch interval for the sidecar (a `sleep` arg, e.g. `6h`, `30m`). |
| `webhook.enforcedFailurePolicy` | `Fail`                            | The fail-closed enforcing webhook's policy (its scope is derived from `enforceScope`). |
| `resources`                  | 10m/64Mi → 250m/256Mi                | RAM-tight, arm64-friendly.                          |

See [`values.yaml`](values.yaml) for the fully commented set.

## Validate locally

```sh
helm lint charts/protector
helm template charts/protector
```
