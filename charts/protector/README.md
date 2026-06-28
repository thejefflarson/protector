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
| Webhook gating      | **audit-only** (`enforceNamespaces` empty) | Logs unsigned/unmeshed pods, never blocks them.             |
| Webhook scope       | **audit every namespace** (`webhook.excludeNamespaces: []`) | The fail-open audit webhook observes Pod creates cluster-wide, including kube-system / cert-manager / linkerd / argocd / protector. List names in `excludeNamespaces` to opt some out. |
| Webhook failure     | audit `failurePolicy: Ignore`; enforcing webhook `Fail` but **scoped to nothing** | The audit webhook never blocks API writes (so auditing every namespace is safe even for kube-system); the fail-closed enforcing webhook matches no namespace until you label one in. |
| Ingest auth         | **on** (`ingestAuth.enabled: true`)    | The :9999 runtime ingest requires a bearer token; engine + agent share a chart-provisioned Secret. |
| Engine              | **shadow** (`engine.enable` empty)     | Detects + proposes; the engine forces dry-run actuation while no class is armed. |
| Actuator            | `dryrun`                               | Touches nothing even if a class is later armed (a deliberate two-step). |
| Engine egress       | **none** (zero-egress, ADR-0015)       | The engine makes no breach-notify call, no OTLP export, no live feed fetch — it only reads mounted feed files; the security graph never leaves the cluster. |
| Feed-fetcher egress | **on** (`feedSync.enabled: true`)      | The ONE component with egress: a co-located sidecar that GETs public, read-only exploitation-intel feeds (CISA KEV + FIRST.org EPSS) into a shared volume the engine reads. It never reads or transmits cluster data. Set `feedSync.enabled=false` for a fully air-gapped install. |
| Model               | **off** (`engine.model.endpoint` empty) | Engine runs the deterministic enumerator only; no model required. |
| eBPF agent          | **off** (`agent.enabled: false`)       | Needs the agent image + probes load-tested on your kernel.      |
| RBAC                | read-only                              | No write grants unless `actuationRBAC: true` (armed mode).      |

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

and review the engine's proposals on the read-only dashboard:

```sh
kubectl -n protector port-forward svc/protector-dashboard 8080:8080
# open http://localhost:8080/
```

## Opt-ins (each is one value change)

Nothing below that **acts on or blocks** your workloads is enabled by default (the one
default-on item is the read-only **feed-fetcher** egress, covered below). Arm in this order
and review the decision journal / audit log at each step.

### Enforce image signatures in a namespace

```sh
--set signature.enforceNamespaces="payments,ingress"
```

Unsigned gated images are then **denied** in those namespaces (audit everywhere
else). There is no enforce-everywhere wildcard by design. Same shape for mesh-
injection: `--set mesh.enforceNamespaces=...`.

### Fail closed in enforced namespaces (webhook availability tradeoff)

By default the admission webhook **fails open** (`failurePolicy: Ignore`): a
protector outage never blocks Pod creation. That is the right posture for audit, but
it means an outage could admit an *unsigned* image into a namespace you intended to
gate. The chart ships a second, **fail-closed** webhook (`pods-enforce.protector.dev`,
`failurePolicy: Fail`) scoped by a label selector — empty by default, so it blocks
nothing until you opt a namespace in:

```sh
kubectl label namespace payments protector.dev/enforce=true
helm upgrade protector ./charts/protector --namespace protector --reuse-values \
  --set webhook.enforcedNamespaceSelector.matchLabels.'protector\.dev/enforce'=true
```

Now in `payments`, if protector is down (or a Pod spec is oversized), Pod **CREATE is
blocked** instead of admitting a possibly-unsigned image. **Tradeoff:** while
protector is unavailable, new Pods (including rollouts and HPA scale-ups) cannot be
created in the labeled namespaces until it recovers. Keep the selector tight and
aligned with `signature.enforceNamespaces` / `mesh.enforceNamespaces`. The audit
webhook automatically *excludes* the enforced namespaces, so they aren't
double-validated and aren't silently failed open.

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

### Arm the engine (live actuation) — the careful two-step

1. **Choose a live actuator** (still no class enabled, so still dry-run):
   ```sh
   --set engine.actuator=networkpolicy   # or adminnetworkpolicy (needs a CNI implementing ANP)
   ```
2. **Arm a class** and grant the write RBAC together, only after a journal review:
   ```sh
   --set engine.enable=network \
   --set engine.actuationRBAC=true
   ```

`network` is the only live-actuatable class today; `escape` is never enableable.
With `engine.enable` empty the engine forces dry-run regardless of `engine.actuator`,
so step 1 alone never writes to the cluster.

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
| `image.tag`                  | `""` → chart `appVersion`            | Pin a cosign-signed semver tag.                    |
| `imagePullSecrets`           | `[]`                                 | protector publishes to a public ghcr repo.         |
| `engine.enabled`             | `true`                               | The mitigation engine (the product).               |
| `engine.enable`              | `""` (shadow)                        | **Arming switch** — comma list of classes.         |
| `engine.actuator`            | `dryrun`                             | `networkpolicy` / `adminnetworkpolicy` to go live. |
| `engine.actuationRBAC`       | `false`                              | NetworkPolicy write grant; arm with the actuator.  |
| `engine.journal.enabled`     | `true`                               | Persistent decision journal (a PVC).               |
| `engine.journal.storageClass`| `""` (cluster default)               | RWO; the Deployment uses the `Recreate` strategy.  |
| `cert.create`                | `true`                               | cert-manager serving cert + caBundle injection.    |
| `ingestAuth.enabled`         | `true`                               | Bearer-token authn on the :9999 ingest (engine + agent share a Secret). |
| `ingestAuth.existingSecret`  | `""`                                 | Bring your own Secret (key `token`) for rotation.  |
| `feedSync.enabled`           | `true`                               | Feed-fetcher sidecar (the one default-on egress); fetches the full CISA KEV + FIRST.org EPSS feeds into a shared volume the engine reads. Set `false` for air-gapped. |
| `feedSync.kevUrl`            | CISA KEV catalogue JSON              | KEV source (plain JSON, fetched in full). See feeds section. |
| `feedSync.epssUrl`           | FIRST.org EPSS scores CSV (gzipped)  | EPSS source (gzipped CSV, gunzipped in place). See feeds section. |
| `feedSync.interval`          | `"12h"`                              | Re-fetch interval for the sidecar (a `sleep` arg, e.g. `6h`, `30m`). |
| `webhook.enforcedFailurePolicy` | `Fail`                            | The fail-closed enforcing webhook's policy.        |
| `webhook.enforcedNamespaceSelector` | `{}` (matches nothing)         | Label-select the namespaces that fail closed.      |
| `resources`                  | 10m/64Mi → 250m/256Mi                | RAM-tight, arm64-friendly.                          |

See [`values.yaml`](values.yaml) for the fully commented set.

## Validate locally

```sh
helm lint charts/protector
helm template charts/protector
```
