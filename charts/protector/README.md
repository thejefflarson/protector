# protector Helm chart

Install [protector](../../README.md) — the admission webhook (first-party
image-signature verification + mesh-injection policy) and the async mitigation
engine (proves ATT&CK attack chains over observed cluster state and proposes, or
once armed auto-applies, reversible minimal cuts) — with one `helm install` instead
of hand-assembling RBAC, the webhook serving cert, the journal PVC, the agent
DaemonSet, and ~30 env vars.

## Safe by default

Out of the box the chart is in its most conservative posture. **Every step toward
acting on the cluster is a single, documented value change — nothing dangerous is
default-on.**

| Property            | Default                                | Why                                                              |
| ------------------- | -------------------------------------- | --------------------------------------------------------------- |
| Webhook gating      | **audit-only** (`enforceNamespaces` empty) | Logs unsigned/unmeshed pods, never blocks them.             |
| Webhook failure     | audit `failurePolicy: Ignore`; enforcing webhook `Fail` but **scoped to nothing** | The audit webhook never blocks API writes; the fail-closed enforcing webhook matches no namespace until you label one in. |
| Ingest auth         | **on** (`ingestAuth.enabled: true`)    | The :9999 runtime ingest requires a bearer token; engine + agent share a chart-provisioned Secret. |
| Engine              | **shadow** (`engine.enable` empty)     | Detects + proposes; the engine forces dry-run actuation while no class is armed. |
| Actuator            | `dryrun`                               | Touches nothing even if a class is later armed (a deliberate two-step). |
| Egress              | **none**                               | No breach-notify URL, no OTLP, no live advisory/intel fetch — advisory + KEV are mounted snapshots only (ADR-0015). |
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

Nothing below is enabled by default. Arm in this order and review the decision
journal / audit log at each step.

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

### Mount advisory / KEV snapshots (zero egress)

Sync a CISA KEV list and/or a CVE-keyed advisory file into a ConfigMap out of band
(the engine never fetches them over the network — ADR-0015), then:

```sh
--set engine.kev.configMapName=kev-snapshot \
--set engine.advisory.configMapName=advisory-snapshot
```

### Auto-sync the KEV / advisory snapshots (feed-sync CronJob)

Instead of syncing those ConfigMaps by hand, opt into the **feed-sync** CronJob — a
dedicated, off-by-default job that downloads the public CISA KEV feed (and an optional
advisory source) on a schedule and upserts the `kev-snapshot` / `advisory-snapshot`
ConfigMaps the engine mounts:

```sh
--set feedSync.enabled=true \
--set engine.kev.configMapName=kev-snapshot \
--set engine.advisory.configMapName=advisory-snapshot \
# optional advisory source (empty = KEV only):
--set feedSync.advisoryUrl="https://your-internal/advisories.json"
```

**Egress boundary.** The CronJob is the **only** component the chart gives network
egress to. It makes outbound GETs to two **public, read-only** feed URLs and writes to
the in-cluster apiserver to upsert the two ConfigMaps — it never reads cluster state and
never transmits any cluster data outward. The **engine stays zero-egress** (ADR-0015):
it only mounts the resulting snapshot files and makes no advisory/KEV network call of its
own. The job runs as its **own dedicated ServiceAccount** whose Role grants
get/update/patch (plus the first-run create) on **only** the two named ConfigMaps in the
release namespace — least privilege, isolated from the engine's ServiceAccount.

When `feedSync.enabled=false` (the default) nothing extra is templated and the
manual-mount path above is unchanged. Tune the cadence with `feedSync.schedule`, the
sources with `feedSync.kevUrl` / `feedSync.advisoryUrl`, and the image (official
`bitnami/kubectl` by default) with `feedSync.image.*`.

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
| `webhook.enforcedFailurePolicy` | `Fail`                            | The fail-closed enforcing webhook's policy.        |
| `webhook.enforcedNamespaceSelector` | `{}` (matches nothing)         | Label-select the namespaces that fail closed.      |
| `resources`                  | 10m/64Mi → 250m/256Mi                | RAM-tight, arm64-friendly.                          |

See [`values.yaml`](values.yaml) for the fully commented set.

## Validate locally

```sh
helm lint charts/protector
helm template charts/protector
```
