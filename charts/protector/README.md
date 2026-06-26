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
| Webhook failure     | `failurePolicy: Ignore`                | A protector outage can never block API writes.                  |
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
| `resources`                  | 10m/64Mi → 250m/256Mi                | RAM-tight, arm64-friendly.                          |

See [`values.yaml`](values.yaml) for the fully commented set.

## Validate locally

```sh
helm lint charts/protector
helm template charts/protector
```
