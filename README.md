# protector

A validating admission webhook for the cluster. The Kubernetes API server calls
it on every matched write; it runs an ordered set of policies against the
request and admits it only if every applicable policy allows it.

It is deliberately a small, focused set of Rust policies behind a registry — not
a generic rules engine (no Kyverno/OPA re-implementation).

## Policies

| Policy | What it does | Default |
|--------|--------------|---------|
| `image-signature` | Rejects Pods whose **first-party** images (`ghcr.io/thejefflarson/…`) aren't keyless cosign-signed by our GitHub Actions identity, verified in-process with [sigstore-rs](https://github.com/sigstore/sigstore-rs). Third-party images are out of scope. | audit (allow + log) |
| `mesh-injection` | Rejects Pods that aren't Linkerd-meshed (no injected `linkerd-proxy`), outside an exempt namespace set. The exempt set **must** include the deliberately-unmeshed runner namespace and the control plane. | audit (allow + log) |

Signature verification mirrors the fleet-wide cosign check:
`--certificate-identity-regexp '^https://github.com/thejefflarson/'`
`--certificate-oidc-issuer 'https://token.actions.githubusercontent.com'`.

## Why TLS, and why it isn't Linkerd's job

The caller is the **kube-apiserver**, which is not in the mesh — so Linkerd's
mTLS can't secure this hop. Kubernetes also *requires* webhooks to be HTTPS: the
apiserver validates the serving cert against the `caBundle` in the
`ValidatingWebhookConfiguration`. So protector terminates its own TLS from a
cert-manager-issued cert; Linkerd still meshes the pod for its outbound calls.

## Configuration (env)

| Var | Default | Meaning |
|-----|---------|---------|
| `PROTECTOR_ADDR` | `0.0.0.0:8443` | listen address |
| `PROTECTOR_TLS_CERT` / `PROTECTOR_TLS_KEY` | `/etc/protector/tls/tls.{crt,key}` | serving cert/key (cert-manager) |
| `PROTECTOR_IDENTITY_REGEXP` | `^https://github\.com/thejefflarson/` | trusted signing identity (start-anchored; substring-anchored if no `^`) |
| `PROTECTOR_OIDC_ISSUER` | `https://token.actions.githubusercontent.com` | expected OIDC issuer |
| `PROTECTOR_GATED_PREFIXES` | `ghcr.io/thejefflarson/` | comma-separated image prefixes to enforce (registry host case-normalized) |
| `PROTECTOR_ENFORCE_NAMESPACES` | — | namespaces where signatures are **enforced** (denied). Empty = audit everywhere |
| `PROTECTOR_ENFORCE_LABELS` | — | `key=value` pod labels that opt a Pod into signature enforcement |
| `PROTECTOR_TUF_CACHE` | `/tmp/sigstore` | writable sigstore TUF cache dir |
| `PROTECTOR_REGISTRY_USERNAME` / `PROTECTOR_REGISTRY_PASSWORD` | — | registry auth for private gated images |
| `PROTECTOR_VERIFY_TIMEOUT` | `5` | per-image verification timeout (seconds) |
| `PROTECTOR_CACHE_TTL` | `300` | verdict cache TTL (seconds); bounds mutable-tag TOCTOU |
| `PROTECTOR_MAX_IMAGES` | `32` | max distinct gated images verified per Pod |
| `PROTECTOR_MESH_ENFORCE_NAMESPACES` | — | namespaces where mesh injection is **enforced**. Empty = audit everywhere. **Never list the runner namespace** (deliberately unmeshed) |
| `PROTECTOR_MESH_ENFORCE_LABELS` | — | `key=value` pod labels that opt a Pod into mesh enforcement |
| `RUST_LOG` | — | tracing filter (e.g. `protector=info`) |

**Enforcement is opt-in.** Both policies audit everywhere by default (log + meter,
never block). You start blocking by adding namespaces or pod labels to a policy's
enforce allowlist — one slice at a time. There is no "enforce everywhere"
wildcard by design (it would be a footgun, e.g. blocking the unmeshed runner ns);
list the namespaces you mean.

## Endpoints

- `POST /validate` — the AdmissionReview endpoint
- `GET /healthz`, `GET /readyz` — probes
- `GET /metrics` — Prometheus exposition of `protector_policy_violations_total{policy,decision}`

## Audit vs enforce, and discovery

A policy that finds a violation but isn't enforcing *here* — because the Pod's
namespace/labels aren't on the policy's enforce allowlist — does **not** silently
allow. It returns an **audit** outcome: the request is admitted, but the engine
records a structured log line (`policy`, `namespace`, `name`, `kind`,
`decision=audit`) and increments the `audit` counter. So audited workloads stay
*visible*. That stream is the discovery signal for "what would enforcement
reject" — query the logs/metric, or run `scripts/protector-discover.py` in the
cluster repo for an active inventory of mesh/signing candidates.

## Rollout

Ships fail-safe: `failurePolicy: Ignore` and empty enforce allowlists (audit
everywhere). Watch the audit logs/metrics until a namespace looks clean, then add
just that namespace to the policy's `*_ENFORCE_NAMESPACES` to start blocking
there — and, once proven broadly, tighten the webhook to `failurePolicy: Fail`.

## Develop

```sh
cargo test
cargo clippy --all-targets
```
