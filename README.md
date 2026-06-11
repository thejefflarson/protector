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
| `PROTECTOR_ENFORCE` | `false` | `true` denies signature violations; `false` logs only (audit) |
| `PROTECTOR_TUF_CACHE` | `/tmp/sigstore` | writable sigstore TUF cache dir |
| `PROTECTOR_REGISTRY_USERNAME` / `PROTECTOR_REGISTRY_PASSWORD` | — | registry auth for private gated images |
| `PROTECTOR_VERIFY_TIMEOUT` | `5` | per-image verification timeout (seconds) |
| `PROTECTOR_CACHE_TTL` | `300` | verdict cache TTL (seconds); bounds mutable-tag TOCTOU |
| `PROTECTOR_MAX_IMAGES` | `32` | max distinct gated images verified per Pod |
| `PROTECTOR_MESH_ENFORCE` | `false` | `true` denies unmeshed Pods; `false` logs only (audit) |
| `PROTECTOR_MESH_EXEMPT_NAMESPACES` | `dev,kube-system,…,protector` | namespaces exempt from mesh-injection enforcement |
| `RUST_LOG` | — | tracing filter (e.g. `protector=info`) |

## Endpoints

- `POST /validate` — the AdmissionReview endpoint
- `GET /healthz`, `GET /readyz` — probes
- `GET /metrics` — Prometheus exposition of `protector_policy_violations_total{policy,decision}`

## Audit vs enforce, and discovery

A policy that finds a violation but isn't enforcing — because it's in audit mode
*or* the workload is exempt (e.g. an unmeshed Pod in the runner namespace) — does
**not** silently allow. It returns an **audit** outcome: the request is admitted,
but the engine records a structured log line (`policy`, `namespace`, `name`,
`kind`, `decision=audit`) and increments the `audit` counter. So exempt/audit
workloads stay *visible*. That stream is the discovery signal for "what would
enforcement reject" — query the logs/metric, or run `scripts/protector-discover.py`
in the cluster repo for an active inventory of mesh/signing candidates.

## Rollout

Ships fail-safe: `failurePolicy: Ignore` and `PROTECTOR_ENFORCE=false`. Watch the
audit logs/metrics until clean, then flip enforce on (and, per policy, tighten the
webhook to `failurePolicy: Fail`).

## Develop

```sh
cargo test
cargo clippy --all-targets
```
