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
| `mesh-injection` | (stub) Will require Linkerd injection on non-exempt workloads. | allow |

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
| `PROTECTOR_IDENTITY_REGEXP` | `^https://github.com/thejefflarson/` | trusted signing identity |
| `PROTECTOR_OIDC_ISSUER` | `https://token.actions.githubusercontent.com` | expected OIDC issuer |
| `PROTECTOR_GATED_PREFIXES` | `ghcr.io/thejefflarson/` | comma-separated image prefixes to enforce |
| `PROTECTOR_ENFORCE` | `false` | `true` denies violations; `false` logs only (audit) |
| `PROTECTOR_TUF_CACHE` | `/tmp/sigstore` | writable sigstore TUF cache dir |
| `PROTECTOR_REGISTRY_USERNAME` / `PROTECTOR_REGISTRY_PASSWORD` | — | registry auth for private gated images |
| `RUST_LOG` | — | tracing filter (e.g. `protector=info`) |

## Endpoints

- `POST /validate` — the AdmissionReview endpoint
- `GET /healthz`, `GET /readyz` — probes

## Rollout

Ships fail-safe: `failurePolicy: Ignore` and `PROTECTOR_ENFORCE=false`. Watch the
audit logs until clean, then flip enforce on (and, per policy, tighten the
webhook to `failurePolicy: Fail`).

## Develop

```sh
cargo test
cargo clippy --all-targets
```
