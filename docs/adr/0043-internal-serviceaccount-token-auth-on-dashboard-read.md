# 0043. Accept an internal Kubernetes ServiceAccount-token on the dashboard read surface

- Status: Accepted
- Date: 2026-11-07
- Relates to: [0030](0030-app-level-oidc-verification-supersedes-edge-trust.md) (the app-level
  OIDC verifier + fail-closed enforcement this extends), [0031](0031-read-only-mcp-server-tiered-redaction.md)
  (the same read-only, tiered-redaction surface — the internal lane is read-only too),
  [0016](0016-severity-vs-urgency.md) (presentation is a view, never a decision gate — this gates
  *viewing*, never the verdict/actuation path)

## Context

[0030](0030-app-level-oidc-verification-supersedes-edge-trust.md) made protector a **resource
server**: the dashboard read surface (the shell + the `/api/*.json` snapshots) verifies the
Cloudflare Access JWT the edge issues (the `Cf-Access-Jwt-Assertion` header / `CF_Authorization`
cookie) and fails closed. That is the right gate for a *browser* reaching protector through the
Cloudflare tunnel. It is the wrong gate for an *in-cluster* caller.

The cluster repo's **`fixer`** runs in the same Kubernetes cluster as protector and needs to read
`/api/*.json` (its new `protector_read` tool). Routing it out to the Cloudflare edge and back to
obtain an Access assertion is absurd for a Service-to-Service call on the pod network — slower,
coupling an internal control path to the public edge, and `fixer` has no browser to carry the
Access cookie and cannot mint an edge Access JWT in-cluster. What `fixer` *does* already have is a
projected Kubernetes ServiceAccount token.

Those tokens are OIDC JWTs the cluster itself issues and can verify:

- issuer `https://kubernetes.default.svc.cluster.local`, signed **RS256**;
- JWKS published in-pod at `https://kubernetes.default.svc.cluster.local/openid/v1/jwks`;
- a projected token carries `aud=["protector"]` (the audience we require), `exp`, `nbf`, and
  `sub="system:serviceaccount:<namespace>:<name>"`.

Reading that JWKS is itself authenticated: the `system:service-account-issuer-discovery`
ClusterRole gates it, so the fetch must present protector's own projected token as
`Authorization: Bearer` and trust the cluster CA (the apiserver's serving cert chains to it, not a
public root).

## Decision

Accept an internal ServiceAccount-token JWT on the dashboard read surface **in addition to** the
Cloudflare Access assertion. This is **pure addition** — the edge/Access path is unchanged, and the
lane is **read-only** (it mounts on the same read gate, never on a mutating or admission path).

- **Reuse the existing verifier.** `dashboard::auth::Verifier` already checks RS256 signature +
  `iss` + `aud` + `exp` + `nbf` + `sub`, pins the algorithm from config (never the token's own
  header — the alg-confusion close of 0030 §1), and is issuer/audience-agnostic. A new
  `jwks::ClusterJwksFetcher` points it at the cluster issuer/JWKS, trusts the cluster CA
  (`reqwest::Certificate::from_pem`), and reads protector's SA token **fresh on every JWKS fetch**
  (projected tokens rotate) to authenticate the discovery request. The same bounded-body /
  single-flight / rate-limited `JwksStore` (0030 §5) protects this fetch too.
- **Require a `sub` allowlist.** A verified internal token is admitted only when its `sub` is in
  `PROTECTOR_DASHBOARD_INTERNAL_ALLOWED_SUBS` (e.g. `system:serviceaccount:fixer:fixer`). A valid
  token with a non-allowlisted `sub` is a hard `401` — a presented-but-unauthorized identity is a
  reject, never a fall-through, and never a browser `302` (a machine identity is not re-challenged
  at a login page). If the lane is configured (`PROTECTOR_DASHBOARD_INTERNAL_AUD` set) but the
  allowlist is empty, the lane is treated as **off** (logged at ERROR) — fail closed, and the edge
  path is left untouched.
- **One gate, two lanes, tried in order.** The dashboard enforce gate first tries the internal lane
  when an `Authorization: Bearer` token is present; on a verify failure it **falls through** to the
  edge path (it never fails *open* on the internal lane). An admitted internal identity is inserted
  and subjected to the **same** minimum-tier gate as the edge path — it authorizes read exactly as
  the edge path authorizes read today.
- **Floor tier, read-only.** A cluster SA token carries no `tier` claim, so an admitted internal
  identity resolves to the most-restricted `Redacted` tier (0030 §6 — a missing tier is never
  permissive). `fixer` reads the redacted view, which is the appropriate disclosure for an
  automated reader.

### Posture: fail-closed internal, fail-open-nowhere

The edge path remains defense-in-depth exactly as 0030 left it. The internal lane fails **closed**:
an internal caller sends no `Cf-Access-Jwt-Assertion`, so when its token can't be verified it falls
through to the edge path, hits "no token," and gets `401`/`302` per the route class. A cluster-JWKS
outage (`AuthError::JwksUnreachable`) therefore admits no unverified internal caller — unlike the
Cloudflare path, there is no warm-cache fail-open here, because the internal lane is the *only*
thing that could admit a tokenless-at-the-edge caller.

### Coupling to the edge gate

The internal lane rides on `dashboard::auth::enforce::Enforcer`, which `run_loop` mounts only when
the edge OIDC issuer is configured (the dashboard's `Oidc` mode). An edge-trust-only deployment (no
issuer) mounts no gate at all, so the `PROTECTOR_DASHBOARD_INTERNAL_*` vars are inert there — but
that mode already serves the dashboard unauthenticated in-cluster, so there is nothing for the
internal lane to add. The cluster deploys protector with the edge issuer set, so the lane is active.

### Configuration (env vars)

| Variable | Default | Meaning |
| --- | --- | --- |
| `PROTECTOR_DASHBOARD_INTERNAL_AUD` | *(unset ⇒ lane off)* | Required audience; enables the lane when set and non-empty. |
| `PROTECTOR_DASHBOARD_INTERNAL_ALLOWED_SUBS` | *(empty ⇒ lane off)* | Comma-separated exact `sub` allowlist. |
| `PROTECTOR_DASHBOARD_INTERNAL_ISSUER` | `https://kubernetes.default.svc.cluster.local` | Expected `iss`. |
| `PROTECTOR_DASHBOARD_INTERNAL_JWKS_URL` | `<issuer>/openid/v1/jwks` | JWKS endpoint (direct, no discovery). |
| `PROTECTOR_DASHBOARD_INTERNAL_TOKEN_PATH` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | protector's own SA token, read fresh per fetch. |
| `PROTECTOR_DASHBOARD_INTERNAL_CA_PATH` | `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` | Cluster CA trusted for the JWKS fetch. |

## Consequences

- `fixer` (and any future in-cluster `/api` reader) authenticates with its own SA token — no
  Cloudflare round-trip, scoped to a named identity, read-only at the redacted tier. The cluster
  repo's protector chart sets `PROTECTOR_DASHBOARD_INTERNAL_AUD=protector` and the allowlist to
  `system:serviceaccount:fixer:fixer`; the `fixer` chart mounts a projected `aud=protector` SA token
  and presents it as the bearer.
- The attack surface stays narrow: RS256 only (no alg-confusion regression), the exact cluster `iss`
  and the required `aud`, a non-expired/active token, and an explicit `sub` allowlist. Token
  contents are never logged — only the `sub` on a reject.
- The edge path is untouched; existing Access/enforce tests and behavior stand. The cost is a second
  verifier and a slightly more involved gate (two ordered lanes instead of one), plus the operational
  duty to keep the allowlist correct — an empty or wrong allowlist fails closed, the safe direction.
- Unset `PROTECTOR_DASHBOARD_INTERNAL_AUD` leaves the lane entirely out of the gate, so local dev and
  non-cluster deploys are unchanged.
