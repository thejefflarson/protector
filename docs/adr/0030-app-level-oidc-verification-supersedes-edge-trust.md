# 0030. App-level, provider-agnostic OIDC verification supersedes edge-only trust

- Status: Proposed
- Date: 2026-07-22
- Relates to: [0014](0014-behavioral-telemetry-ebpf.md) (the "in-cluster, no egress of
  cluster data" posture this decision keeps while adding one inbound-trust lane),
  [0015](0015-advisory-evidence-egress.md) (the same-request-for-everyone egress test the
  JWKS fetch is argued under — the KEV catalogue precedent), [0018](0018-operator-configured-redacted-breach-notifier.md)
  (the one sanctioned *outbound* path — this ADR names a distinct, inbound-only lane and
  keeps 0018's the only cluster-data egress), [0020](0020-signature-continuity.md) (the
  Rekor-read carve-out under the same test), [0016](0016-severity-vs-urgency.md)
  (presentation is a view, never a decision gate — auth gates *viewing*, not the verdict path)

## Context

The dashboard and its read-only JSON feeds have **no application-level authentication.**
`engine/src/engine/dashboard/mod.rs::router()` wires seven routes (`/`, the five
`/api/*.json` snapshots, the two `/assets/*` files) under a **single layer** —
`security_headers::set_csp` — and nothing else. There is no auth middleware, no token
check, no session gate. Every request that reaches the listener is served the full
view-model: `GET /api/findings.json` returns the entire proven-attack-chain graph
(verdicts, reachable objectives, the whole security posture); `admission.json` returns the
signing inventory; `action.json` returns the would-have-acted decision journal. The crown
jewels are served to anyone who can open a socket to the bind address.

Today that address sits behind a Cloudflare Access public tunnel, and auth is trusted
**entirely at that edge.** The engine assumes: *if a request arrived, the edge already
authenticated it.* That assumption is false the moment anything else can reach the port —
and in a Kubernetes cluster, plenty can:

```
kubectl port-forward svc/protector-dashboard 8080:8080
curl localhost:8080/api/findings.json      # → the entire security graph, zero auth
```

Any principal with `port-forward` (or any pod on the pod network that can route to the
Service) reads everything, with no credential at all. The crown jewels are **one kubectl
— or one compromised pod — away.** The dashboard's own doc-comment even calls it
"read-only, zero-egress … meant to sit behind the cluster's own ingress/mesh, not face the
internet directly" — but "behind the mesh" is exactly a *perimeter*, and a perimeter-only
"internal = trusted" model is precisely the assumption a runtime-security tool must **not**
make about the cluster it is watching. Protector's entire thesis (ADR-0016/0020) is that
the inside is not to be trusted by default — a breach *is* an attacker who is already
inside. A dashboard that trusts every in-cluster caller contradicts the product it ships.

We need application-level authentication that the engine enforces itself, on every request,
without weakening the two invariants that define protector: **zero egress of cluster data**
and **presentation is a view, never a decision gate.**

## Decision

**Protector verifies an OIDC JWT itself, on every request to the dashboard and its JSON
feeds, against a configurable issuer — superseding edge-only trust.** The edge (Cloudflare
Access) may still front the tunnel, but it is no longer the *only* thing standing between an
attacker and the graph; the engine independently re-verifies the assertion the edge issued.

### 1. Protector is a RESOURCE SERVER, not an authorization server — it verifies, it cannot actuate

Protector is an OAuth **protected resource / resource server**. It **verifies presented
tokens**; it does **not** mint them, run interactive login flows, hold client secrets, or
issue redirects to an authorization endpoint. On each request it:

- extracts the bearer JWT from the request (the `Authorization: Bearer` header, or the
  provider's header/cookie — see §6);
- verifies **signature, `iss`, `aud`, `exp`, and `nbf`**;
- **pins the algorithm to the expected asymmetric family** (the configured issuer's signing
  algorithm, e.g. RS256/ES256) and **never selects the key type from the token's own `alg`
  header** — the classic `alg` confusion (accepting `HS256` and verifying an RSA public key
  as an HMAC secret, or honoring `alg: none`) is structurally excluded because the verifier
  decides the algorithm from configuration, not from attacker-controlled token bytes;
- extracts the **subject** and a **configurable tier claim** (which claim path names the
  operator's authorization tier — protector reads it, it does not define the IdP's claim
  schema).

Crucially, this changes **who may VIEW**; it adds **no new actuation surface.** The verifier
gates reads of an already-read-only presentation. It cannot promote a verdict, cut a network
edge, or write any state — the dashboard has no write path (ADR-0016), and this ADR adds
none. A resource server that can only *let a request through to a read* cannot actuate.

### 2. Provider-agnostic, bring-your-own-IdP — protector ships NO identity provider

The issuer is **configurable**, and any conformant OIDC provider is valid: **Cloudflare
Access** is the reference browser/dashboard issuer (it already fronts the tunnel today);
**Okta, Keycloak, Auth0, Azure AD, Google, Dex-run-by-the-operator** are equally valid. The
operator points protector at *their* issuer.

**Protector ships no IdP of its own.** Bundling Dex/Keycloak in-cluster — considered earlier
as a "zero-egress-pure, no-outbound-anything" option (run the whole identity plane inside the
cluster so nothing about auth ever leaves) — is **explicitly out of scope and rejected here.**
Protector is a **verifier, not an identity provider.** Reasons:

- Running an IdP is a large, security-critical, stateful surface (user store, session
  management, its own crypto, its own patch cadence) that is *not protector's job* and would
  dwarf the verifier in blast radius.
- Operators already have an IdP; forcing a second one is hostile, not helpful.
- The zero-egress motivation for an in-cluster IdP is satisfied more cheaply by §5 — the JWKS
  fetch leaks nothing cluster-specific, so "no IdP outbound" buys no real confidentiality over
  "verify against the operator's existing IdP."

This **supersedes** that earlier in-cluster-Dex idea as an explicit decision: *protector is a
resource server that verifies tokens from an IdP it does not run.*

### 3. ID-JAG forward-compatibility falls out for free

An **ID-JAG** token (the *Identity Assertion Authorization Grant*,
`draft-ietf-oauth-identity-assertion-authz-grant`) is, from the resource server's side,
**just a JWT** with `aud=protector` and a human `sub`. The **same verifier accepts it** with
no new code path: same signature/`iss`/`aud`/`exp`/`nbf` checks, and the **tier is governed by
the IdP-asserted human claim** carried in the token. No special-casing is needed because
resource-server verification is agnostic to *how* the token was granted.

This matters because MCP enterprise auth went stable (2026-06-18) on ID-JAG, and
**Okta/Keycloak issue ID-JAG tokens today** while **Cloudflare Access does not yet.** Building
plain resource-server verification now means protector is ID-JAG-ready the day an operator's
IdP starts issuing them — a machine/agent identity presenting an ID-JAG to protector's
dashboard/API is verified by the identical lane a browser's OIDC ID token is. We design for it,
we do not build a bespoke ID-JAG path.

### 4. Auth gates WHO MAY VIEW — it is NOT a decision input to the engine (ADR-0016 is not in tension)

ADR-0016 establishes that the **deterministic layer proves and enriches; the model decides
breach; presentation is a view, never a decision gate** — and the repo carries that
"presentation is a view, never a gate" principle from ADR-0016 throughout (the dashboard
module's own doc-comment, ADR-0020 §JEF-265.4, ADR-0025's "Reaffirms 0016"). Nothing here
touches that:

- Authentication gates **who may look at the view.** It is upstream of, and orthogonal to,
  the verdict/action path. The identity of the *viewer* is **never** an input to whether a
  chain is a breach or whether a cut is proposed — the model decides that from the proven,
  enriched chain, exactly as before.
- Presentation stays a **view**: still read-only, still no write route, still no dashboard
  path into the engine's decisions. Adding a *read gate* in front of a read-only surface does
  not make presentation a decision gate; the decision path is untouched and shadow-first
  (ADR-0016) is preserved verbatim.

So ADR-0016 is **reaffirmed, not amended**: the auth check decides *access to the view*, never
*the engine's judgement*.

### 5. Zero-egress reconciliation: the JWKS/discovery GET passes ADR-0015's same-request-for-everyone test

The one honest tension: verifying a JWT's signature requires the issuer's **public signing
keys**, fetched via **OIDC discovery** (`/.well-known/openid-configuration`) and the **JWKS**
endpoint it points at. That is an **outbound call.** Protector's posture is zero egress
(ADR-0014/0015). We must name the tension rather than hide it — the discipline ADR-0015 and
ADR-0020 hold.

It resolves cleanly under **the exact test ADR-0015 established** for the CISA KEV catalogue
fetch (§Context.1, §JEF-238 amendment): the rejected lane there was a **per-CVE** OSV/NVD
lookup, because it is *keyed on the cluster's own data* (its CVE profile) and leaks that
profile to a third party on every pass. The **sanctioned** lane was the KEV catalogue GET,
because it is **the same request for every relying party** and carries **no cluster-specific
datum outbound** — "the full CISA KEV catalogue is the same request for every cluster … it
does **not** leak the cluster's own CVE profile." ADR-0020 admits the Rekor read under the
same reasoning (a milder, non-cluster-data leak; the graph and evidence still never leave).

The **JWKS/discovery GET is the KEV-shaped lane, not the per-CVE-shaped one:**

- It fetches the **issuer's public signing keys** — a document identical for every relying
  party of that issuer, keyed on **nothing about this cluster.** Two clusters using the same
  Okta org make byte-identical requests.
- **What goes out:** a request for public keys. **What comes back:** public keys. **What never
  goes out:** anything about the security graph, the findings, the CVE profile, the cluster's
  identity, or the token being verified (the token is verified *locally* against the fetched
  keys — it is never transmitted to the issuer). The verification is a local signature check;
  only the *public key material* is fetched.

This is a **sanctioned inbound-trust lane** (pull public verification material *in*), not a
**data-egress breach** (push cluster data *out*). It is categorically the KEV/Rekor shape, and
categorically not the per-CVE shape. Public signing keys go out as a request; nothing about the
graph does. **Air-gapped escape hatch, verbatim with ADR-0015's posture:** an operator may mount
the JWKS as a static file (or point at an in-cluster IdP) so even the public-keys request stays
inside — the verifier reads keys from a mounted source exactly as the engine reads mounted
feeds, and the lane goes fully dark with no loss of verification.

Note this is an **inbound** lane and is therefore **distinct from ADR-0018's** one sanctioned
*outbound* path (the breach notifier). ADR-0018 remains the only lane that carries *cluster
data* out; the JWKS fetch carries none, so it does not widen 0018's carve-out.

### 6. Default posture is FAIL-CLOSED — the single bypass announces itself

**When an issuer is configured, every verification failure DENIES.** Bad signature, wrong
`iss`, wrong `aud`, expired (`exp`) or not-yet-valid (`nbf`), unknown `kid`, missing token,
malformed token, **and JWKS unreachable** all return **`401`/`403`/`503`** and **never run the
request through** to the view. There is no exception path that serves the graph on a
verification error. This is the crux and the **single highest-risk implementation line** — the
classic fail-*open*-on-exception trap (an error in the verifier that falls through to "allow")
is the one bug that silently reopens the entire exposure. The implementation must treat *any*
verifier error — including an unexpected panic/`Err` — as **deny**, never as "skip auth."
Specifically, a JWKS-unreachable condition is a **`503`, not a bypass**: if protector cannot
verify, it does not serve.

**When UNCONFIGURED, protector behaves as today** — edge-trust only, no application-level check
— **but logs loudly on every startup and periodically:** e.g.
`dashboard AUTH DISABLED — no OIDC issuer configured; relying on edge trust only`. This is the
**only** bypass, and it is **loud by construction**: an operator who has not configured an
issuer is told, unmistakably and repeatedly, that the dashboard is unauthenticated at the app
layer. Silence would be the danger; the escape hatch announces itself.

### 7. Migration path: Cloudflare Access already issues a verifiable JWT — the exposure closes with no new flow

The exposure can be closed **immediately, with no new interactive login flow to build.**
Cloudflare Access — the edge that already fronts the tunnel — **already issues a verifiable
JWT** on every authenticated request: the **`Cf-Access-Jwt-Assertion` header** (and the
`CF_Authorization` cookie), signed by Cloudflare's per-team OIDC issuer with a public JWKS.

So **pointing the verifier at the Cloudflare Access issuer authenticates every existing
browser with zero new UX:** the browser already carries the assertion, the verifier just starts
*checking* it instead of trusting that the edge did. This means the resource-server verification
(§1) is the **only** thing that must ship to close the port-forward hole — **`authorization_code`
and interactive flows are NOT prerequisites.** The exposure closes the moment the verifier is
wired in and configured against the CF issuer; broader BYO-IdP support (§2) and ID-JAG (§3)
follow on the *same verifier* without re-opening the gap.

## Consequences

What becomes easier / better:

- **The port-forward / on-pod-network exposure closes.** `curl /api/findings.json` without a
  valid token returns `401`, not the graph. The "internal = trusted" assumption is gone; the
  engine authenticates every caller itself.
- **Defense in depth that matches the product.** Protector stops trusting the perimeter of the
  very cluster it exists to distrust. Edge auth and app-level auth now both hold; compromising
  the edge (or bypassing it via the pod network) no longer yields the graph.
- **Provider freedom.** Operators bring their own IdP; protector ships none and runs none.
- **ID-JAG-ready** the day an operator's IdP issues them, on the identical verifier.
- **Zero-egress intact.** Only public signing keys are fetched, under the sanctioned
  same-request-for-everyone lane (ADR-0015/0020); an air-gapped operator mounts the JWKS and the
  lane goes dark with no loss of verification. Cluster data still never leaves (ADR-0018 stays
  the only outbound path for it).

What becomes harder / the downsides we accept:

- **Fail-closed is unforgiving, deliberately.** A misconfigured issuer, a wrong `aud`, or an
  unreachable JWKS locks operators out of their own dashboard (`401`/`503`) rather than serving
  the graph. That is the correct failure direction for a security tool, and the loud
  unconfigured-mode log (§6) plus the mounted-JWKS escape hatch (§5) are the pressure-relief.
- **Fail-open-on-exception is the one bug that reopens everything.** The single highest-risk
  line is the verifier's error path; it must deny on *every* error, including unexpected ones.
  This ADR names it so the implementation and its review treat it as the load-bearing invariant
  it is (a test that a thrown/`Err` verifier path yields deny, never allow, is mandatory).
- **Operators must run/point at an IdP.** Protector ships none; an operator with no OIDC issuer
  and no Cloudflare Access must stand one up (or knowingly run unconfigured, edge-trust-only,
  under the loud warning).

## Implementation follow-ups

These are **named, not numbered** here (their tracker ids are assigned when they are cut, to
avoid inventing numbers this ADR cannot confirm):

- **Verifier build** — the resource-server JWT verifier: configurable issuer, OIDC discovery +
  JWKS fetch with caching + key rotation, alg pinned to the issuer's asymmetric family,
  `iss`/`aud`/`exp`/`nbf`/signature checks, subject + configurable-tier extraction, and the
  mounted-JWKS air-gap source. Fail-closed on every error, with the fail-open-on-exception test
  as an acceptance gate.
- **Enforcement wiring** — the axum layer on `dashboard::router()` (alongside `set_csp`) that
  denies on verification failure across all routes (page, `/api/*.json`, assets), the loud
  unconfigured-mode log, and the Cloudflare-Access reference configuration (§7) as the first
  closing migration.
