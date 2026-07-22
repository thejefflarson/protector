# 0031. A read-only, tiered-redaction MCP server: the second sanctioned egress carve-out

- Status: Proposed
- Date: 2026-07-22
- Relates to: [0014](0014-behavioral-telemetry-ebpf.md)/[0015](0015-advisory-evidence-egress.md) (the in-cluster, zero-egress posture this carves a second, bounded exception to), [0018](0018-operator-configured-redacted-breach-notifier.md) (the direct lineage — operator-owned, redacted-by-default, one sanctioned egress; this ADR generalizes that carve-out from *push* to *pull*), [0016](0016-severity-vs-urgency.md) (presentation is a **view, never a gate**, and the engine is **shadow-first** — a read surface cannot become an actuation surface), [0020](0020-signature-continuity.md) (the signing inventory the `signing_inventory` tool exposes), [0025](0025-dashboard-v4-preact-client-render.md) (the read-only, same-origin JSON snapshot this reuses as the tools' data source). **Depends on ADR-0030** (the OIDC token verifier), referenced by number — its file lands on the sibling branch (JEF-483).

## Context

An operator increasingly wants to point an assistant or agent at protector and ask
the questions they already ask the dashboard: *why is `X` flagged? am I blind on this
node? is this verdict fresh, or stale from before the last restart?* Today there is no
programmatic surface for that. The choices are all bad: hand the assistant the raw
secret inventory and the peer-by-peer graph (a crown-jewels dump), build a bespoke
one-off integration per operator, or — worst — expose anything that can *act*.

There is no recorded decision on **how a read-only, machine-facing surface may emit
graph-derived data without breaking the invariants**. Two are in tension:

1. **Zero egress** ([ADR-0014](0014-behavioral-telemetry-ebpf.md)/
   [0015](0015-advisory-evidence-egress.md)): the security graph and its evidence —
   topology, secret names, peer reachability, the CVE inventory — **never leave the
   cluster**. An MCP response travels to the operator's LLM provider; that *is* egress.
2. **Redacted-by-default operator-owned egress** ([ADR-0018](0018-operator-configured-redacted-breach-notifier.md)):
   we already carved **one** sanctioned outbound path — the breach notifier — and the
   shape of that carve-out (off by default, redacted by default, operator owns the
   sink's trust, richer detail is a bounded explicit opt-in) is the pattern to extend,
   not reinvent.

A third force is structural: the standardized way an assistant consumes a tool surface
today is **MCP**. The question is not *whether* to speak MCP but *where the redaction
boundary sits relative to the transport*, and *how a request is authenticated to a real
human* so a tier and an audit line can bind to a subject the operator's IdP governs.

The non-negotiable frame: this surface is **read-only by construction**. The engine is
shadow-first and presentation is a view, never a gate
([ADR-0016](0016-severity-vs-urgency.md)); a machine-facing read surface must inherit
that exactly. An assistant may *explain* protector's state; it may never *act* on
protector's behalf.

## Decision

We will build a **read-only, tiered-redaction MCP server** as a **second sanctioned
egress carve-out**, the pull-side sibling of the [ADR-0018](0018-operator-configured-redacted-breach-notifier.md)
push notifier. It reuses that ADR's exact posture: off-by-default for anything beyond
the safe-by-construction tier, redacted by default, operator-owned trust, richer detail
as a bounded, journaled, explicit opt-in.

### 1. Read-only ONLY — no actuation tool exists, by construction

The server exposes exactly **four** tools, all pure reads over the state the engine
already computes:

- **`list_findings`** — the current findings snapshot (verdicts + the fields the active
  tier permits).
- **`explain_verdict`** — the *why* behind one entry's verdict (the adjudication
  reasoning, at the depth the tier permits).
- **`get_coverage`** — runtime-coverage / freshness: is protector blind on a node, and
  how stale is what it last saw (the [JEF-421](0018-operator-configured-redacted-breach-notifier.md)/JEF-427 signal, read-side).
- **`signing_inventory`** — the [ADR-0020](0020-signature-continuity.md) signing
  posture: which images are signed, by whom, and where continuity regressed.

There is **no** `isolate`, `arm`, `quarantine`, `patch`, `apply`, `revert`, or any tool
that mutates cluster or engine state. This is not a permission we withhold at runtime —
**no such tool is defined**, so no token, tier, or prompt-injection can reach one. The
view-never-a-gate and shadow-first invariants ([ADR-0016](0016-severity-vs-urgency.md))
are preserved verbatim: the LLM cannot act on protector's behalf, only report what
protector decided. Actuation stays exactly where it is — the engine's own reversible,
blast-radius-gated cut, gated by `arm` ([ADR-0021](0021-two-setting-operating-posture.md)) —
untouched by this surface.

### 2. Tiered redaction, redacted-by-default

Every tool response is redacted to one of three tiers. The default is the most
restrictive; each higher tier is strictly additive.

- **`redacted`** (default) — verdict, **sanitized** reason, objective **COUNT** (never
  the per-objective list), ATT&CK technique IDs, coverage, and freshness. **No** secret
  names, **no** CVE ids, **no** paths, **no** topology. This is the same shape
  [ADR-0018](0018-operator-configured-redacted-breach-notifier.md)'s default notifier
  payload draws.
- **`forensic`** — adds the judgement **prompt + reply**, **CVE ids + reachability
  tags**, and **paths**. Secret **names are still scrubbed**. This is the tier that
  answers "*why*, in detail" — the evidence the model reasoned over, minus the names of
  the secrets themselves.
- **`raw`** — adds the **actual secret names**. There is **no tier that emits secret
  VALUES.** Values have no unlock tier and are never rendered by any tool at any tier;
  the server has no code path that reads a secret's value into a response. `raw` is
  "which secrets", never "what they are."

The tier is a **CEILING**, derived server-side from a **verified token claim** (§5),
and enforced server-side. A tool argument may *request* a tier, but the requested tier
is clamped to `min(requested, ceiling)` — the argument can only ever narrow, never
widen. A client cannot self-elevate by asking; the ceiling is the operator's IdP
grant, not the caller's assertion.

Redaction is **per-entry**, applied to each finding as it is serialized — **never** a
bulk dump that is redacted afterward. There is no code path that assembles the raw
inventory and then filters; each entry is scrubbed to the active tier at the point it
enters the response.

### 3. Redaction is server-side, in-cluster, BEFORE egress — so protector is the remote HTTP MCP server

Because the MCP response *is* egress to the operator's LLM provider, the redaction must
happen **inside the cluster, before a single byte leaves**. That single fact settles the
topology: a local **stdio** MCP bridge (the assistant shells out to a local process that
proxies to protector) would redact **too late** — either the bridge pulls raw data
across the cluster boundary to redact it outside (the leak we are preventing), or it is
one more trusted component to build and secure. Therefore **protector itself is the
remote MCP server, spoken over HTTP**, and redaction is a first-class step in its own
response path, below no external boundary.

The scrubbers are the [ADR-0018](0018-operator-configured-redacted-breach-notifier.md)
lineage — `sanitize` / `scrub_decision_names` / `scrub_cve_tokens` — **lifted and
generalized** from their current private home in `engine/src/engine/notify.rs` into a
shared redaction module a sibling ticket extracts. The MCP server and the notifier then
share **one** redaction implementation, so the two egress paths cannot drift in what
they consider safe. The tiers above are expressed as which scrubbers run: `redacted`
runs all of them, `forensic` relaxes the CVE/path scrubbers, `raw` relaxes the
name scrubber — and **none** of them ever relaxes a secret-**value** scrubber, because
no such value is ever read.

### 4. `redacted` is safe-by-construction; `forensic`/`raw` are genuine egress — off by default, opt-in, journaled

The tiers split cleanly along the egress boundary:

- **`redacted` is safe-by-construction.** After the scrubbers run, **nothing
  cluster-specific remains** — no name, no CVE, no path, no topology, only verdicts,
  counts, technique IDs, and coverage/freshness. It is the same "no untrusted cluster
  string to leak" property [ADR-0018](0018-operator-configured-redacted-breach-notifier.md)'s
  redacted default and its JEF-427 counts-only extension rely on. This tier is **on by
  default** and needs no per-tier opt-in.
- **`forensic` and `raw` are genuine cluster-data egress.** A CVE id, a path, a
  judgement prompt, a secret name — these are cluster facts. Emitting them is exactly
  the eyes-open choice [ADR-0018](0018-operator-configured-redacted-breach-notifier.md)
  drew for the notifier sink. So they are:
  - **OFF by default.** A fresh install grants nobody above `redacted`.
  - **Opt-in.** A `forensic`/`raw` ceiling is a grant the operator makes deliberately at
    their IdP (§5), the same shape as an operator pointing the notifier URL off-cluster.
  - **Journaled.** Every response above `redacted` appends an audit line —
    **subject · entry · tool · tier · time** — so the operator can always answer "who
    saw which cluster fact, when." (The `redacted` tier, having nothing cluster-specific
    to disclose, does not require the entry-level line.)
  - **Operator-owned trust.** The operator owns where the response goes. Pointed at a
    **fully local / in-cluster LLM**, even `raw` keeps the deployment **zero-egress-pure**
    — the crown jewels never leave the cluster boundary. Pointed at a third-party
    provider, a `raw` grant is the operator's explicit, recorded, eyes-open decision —
    the identical trade [ADR-0018](0018-operator-configured-redacted-breach-notifier.md)
    documented and could not enforce.

### 5. Auth via the ADR-0030 verifier, single-pathed; ID-JAG discovery for zero-touch enterprise auth

Authentication and authorization go through **one** path: **ADR-0030's OIDC token
verifier**. There is no second auth mechanism, no MCP-specific bypass, no API-key side
door. The verifier establishes the **real human subject**; the tier ceiling (§2) and the
audit line (§4) bind to **that subject**, and governance of who may reach `forensic`/`raw`
lives at the **operator's IdP** — not in protector config.

For zero-touch enterprise auth we adopt **ID-JAG / MCP enterprise-managed authorization**
(stable 2026-06-18). Protector advertises a **`.well-known/oauth-protected-resource`**
document and answers an unauthenticated request with a **`WWW-Authenticate` challenge**,
so an ID-JAG-capable client (Claude, VS Code) runs the token exchange **automatically** —
the operator adds the server URL and the client + IdP negotiate the rest. Protector is
the *protected resource*; it does not mint or broker tokens, it *verifies* them via
ADR-0030 and maps the verified claim to a tier ceiling.

### 6. Transport: RMCP mounted BEHIND our verifier — trust decisions stay in-tree

We will use **RMCP (the official Rust MCP SDK)** for the **streamable-HTTP transport**
and the protocol/auth handshake, **mounted as an axum/tower service behind protector's
OIDC verifier layer**. Auth is enforced by *our* verifier middleware **before** a request
reaches any rmcp handler, so authentication stays **single-pathed and ours** (§5). rmcp
is **transport plumbing below the trust boundary**: it frames JSON-RPC, negotiates the
protocol, and speaks the discovery/challenge dance — it makes **no** trust decision.
Every trust decision — **verify the token, compute the tier ceiling, redact the
response** — stays **in-tree**, above rmcp, in code we own and test.

Rationale, recorded because it is a genuine build-vs-adopt call
([ADR-0006](0006-build-vs-adopt.md) territory): the tension is **minimal-trusted-surface**
(hand-roll JSON-RPC, own every line, no third-party protocol code in the request path)
**vs. owning a moving protocol** (MCP's transport, discovery, and enterprise-auth
handshake are evolving; re-implementing them by hand is exactly the undifferentiated,
drift-prone work an SDK exists to absorb). The **deciding factor** is §3: because
redaction must be server-side, **protector must be the remote HTTP MCP server** — which
is precisely the transport-and-handshake layer where an SDK earns its keep, and where a
hand-rolled version would be the most code for the least differentiation. rmcp handles
the plumbing; our verifier and redactor keep every decision that matters.

**Fallback, recorded:** if rmcp **cannot compose behind our verifier** — if mounting it
as a tower service below our OIDC middleware proves infeasible, or if it insists on
owning auth — we **fall back to a hand-rolled JSON-RPC surface** rather than move a
single trust decision out of our layer. Single-pathed, in-tree auth is the invariant;
rmcp is adopted only for as long as it respects it.

## Consequences

Easier / better:

- An operator can point a governed assistant at protector and get honest, scoped answers
  to "*why flagged / am I blind / is it fresh / who signs this*" — **without** a bespoke
  integration, **without** handing over the raw inventory, and **without** any path that
  can act.
- The zero-egress posture holds as the **default**: `redacted` is safe-by-construction,
  and the only cluster-data egress is opt-in, journaled, and (against a local LLM)
  zero-egress-pure. This is [ADR-0018](0018-operator-configured-redacted-breach-notifier.md)'s
  carve-out generalized from push to pull, not a new hole.
- One redaction implementation serves both egress paths (notifier + MCP), so "what is
  safe to emit" can't diverge between them.
- Auth is single-pathed through ADR-0030 and governed at the operator's IdP; tier and
  audit bind to a real human, with zero-touch enterprise onboarding via ID-JAG.

Harder / accepted:

- **The operator owns the destination's trust.** A `forensic`/`raw` grant against a
  third-party LLM is genuine crown-jewels egress; we redact by default, tier by verified
  claim, journal every disclosure, and document the local-LLM zero-egress-pure path — but
  we **cannot enforce** where the operator points the assistant. This is the identical
  limit [ADR-0018](0018-operator-configured-redacted-breach-notifier.md) accepted.
- **A third-party protocol lives in the request path.** rmcp is transport plumbing, but
  it is still someone else's code below our boundary; we accept it only *behind* our
  verifier, with the hand-rolled fallback recorded if it won't compose there.
- **Redaction correctness is now load-bearing for egress, not just presentation.** A bug
  in a scrubber leaks a cluster fact to an LLM provider. The mitigations are the shared,
  tested redaction module, per-entry (never bulk) application, and the structural
  guarantee that secret **values** have **no** read path at all.

## Alternatives considered

- **A local stdio MCP bridge.** Rejected (§3): it redacts too late — either it pulls raw
  data outside the cluster to filter, or it is one more trusted component. Redaction must
  precede egress, so protector must be the remote HTTP server.
- **Any actuation tool, even guarded.** Rejected (§1): it would make a read surface an
  actuation surface, breaking view-never-a-gate / shadow-first
  ([ADR-0016](0016-severity-vs-urgency.md)). No such tool is defined, so none can be
  reached.
- **A single "full detail" mode gated only by auth.** Rejected (§2/§4): it conflates
  "authenticated" with "cleared to see cluster crown jewels" and removes the
  safe-by-construction default. Tiers with a server-enforced ceiling keep `redacted` the
  default and make `forensic`/`raw` a deliberate, journaled grant.
- **A tier that can emit secret values.** Rejected (§2): secret values have no
  operational reason to reach an assistant and are the highest-consequence leak. There is
  no unlock tier; no tool reads a value into a response.
- **A second, MCP-specific auth path (API keys / bearer tokens minted by protector).**
  Rejected (§5): it would fork auth and put governance in protector config instead of the
  operator's IdP. One verifier (ADR-0030), one path, subject-bound tier and audit.
- **Hand-roll the whole JSON-RPC/MCP surface from the start.** Not chosen as the default
  (§6): MCP's transport + enterprise-auth handshake is a moving target, and §3 forces us
  to be the remote HTTP server — the exact layer an SDK is worth adopting. Kept as the
  **fallback** if rmcp cannot compose behind our verifier.
