# 0038. Transitive internet exposure through declared L7 routes

- Status: Proposed
- Date: 2026-08-01

## Context

[ADR-0012](0012-exposure-observed-or-declared.md) computes a workload's `Exposure` from
observation or a declaration, and explicitly defers L7 routing: *"Ingress/Gateway-API
exposure is likewise unmodeled and uses the same annotation until/unless a dedicated
observer is added."* Entries into the proof/adjudication lane are derived from
`Exposure::Internet` (`reason/proof/chain.rs`).

This leaves the **"proxy/exposure problem"** (the last VISION.md north-star residual; see
[the idea brief](../ideas/downstream-cve-exposure-boundary.md)): a backend one hop behind an
L7 forwarder (ingress controller, gateway, tunnel, reverse proxy) is treated as a
*downstream* node, so its own loaded-at-runtime CVE is context/severity only
([ADR-0034](0034-cut-choice-contract.md) §5), never a breach driver — even though the
attacker's crafted bytes arrive at that backend essentially verbatim.

The tempting fix — have a local model read the backend's code to judge whether attacker
input reaches the vulnerable function — is rejected in [ADR-0039](0039-downstream-cve-residual-no-llm-reads-code.md).
The real observation: for an **L7 forwarder**, "does attacker input reach this node?" is not
an application-dataflow question at all — it is a **deterministic routing-topology
question**. The edge is simply drawn one hop too early.

## Decision

**Exposure follows declared L7 routes.** A backend Service targeted by a route object whose
serving controller workload is itself `Exposure::Internet` (observed, or declared per
ADR-0012) inherits `Exposure::Internet`. This is computed **upstream of proof**, so a
route-forwarded backend becomes a normal **entry** and flows through the *existing* edge-CVE
promotion lane unchanged — same proof, prompt, `is_loaded_at_runtime` grounding,
anti-fabrication guards, containment menu, ledger, and bench. **No new evidence class and no
new model-claimable tag** are introduced (⇒ no new fabrication surface).

Rules:
- **Controller-anchored.** Propagation requires a live, internet-exposed controller/gateway
  workload actually serving the route — an orphan route object with no live controller does
  NOT propagate (closes the one over-promotion hazard).
- **One hop per route object; chains compose** — a backend promoted to an entry can itself
  anchor further routes it serves.
- **`enforceScope` and the annotation are unchanged.** The off-cluster declaration
  (e.g. cloudflared) still wins where there is no in-cluster route object; TLS
  termination vs. passthrough is irrelevant (attacker bytes arrive either way).
- **Fail direction: under-promote.** A missing/unbuilt observer means no propagation — the
  ADR-0012-accepted safe direction.

Scope: an **Ingress** observer first. A Gateway API (`HTTPRoute`) observer is added only if a
target cluster actually has the CRDs; otherwise it is not built.

## Consequences

- The tractable majority of the proxy/exposure residual is **discharged deterministically**:
  a route-forwarded backend's loaded CVE is now attacker-hittable evidence, grounded in a
  typed fact the model cannot invent — precisely what edge-CVE promotion already relies on.
- Zero change to the adjudication prompt for existing entries; zero new guard; the
  downstream-CVE cut trap and the minimality centerpiece are unaffected (verified by a
  deployed-pod bench per [ADR-0033](0033-cut-choice-judge-tier.md): a new route-forwarded
  fixture promotes via the entry lane, and the trap/centerpiece do not drift).
- **Entry-count growth**: an Ingress fanning to many backends adds entries to judge on the
  CPU budget — bounded by cluster size, decisive-verdict caching, and the wide-entry budgets;
  watch judge latency after rollout.
- Ships shadow-first automatically: new entries produce proposals only; the per-cut-class
  arming ladder ([ADR-0035](0035-per-cut-class-arming-ladder.md)) and the blast gate apply
  untouched.
- Retires ADR-0012's "Ingress/Gateway-API exposure is unmodeled" caveat for the Ingress case.
- The implementing change flips this ADR to Accepted.
