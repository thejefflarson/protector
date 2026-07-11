# 0002. Change-driven incident loop: diff the cluster, prove the delta, manage the debt

- Status: Accepted
- Date: 2026-06-11

## Context

[ADR-0001](0001-async-mitigation-engine.md) decided *that* protector grows an
async engine that proposes, proves, and responds, local-first. It left open the
question this ADR answers: **what is the unit of work, and what loop runs on
it?** "Scan the whole cluster periodically and reason about everything" is the
obvious answer and the wrong one — it is expensive, it re-derives facts that did
not change, and it gives a small local model the worst possible task (reason
about the entire topology at once) instead of its best one (reason about a small,
local neighborhood that just changed).

The real generator of risk is **change**. A cluster that does not change does not
develop new attack chains. Risk appears the moment something moves: Argo syncs a
new manifest, a CVE is disclosed against an already-running image, someone edits a
NetworkPolicy or grants an RBAC binding, a node joins, Falco sees a new syscall
pattern. Each of these is a **delta** against a known-good prior state. A delta is
small, it is attributable to a cause, and — critically — it bounds the search
space: the only attack chains worth re-examining are the ones that *use an edge
the delta added or strengthened*. Everything else was already accounted for in
the prior pass.

This reframes the five operational questions the platform must answer, and ties
each to a stage of a loop that fires **on a change**, not on a timer:

1. **How does the threat model change?** — the delta to the attack surface.
2. **Are there new, provable, real attack chains?** — proven chains that ride the
   delta.
3. **What do alive / degraded / halted look like, and are the levers accurate?** —
   the health model that both *guards* a response and *verifies* it landed.
4. **What config changes prevent this going forward?** — the durable fix, as a
   GitOps change.
5. **As posture improves, what mitigating controls roll back?** — retirement of
   compensating controls whose justification is gone.

Two further forces shape the design. First, cluster definitions live in **GitOps
(Argo first)** — so any live action the engine takes will be seen as drift and
fought by the reconciler unless the engine is Argo-native by construction.
Second, the model budget must be governed by **stakes, not difficulty**: a
convoluted chain that a tiny model surfaces and the proof layer confirms is
*done* — it never needs a frontier model. A frontier model is worth paying for
only when we are about to pull an expensive, hard-to-reverse lever on production.

## Decision

We will build the engine as a **change-driven differential loop** over a living
model of the cluster, with mitigations treated as **explicit, self-retiring
debt**. The unit of work is a `ClusterDelta`. Two operating modes — **proposed
alerts (easy)** and **active remediation (hard, Argo-native)** — share one
analysis pipeline and differ only in what they are permitted to *do* with its
output.

### The cluster security graph, and the delta against it

We maintain a **cluster security graph (CSG)**: nodes are workloads, identities
(ServiceAccounts / RBAC subjects), secrets, network endpoints, images, and nodes;
edges are *reachability* (Linkerd authz + NetworkPolicy), *privilege* (RBAC
`can-i`), *trust* (is this image signed?), and *data access* (mounts secret X).
Nodes carry facts: vuln reports (trivy ∧ grype), KEV/EPSS, signature status,
live Falco activity. The CSG is the threat model, made concrete and queryable.

The graph tracks **observed cluster state, not desired (git) state** — this is
load-bearing. Reality diverges from git constantly and legitimately: self-hosted
Actions runners create and destroy pods by the minute with no commit per pod, a
mutable tag resolves to a new image digest with no manifest change, a CVE is
disclosed against an image that has run untouched for weeks, an HPA scales, an
operator reconciles, someone `kubectl edit`s during an incident. An engine that
diffed git commits would be blind to every one of those. So the graph is fed by
**watching the live cluster** — API-server informers, runtime events (Falco),
periodic image-digest re-resolution, and new vulnerability reports — and git is
relevant only later, as the place a *durable fix* is proposed (Q4).

A `ClusterDelta` is a set of node/edge mutations against this observed graph plus
the **event that caused it**, sourced from those watch streams regardless of
whether a human, Argo, an operator, or an ephemeral runner triggered it. Every
loop iteration is triggered by one delta. **Question 1 is a deterministic graph
diff:** recompute exposure only for the changed neighborhood, and emit a *threat
delta* — the capabilities added or removed (new entry points, newly reachable
secrets, newly granted privilege), each attributed to the change that caused it.
No model is involved in Q1.

### Prove only the chains the delta enabled

**Question 2 is the propose/prove spine of ADR-0001, scoped to the delta.** The
hypothesis engine proposes only chains that traverse at least one
added-or-strengthened edge; the proof layer confirms each link deterministically
(reachability by graph query, privilege by `can-i`, exploited-in-wild by KEV/EPSS,
presence by trivy ∧ grype, "now" by Falco) or drops it. A chain is *real* at the
action bar when it is **reachable ∧ exploited-in-wild ∧ privileged ∧
runtime-corroborated**. Because the CSG is a real graph, proof extends to
**counterfactuals**: the **minimal cut** — the single edge whose removal breaks
the proven chain — is computed deterministically, and *that* is the action
candidate. The same machinery runs **predictively**: replay a proposed GitOps
change against the CSG *before merge* to answer Q1/Q2 for a change that has not
happened yet. That is the bridge back to the webhook — the engine can sit in a
**PR / CI gate**, shifting the whole loop left of admission.

### Health is both the guard and the proof that a lever pulled

**Question 3 makes the levers trustworthy.** Each service (and the cluster) has an
observable state derived from SLOs: **alive** (within error budget), **degraded**
(burning budget but serving), **halted** (budget blown / not serving). This state
does two jobs. As a **guard**, no automated action may fire if its predicted
effect pushes a *protected* service toward `halted`. As a **proof**, every action
is a closed-loop control, not fire-and-forget:

1. Predict the effect as a counterfactual on the CSG (which flows die).
2. State a **blast-radius assertion** before acting: *only* flows X die; named
   protected services stay `alive`.
3. Apply, then **measure** against the assertion inside a window — including an
   **active probe** that tries the severed connection from a canary and expects
   refusal (trust the lever by testing it, don't assume the apply worked).
4. If measured ≠ predicted — a protected service degrades, or the cut didn't
   actually cut — **auto-revert** and drop the action class to notify-only.

This is how we are "sure the levers are accurately pulled": each lever carries a
pre-stated hypothesis and is verified against it, and disagreement self-heals.

### Durable fixes are GitOps changes; live actions are Argo-native

**Question 4 has two horizons, and the live one must not fight the reconciler.**
The minimal cut from Q2 is the *immediate* stopgap, applied to the live cluster;
the *durable* fix is a change to desired state in git (a tightened NetworkPolicy /
AuthorizationPolicy, a revoked RBAC binding, an image pin or bump, a resource
limit), proposed as a PR for a human to merge. The decisive choice for the live
action: **the engine applies an additive, engine-owned object directly** — a new
scoped `AuthorizationPolicy` or deny `NetworkPolicy`, a new RBAC object, labeled
`managed-by: protector` — never an *edit* to a git-managed resource. Argo only
reconciles resources it tracks; net-new objects it has never seen, it leaves
alone. So additive mitigations coexist with Argo without a drift war, and the
dead-man revert is a direct delete of the engine's own object. Git is for the
*proposed durable fix*, not the mechanism of live action — which keeps detection
and live response grounded in observed cluster state, with git entering only as a
suggested correction to desired state.

The two modes diverge exactly here:

- **Easy mode (proposed alerts)** — read-only on the cluster, read on Git. Emits
  the threat delta (Q1), proven chains (Q2), health context (Q3), a proposed
  **durable-fix PR** (Q4), and proposed **rollback PRs** (Q5). It never touches
  the cluster. This is the default and the long bake.
- **Hard mode (active remediation)** — additionally applies the minimal-cut
  mitigation as an engine-owned object on the live cluster, verifies it via the
  Q3 closed loop, and auto-reverts by deleting that object on dead-man timeout or
  health regression, while opening the durable-fix PR in parallel. Armed per
  action-class, per-namespace, behind the bake. Destructive actions (eviction,
  scale-to-zero) are never auto-armed.

### Mitigations are debt; the active set is a function of the proven chains

**Question 5 is the mirror of Q4.** A live mitigation is a *compensating control*
standing in for a fix that has not landed — it is debt, and left in place it
becomes cruft that carries its own risk and hides whether the real fix works.
Every mitigation is written to a **ledger** with the chain it broke (its
justification), the edge it severed, and a **retirement predicate**: the
deterministic condition under which it is no longer needed (the proven chain no
longer exists in the CSG — because the CVE was patched, the binding removed, the
workload retired). The loop continuously re-evaluates predicates; when one goes
true, the mitigation is **proposed for rollback** (easy mode) or **auto-reverted**
once the durable fix is confirmed present *and* the chain confirmed gone (hard
mode).

This yields the invariant that ties the whole platform together:

> **The set of active compensating controls is exactly the set whose justifying
> attack chain is currently proven.** Add a control when a chain appears; remove
> it when the chain is gone. Both directions gated by the same deterministic
> proof.

The webhook floor and the GitOps durable fixes are the permanent layers;
mitigations are an ephemeral, self-managing layer that exists only while debt is
outstanding. Posture improving *is* chains disappearing *is* mitigations
retiring.

### Model tiering is governed by stakes, not difficulty

- **Tier 0 — deterministic, always on.** Graph diff (Q1), proof and minimal cut
  (Q2), health assertions (Q3), retirement predicates (Q5). Most deltas resolve
  here with no model at all (a deploy that adds no reachable-privileged-exploited
  edge produces no chain and no work).
- **Tier 1 — local small model, per interesting delta.** Hypothesis generation
  scoped to the delta neighborhood, ranking, and the human narrative. Cheap,
  private, temperature 0, constrained JSON decoding, handed deterministic tools
  (`is_reachable`, `can_i`, `kev_lookup`) rather than asked to reason about
  topology. Weakness here costs rejected hypotheses, never a bad action.
- **Tier 2 — frontier, rare, gated on consequence.** Fires only when a chain is
  *already proven* **and** the stakes are high: critical severity, or a proposed
  auto-action whose blast radius touches a protected service. Its job is to
  adjudicate the **judgment call on pulling an expensive lever**, on redacted
  input (structured graph + CVE IDs, never raw secrets), human-in-the-loop. It is
  not used to *find* chains — proof does that. A tiny model surfacing a convoluted
  but provable chain is finished work; escalation buys a second opinion on
  *consequence*, which is exactly where it is worth the cost. Frontier spend is
  therefore bounded by the count of proven critical chains — a tiny, budgetable
  number, because Tier 0 is the filter, not the model.

### Rollout

Shadow-first, as in ADR-0001. The deterministic walking skeleton ships with **no
model and easy mode only**: CSG, graph diff, proof, minimal-cut computation, and
the ledger — all emitting PRs and alerts, touching nothing. Tier 1 is added to
write narratives and rank. Hard mode is armed last, one reversible action class
and one namespace at a time, only after a bake that measures false-positive rate
and confirms the Q3 closed loop reverts cleanly on injected faults.

## Consequences

Easier:

- The unit of work is small and attributable, which makes the loop cheap and
  makes a weak local model *good* — it reasons about a delta neighborhood, its
  best case, never the whole cluster.
- The five operational questions become five stages of one pipeline with clean
  hand-offs, rather than five separate features.
- Active remediation stops fighting Argo without going through git: live actions
  are additive, engine-owned objects Argo never tracked, so the reconciler leaves
  them alone and the revert is a direct delete.
- Detection is grounded in observed reality, so it sees the changes git never
  records — runner churn, mutable-tag digest drift, CVEs against running images,
  hand edits — which is most of what actually generates risk.
- Mitigation cruft is solved by construction — controls retire themselves when
  their justifying chain is gone, so posture improvement is self-cleaning.
- The same proof machinery runs predictively in a PR gate, shifting analysis left
  of admission and reconnecting the engine to the webhook floor.
- Frontier cost is governed by consequence and bounded by proven critical chains —
  cheap by design, not by rationing.

Harder / accepted downsides:

- The **observed-state graph** is now core infrastructure: built from watch
  streams, kept fresh against the live cluster, and reconciled after the engine
  restarts or misses events. A stale graph produces wrong cuts; freshness is a
  first-class correctness concern, not a cache detail. Tracking observed (not
  desired) state makes this *harder* than reading git — it means real informers,
  digest re-resolution, and resync-after-gap — but it is the only state that is
  true.
- The engine needs **live cluster write access** (apply and delete its own
  mitigation objects) on top of ADR-0001's reads — a sensitive credential scoped
  to a narrow set of object kinds and to the `managed-by: protector` label.
- **Engine-owned objects must not collide with git-managed ones.** Coexistence
  with Argo holds only as long as mitigations stay strictly additive; an edit to
  a tracked resource would start a drift war. This is a discipline the action
  layer must enforce, not a property it gets for free.
- The engine needs **PR-only write access to the GitOps repo** for proposed
  durable fixes and rollbacks — narrower than commit-to-main, but still a
  credential to scope.
- The Q3 closed-loop verification depends on **trustworthy SLO signals and a
  working canary prober**; bad telemetry makes a good lever look broken (needless
  revert) or a bad one look fine (the dangerous case). Telemetry integrity is now
  on the critical path.
- It is **more system, not less** — a graph store, a diff engine, a ledger, a
  GitOps committer, a prober — phased strictly behind the easy-mode skeleton.
- The small-cluster bound from ADR-0001 still holds: differential scoping widens
  the practical ceiling but does not make multi-hop chain proving scale to
  thousands of workloads. Accepted.
