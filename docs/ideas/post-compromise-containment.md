# Idea brief — Contain at the boundary the evidence proves broken

**Status:** settled → ticketed via `/plan-sprint`. Load-bearing decisions recorded in
[ADR-0040](../adr/0040-node-scoped-containment-mechanism-escalation.md).

## The idea (as posed)

Three tickets were deferred from the model-as-incident-responder sprint
([ADR-0032](../adr/0032-model-is-incident-responder.md)) as needing their own design pass:

- **Node-level containment escalation** on pod-boundary-break evidence.
- **Post-compromise adversary-reach annotation** — a value-free *"if compromised, this pod
  grants the attacker …"* line composed from secret metadata + proven graph reach.
- **Auto-containment for model-judged internal-only incidents** off the internet path.

They were framed as one interlocking question: *what does protector do once the model
confirms an incident that has moved past, or off, the internet-facing entry path?*

## What the design pass found

The three are **not** a dependency spine. Only one is a real build; the other two do not
survive at their proposed size.

The single real problem underneath is a **unit mismatch**. Every cut in the north-star
vocabulary ([ADR-0032](../adr/0032-model-is-incident-responder.md)/
[ADR-0034](../adr/0034-cut-choice-contract.md)) is pod-scoped — a `podSelector`
`NetworkPolicy`. When typed evidence proves the adversary broke the **pod** boundary
(host-credential read, root + an escape primitive, ptrace/module-load kernel tamper), a
pod-scoped policy no longer bounds the compromise: a process in the host namespace is not
constrained by a `podSelector` at all. Protector would keep proposing a cut its **own
evidence** says cannot contain. Stated once:

> **The containment unit must be at least as large as the proven compromise unit — without
> moving the cut decision away from the model.**

## Recommended approach — deterministic mechanism escalation of a model-decided target

The model still decides *what* (`assessment=attack`, `contain=[X]`). A typed
boundary-break predicate escalates *how* for X — from pod-quarantine to node-containment.
The model keeps sole authority over what is an attack and which workloads are compromised;
determinism keeps sole authority over mechanism and rails, which is exactly where
[ADR-0034](../adr/0034-cut-choice-contract.md) D2 already puts it (*"mechanism is how"*).

### Approaches considered

- **A. Annotate-only, never escalate.** Cheapest, zero new RBAC — but leaves protector
  dishonest at its highest-stakes moment: it would keep proposing a pod `NetworkPolicy`
  its own typed evidence proves cannot contain. Solves nothing.
- **B. Model-driven node escalation** (node containment becomes a menu line the model may
  name). Superficially *"the model decides the cut"*; actually it hands the
  highest-blast-radius action to the model's weakest measured axis (the cut-set, per
  [ADR-0033](../adr/0033-cut-choice-judge-tier.md)) for zero authority gained — the exact
  Option-A error [ADR-0034](../adr/0034-cut-choice-contract.md) already rejected. The
  membership guard has no teeth here (a node line is legal by construction).
- **C. Deterministic mechanism escalation of a model-decided target** (recommended). The
  model names X; a typed `boundary_break(X)` predicate escalates the *mechanism* for X. The
  `node` class sits above `quarantine` on the arming ladder, propose-first by construction.

C is the only shape that fixes the unit mismatch while keeping every invariant intact. The
trusted surface stays small and is all existing machinery: model gate (decisive `attack`
naming X) ∧ typed-evidence gate (`boundary_break(X)`) ∧ blast/alive-collateral gate ∧
ladder rung ∧ `enforceScope`.

## Key decisions (see [ADR-0040](../adr/0040-node-scoped-containment-mechanism-escalation.md))

- **Node escalation is deterministic mechanism, never a model menu choice.** The resolver
  resolves a model-named workload X to `ContainNode` iff `boundary_break(X)` holds. The
  menu line renders the true mechanism + blast note (fixed strings) so the model sees what
  naming X does; the prompt fingerprint covers the escalation, so an evidence change that
  flips the predicate is a re-judge ([ADR-0023](../adr/0023-delta-aware-adjudication.md)
  preserved) and the cut-signature replay-lock ([ADR-0034](../adr/0034-cut-choice-contract.md)
  D8) cold-re-judges rather than silently repointing.
- **Trigger set — typed evidence only, no substrings** (all already produced by `observe/`):
  (a) host-path `SecretRead` on X (host-credential class); (b) `PrivilegeChange` to uid 0
  on X **and** X carries an `EscapesTo` edge (either alone is not a break); (c)
  `PtraceAttach` or `ModuleLoad` on X (kernel tamper); (d) ≥2 workloads on one `Host` node,
  each with a decisive model `attack` naming it **and** actively-exploited live evidence
  (determinism composing two model decisions, not replacing one). (d) needs one new
  metadata fact: a pod→node placement edge for *all* pods (today only escape-primitive pods
  get a Host edge) — metadata-only, no RBAC.
- **Node containment = cordon (`Node.spec.unschedulable`) + per-pod default-deny of the
  node's co-resident labelled pods.** Honest rationale on the surface (fixed strings):
  after a proven host-level break *no* `NetworkPolicy` constrains the adversary; the cordon
  stops scheduler-driven spread, the co-resident denies stop lateral use of the node's
  other pods, and the durable fix (drain / reimage / rotate) is a **human** act. This is
  damage-limitation and the UI must not pretend otherwise.
- **`ProposedAction::ContainNode`: reversible, its own action class, propose-first by
  construction.** Cordon is a shared-field mutation (not an additive engine-owned object),
  so the class is never blanket-auto: a real node always has alive collateral, so the
  existing blast/alive-collateral gate routes every node cut to human approval even at the
  armed rung. Deterministic rails: never a control-plane node; ≤1 node cordoned
  concurrently; refuse if it would leave <2 schedulable workers; cordon carries an engine
  ownership annotation and revert only uncordons nodes carrying it (never fight a human or
  autoscaler). Joins [ADR-0036](../adr/0036-break-glass-disarm.md)'s armed-set revert.
- **Ladder: rung 3 `node`, strictly above `quarantine`** (edge-cut < quarantine < node) —
  one ordered position, no new toggle. RBAC (`nodes` patch, cluster-scoped) rendered only
  when `mode: enforce` ∧ rung = `node`; an audit install keeps zero write grants. Chart
  change + manual port to the diverged cluster-chart fork.
- **Split: trigger + proposal surface first** (shadow, no RBAC, no chart), **actuator
  second.** The proposal surface alone is most of the value — the incident detail stops
  proposing a known-ineffective pod cut and starts proposing the honest one.

## What we are explicitly NOT building

- **Adversary-reach as judge context** (the original reach-into-the-prompt shape).
  *Context-not-evidence*
  ([ADR-0029](../adr/0029-adjudication-verdict-is-authoritative.md)) is enforced by
  **absence** — the only guard with no failure mode. Prior fabrication findings show a 1.7b
  judge converts scary context lines into fabricated breach evidence, and
  [ADR-0034](../adr/0034-cut-choice-contract.md) already pins `contain` to exactly the
  evidence-bearing set, so there is no legitimate discretion for reach-context to inform.
  Instead the reach line ships as a **presentation annotation only** — a closed-vocabulary
  secret-*purpose* inference (from secret name / `type` / mount metadata, never `.data`)
  plus the node's already-computed assume-breach reach — rendered in finding detail, MCP,
  and the notifier via the existing scrub inventory
  ([ADR-0018](../adr/0018-operator-configured-redacted-breach-notifier.md)/
  [ADR-0031](../adr/0031-read-only-mcp-server-tiered-redaction.md)). No bakeoff, no prompt
  change. Revisit only if a future ADR relaxes the exact-evidence-set instruction.
- **Auto-containment off the internet path** (the original off-path auto lane). Won't-build.
  [ADR-0032](../adr/0032-model-is-incident-responder.md) §6 is reaffirmed, now stronger:
  [ADR-0038](../adr/0038-transitive-internet-exposure-l7-routes.md) moved the
  honestly-reachable "internal" pods into the entry lane, and trigger (d) covers the
  scariest genuinely-internal case (multi-pod spread) through the incident that *did* have
  a path. The deterministic propose-only lane already gives operators a reviewable
  proposal. Nobody has asked (the ticket's own bar: *revisit only if operators ask*).
- **Drain / evict, CNI-level node fencing, kubelet credential revocation** — the human
  runbook, linked from the proposal surface, not automated (VISION: eviction is never
  automatic).
- **A model-selectable node menu line** — revisit only under
  [ADR-0034](../adr/0034-cut-choice-contract.md)'s incomparable-mechanisms condition, which
  this design deliberately avoids creating.

## Rough shape & sequence

1. Placement fact (pod→node map) + `boundary_break` predicate module (typed, four
   triggers) + tests. Small, pure, no surface change.
2. `ContainNode` action + resolver escalation in the menu/ledger (same code path) +
   proposal surface (fixed strings, honest damage-limitation copy) + journal/bench fixture.
   Shadow-complete.
3. Actuator: cordon renderer + co-resident deny set + rails (control-plane / one-node /
   floor / ownership) + rung 3 + posture-derived RBAC + chart, then the manual fork port.
4. Reach annotation (573-lite): purpose-category inference + reach line, dashboard / MCP /
   notifier + scrub tests. Independent; can land any time or slip without blocking 1–3.

Bench: one new cut-choice fixture (boundary-broken downstream → model names X, no over-cut
of neighbors), run on the deployed pod per
[ADR-0033](../adr/0033-cut-choice-judge-tier.md) (local arm64 diverges on the cut-set).

## HANDOFF TO PLAN-SPRINT

Theme: **"contain at the boundary the evidence proves broken."** Plan against one real
build (node containment as a deterministic mechanism escalation of model-decided targets —
trigger + proposal surface in shadow first, then the node actuator + rung 3 + RBAC/chart
port) plus one small presentation feature (the adversary-reach annotation, no judge
involvement), with the off-path auto-containment lane closed as a recorded won't-build.
Panel: **architect + devops** — infra/graph/resolver/actuator/RBAC/chart work; no
product-surface change beyond the proposal copy, one annotation line, and the new action
class.
