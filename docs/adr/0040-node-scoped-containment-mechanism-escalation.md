# 0040. Node-scoped containment is a deterministic mechanism escalation of a model-decided target

- Status: Proposed
- Date: 2026-08-01

## Context

The north star ([ADR-0032](0032-model-is-incident-responder.md),
[ADR-0034](0034-cut-choice-contract.md)) is complete for the on-path case: the model names
the compromised workloads (`assessment=attack`, `contain=[node-key]`), determinism resolves
each to its narrowest reversible cut, and the arming ladder
([ADR-0035](0035-per-cut-class-arming-ladder.md)) + break-glass
([ADR-0036](0036-break-glass-disarm.md)) + freshness gate
([ADR-0037](0037-shadow-bake-arm-readiness.md)) govern actuation. But every cut in the
vocabulary is **pod-scoped** — a `podSelector` `NetworkPolicy`
([ADR-0010](0010-flannel-actuator-workload-isolation.md),
[ADR-0022](0022-quarantine-the-entry-is-the-default-containment.md)).

There is one shape this cannot contain, and protector's own evidence proves it: when typed
runtime evidence shows the adversary broke the **pod** boundary — a host-credential read, a
root escalation paired with a container-escape primitive, or a kernel tamper
(ptrace-attach / module-load) — a process in the host namespace is not constrained by a
`podSelector` policy at all. Protector would keep proposing a pod cut that its own evidence
says cannot work. The containment **unit** (pod) is smaller than the proven compromise
**unit** (node).

Three tickets were deferred from the model-as-incident-responder sprint to a design pass on
this frontier: node-level escalation, a post-compromise adversary-reach annotation, and
auto-containment for internal-only incidents off the internet path. The design pass
(`docs/ideas/post-compromise-containment.md`) found only the first is a real build; the
other two are settled here as a shrink and a won't-build.

## Decision

**The containment unit must be at least as large as the proven compromise unit — without
moving the cut decision away from the model.** Node containment is a **deterministic
mechanism escalation** of a target the model already decided, never a new choice handed to
the model.

1. **The model decides *what*; determinism escalates *how*.** The model's contract is
   unchanged ([ADR-0034](0034-cut-choice-contract.md) — `assessment` + `contain`). The
   resolver resolves a model-named workload X to `ProposedAction::ContainNode` **iff**
   `boundary_break(X)` holds; otherwise X resolves to its existing pod-scoped cut. This is
   the same menu/ledger code path, so the proposal surface and the actuation cannot
   disagree. We reject a **model-selectable node menu line**: it would hand the
   highest-blast-radius action to the model's weakest measured axis (the cut-set, per
   [ADR-0033](0033-cut-choice-judge-tier.md)) for no authority gained, and the membership
   guard has no teeth against a line that is legal by construction — the exact
   mechanism-menu error [ADR-0034](0034-cut-choice-contract.md) already rejected. Mechanism
   is determinism's job, where [ADR-0034](0034-cut-choice-contract.md) D2 already puts it.

2. **The escalation is visible to the model and to the replay-lock.** The menu line for X
   renders the true mechanism and a fixed-string blast note, so the model sees what naming
   X actually does. The prompt fingerprint covers the escalation: an evidence change that
   flips `boundary_break(X)` is a prompt change and therefore a re-judge
   ([ADR-0023](0023-delta-aware-adjudication.md) preserved), and the cut-signature
   replay-lock ([ADR-0034](0034-cut-choice-contract.md) D8) fails byte-identity and
   cold-re-judges rather than silently repointing a standing cut.

3. **`boundary_break(X)` is typed evidence only — no untrusted substrings** (the
   anti-fabrication discipline of [ADR-0029](0029-adjudication-verdict-is-authoritative.md):
   ground on typed fields, never on trivy/CVE title text). Any one of:
   - (a) a host-path `SecretRead` on X (the host-credential class);
   - (b) a `PrivilegeChange` to uid 0 on X **and** X carries an `EscapesTo` edge — either
     fact alone is not a break;
   - (c) a `PtraceAttach` or `ModuleLoad` on X (kernel tamper);
   - (d) ≥2 workloads co-resident on one `Host` node, each with a decisive model `attack`
     naming it **and** actively-exploited live evidence — determinism composing two model
     decisions, not replacing one.

   Trigger (d) needs one new metadata-only fact: a pod→node placement edge for *all* pods
   (today only escape-primitive pods carry a `Host` edge), derived from the pod spec the
   engine already watches — no new RBAC.

4. **Node containment = cordon + co-resident default-deny.** The actuator sets
   `Node.spec.unschedulable` (cordon) and writes one default-deny `NetworkPolicy` per
   co-resident **labelled** pod (unlabelled ⇒ decline, the existing rule). The proposal
   surface states the honest rationale in fixed strings: after a proven host-level break no
   `NetworkPolicy` constrains the adversary; the cordon stops scheduler-driven spread, the
   co-resident denies stop lateral use of the node's other pods, and the durable fix
   (drain / reimage / rotate) is a **human** act. Containment here is damage-limitation and
   the UI must not present it as a clean sever.

5. **`ContainNode` is reversible, its own action class, and propose-first by construction.**
   Cordon mutates a shared field on a live object — it is reversible but **not** additive
   in the [ADR-0002](0002-change-driven-ir-loop.md)/[ADR-0022](0022-quarantine-the-entry-is-the-default-containment.md)
   `is_additive_live` sense — so the class is never blanket-auto. A real node always has
   alive collateral, so the existing blast/alive-collateral gate routes every node cut to
   human approval even at the armed rung; propose-first is structural, not a toggle
   (consistent with the no-per-feature-flags rule). Deterministic actuator rails:
   - never a control-plane node (VISION: protector cannot touch the control plane);
   - at most one node cordoned concurrently;
   - refuse if the cordon would leave fewer than two schedulable workers;
   - the cordon carries an engine ownership annotation, and revert only uncordons nodes
     carrying it — protector never fights a human or autoscaler cordon.

   `ContainNode` joins [ADR-0036](0036-break-glass-disarm.md)'s armed-set revert trigger, so
   break-glass uncordons within one pass, and self-reverts on the standard ledger lifecycle
   ([ADR-0017](0017-isolation-persists-on-the-breach-condition.md)) when no chain still
   carries X as a boundary-broken target.

6. **Ladder rung 3 `node`, strictly above `quarantine`** (edge-cut < quarantine < node) —
   one ordered position under [ADR-0035](0035-per-cut-class-arming-ladder.md), no new
   toggle. The `nodes` patch RBAC (cluster-scoped) is rendered only when `mode: enforce` ∧
   the armed rung reaches `node`, matching the existing posture-derived write-grant pattern
   ([ADR-0021](0021-two-setting-operating-posture.md)); an `audit` install keeps zero write
   grants. This is a chart change plus a manual port to the diverged cluster-chart fork.

7. **Ship split, shadow first.** Trigger + proposal surface (shadow, no RBAC, no chart)
   lands first — the incident detail stops proposing a known-ineffective pod cut and starts
   proposing the honest node containment, which is most of the value. The actuator (cordon +
   co-resident denies + rails + rung 3 + RBAC + chart) lands second.

### Adversary-reach annotation: presentation-only, never judge context

The deferred *"if compromised, this pod grants the attacker …"* line ships as an
**operator-facing annotation, not judge input**. *Context-not-evidence*
([ADR-0029](0029-adjudication-verdict-is-authoritative.md)) is enforced by **absence from
the prompt** — the only guard with no failure mode. Two facts make this the correct call,
not a compromise: prior fabrication findings showed a qwen3:1.7b judge converts scary
context lines into fabricated breach evidence, and [ADR-0034](0034-cut-choice-contract.md) already
pins `contain` to exactly the evidence-bearing set, leaving no legitimate discretion for
reach-context to inform. The line is a closed-vocabulary secret-**purpose** inference (from
secret name / k8s `type` / mount metadata — never `.data`, which stays a closed privacy
door) composed with the node's already-computed assume-breach reach, rendered in finding
detail, the read-only MCP ([ADR-0031](0031-read-only-mcp-server-tiered-redaction.md)), and
the notifier ([ADR-0018](0018-operator-configured-redacted-breach-notifier.md)) through the
existing scrub inventory. No bakeoff and no prompt change are required. Revisit only if a
future ADR relaxes the exact-evidence-set containment instruction.

### Off-path auto-containment: won't-build

Auto-containment for model-judged internal-only incidents (no internet-facing path) is
**not built**. [ADR-0032](0032-model-is-incident-responder.md) §6 (internal-only actively-
exploited pod ⇒ propose-only) is reaffirmed, with a stronger argument than when it was
written: [ADR-0038](0038-transitive-internet-exposure-l7-routes.md) moved the
honestly-reachable "internal" pods into the entry lane, and trigger (d) above covers the
scariest genuinely-internal scenario (multi-pod spread on one node) through the incident
that *did* have a path. What remains internal-only arrives by supply-chain or insider
vectors, for which a single pod's network cut is not the response; the deterministic
propose-only lane already surfaces a reviewable proposal. This closes the frontier as a
recorded decision rather than a lingering TODO, in the spirit of
[ADR-0039](0039-downstream-cve-residual-no-llm-reads-code.md). Revisit only if operators
ask.

## Consequences

- Protector stops proposing a cut its own evidence proves ineffective; on a proven pod-
  boundary break it proposes the containment unit that matches the compromise unit. The
  model's authority (what is an attack, which workloads are compromised) is untouched.
- **New highest-blast-radius action.** Node containment cordons a live node and severs its
  co-resident pods' traffic. It is bounded on every side: propose-first by construction
  (alive collateral always present), reversible + ownership-marked + self-reverting, one
  node at a time, never the control plane, floor of two schedulable workers, top of the
  arming ladder, confined to `enforceScope`, and covered by break-glass.
- **New failure/interaction surfaces**, accepted and bounded: cordon contention with the
  autoscaler / node-lifecycle controllers / humans (ownership annotation + one-node cap;
  residual is a controller un-cordoning, which self-re-proposes and is visible); potential
  self-severance if the contained node hosts protector's own agent/judge (bounded by the
  alive-collateral gate + freshness gate + break-glass; the approval UI names protector
  components in the collateral list explicitly).
- One new cut-choice bench fixture (boundary-broken downstream → model names X, no over-cut
  of neighbors), run on the deployed pod per [ADR-0033](0033-cut-choice-judge-tier.md).
- Left open for the build to settle by fixture: whether trigger (d) requires both
  co-resident pods model-confirmed or one confirmed + one actively-exploited (default to
  the stricter *both*, loosen only on evidence), and the exact closed vocabulary of
  secret-purpose categories (presentation-only).

## References

- `docs/ideas/post-compromise-containment.md` — the design brief this ADR records.
- [ADR-0032](0032-model-is-incident-responder.md) / [ADR-0034](0034-cut-choice-contract.md)
  — the model decides the cut; determinism proves + enriches + feeds + bounds the mechanism.
- [ADR-0033](0033-cut-choice-judge-tier.md) — deployed-hardware bench discipline; the judge
  cut-set is the fragile axis (why node escalation is not a model choice).
- [ADR-0035](0035-per-cut-class-arming-ladder.md) / [ADR-0036](0036-break-glass-disarm.md) /
  [ADR-0037](0037-shadow-bake-arm-readiness.md) — the arming rung, disarm, and freshness
  rails the `node` class joins.
- [ADR-0021](0021-two-setting-operating-posture.md) — posture-derived RBAC (the `nodes`
  grant pattern) and `enforceScope`.
- [ADR-0022](0022-quarantine-the-entry-is-the-default-containment.md) /
  [ADR-0010](0010-flannel-actuator-workload-isolation.md) /
  [ADR-0017](0017-isolation-persists-on-the-breach-condition.md) — the containment
  vocabulary, additive/reversible shapes, and self-revert lifecycle reused here.
- [ADR-0038](0038-transitive-internet-exposure-l7-routes.md) /
  [ADR-0039](0039-downstream-cve-residual-no-llm-reads-code.md) — the exposure-boundary work
  that strengthens the off-path won't-build.
