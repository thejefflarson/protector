# 0021. Two-setting operating posture: `mode` + one `enforceScope` arms all three surfaces

- Status: Accepted
- Date: 2026-07-02

## Context

Protector accreted a wide operator surface — roughly four dozen settings — as each
capability landed with its own knob. Enforcement in particular was spread across
*per-surface* toggles that an operator had to set, and keep aligned, by hand:

- the signature webhook's enforced scope (`PROTECTOR_ENFORCE_NAMESPACES` / `_LABELS`),
- the mesh webhook's enforced scope (`PROTECTOR_MESH_ENFORCE_NAMESPACES` / `_LABELS`),
- the engine's live-actuation arming (`PROTECTOR_ENGINE_ENABLE`) and its actuation
  namespace allowlist (`PROTECTOR_ENGINE_ENFORCE_NAMESPACES`),
- the chart's fail-closed enforcing-webhook selector (`webhook.enforcedNamespaceSelector`),
- and the chart's actuation RBAC grant (`engine.actuationRBAC`).

Nothing but operator discipline kept these consistent. A namespace could be "enforced"
by the signature gate but not covered by the fail-closed webhook, or armed for the
engine cut but not granted the RBAC to apply it — each drift a latent
security-or-availability bug. The chart's own comments told operators to "align
`webhook.enforcedNamespaceSelector` with `signature.enforceNamespaces` by hand".

Three of these surfaces are the *same decision* — "enforce protector's judgement here" —
expressed three times. One of them, the engine's live cut, is not a passive gate: it
writes an additive `NetworkPolicy` / `AdminNetworkPolicy` that severs live traffic
(ADR-0007, ADR-0010). Arming it is the single highest-blast-radius flip protector
offers.

## Decision

Collapse enforcement to **two settings**:

- **`mode: audit`** (the DEFAULT) — every surface observes and proposes; nothing blocks
  or acts. The signature and mesh webhooks audit everywhere (log + meter, never deny);
  the engine runs in shadow (proposes cuts, applies none — dry-run actuator). This is
  the shadow-by-default invariant, unchanged.
- **`mode: enforce`** + **`enforceScope { namespaces: [...], labels: [...] }`** — the
  ONE scope. Flipping to `enforce` arms **all three** surfaces together, each confined
  to *exactly* `enforceScope`:
  1. the signature webhook denies unsigned/regressed images,
  2. the mesh webhook denies unmeshed Pods,
  3. the engine applies its reversible network cut,

  and the two chart-level derivations follow from the same source: the **fail-closed
  enforcing-webhook selector** and the **actuation RBAC grant**.

There is **no per-surface enforcement toggle** and **no enforce-everywhere wildcard**.
`enforceScope` with namespaces enforces those namespaces by name; with labels it
enforces Pods carrying those labels (labels behave like namespaces — the in-process
gate matches namespace *or* label). `mode: enforce` with an *empty* `enforceScope` is
refused at startup: enforcing everywhere is the footgun ADR — the guard from
`EnforceScope` (no wildcard) is preserved.

The internal `EnforceScope` / `ActuationScope` / `EnabledActions` types and their
plumbing are unchanged — only what *feeds* them changes: `mode` + `enforceScope` derive
all three internal scopes at startup instead of five independent env knobs.

### Why one scope may arm the live cut — the load-bearing security call

The engine's network cut is a *live* mutation, not a view (contrast ADR-0016:
presentation is a view, never a gate). Binding it to the same `enforceScope` that arms
the two admission webhooks means a single `mode: enforce` flip widens protector's blast
radius from "blocks new Pods in scope" to "also severs live traffic in scope". That
widened blast radius is deliberate and is guarded on three sides:

- **`audit` is the default**, so the widened radius is never reached by accident — it
  is a single, explicit, documented flip (the whole point of the collapse: one honest
  switch, not five that can drift).
- **No wildcard, empty-scope-refused**, so `enforce` is always confined to a named,
  finite scope — never the whole cluster.
- **The cut keeps every existing safety gate** it already had (ADR-0007/0009/0010/0013):
  it is additive and reversible, gated behind live runtime corroboration on the chain
  entry, the live-collateral blast-radius guard, the adjudicator's veto, and the
  closed-loop self-revert. `enforceScope` only says *where* the cut may land; it does
  not loosen *whether* a given chain qualifies.

The actuation scope honours `enforceScope` on both axes: a cut is auto-applied only when
**every** workload endpoint it would write into is in scope (namespace listed *or* Pod
carrying a listed label). An out-of-scope endpoint on either side holds the cut as a
proposal — so a scope that names namespace `foo` can never actuate into `bar`, and a
label-only scope can never actuate a cut whose endpoints don't carry the label. There is
no path where a scope leak widens enforcement beyond `enforceScope`.

### The one enforcement knob that is *not* collapsed: the actuator mechanism

`PROTECTOR_ENGINE_ACTUATOR` (`engine.actuator`) is **kept**, because more than one live
actuator is real per ADR-0007/0010: `networkpolicy` (the `IsolationActuator`, a
default-deny `NetworkPolicy` for flannel/kube-router and any NetworkPolicy-enforcing
CNI, ADR-0010) and `adminnetworkpolicy` (the `KubeActuator`, a surgical
`AdminNetworkPolicy` edge-cut for Cilium/Calico, ADR-0007), plus `dryrun`. This is a
per-cluster *CNI* choice — real infrastructure, not an enforcement posture — so it stays
a knob (defaulting to the portable `networkpolicy`). It is not reducible to a constant.

## Consequences

Easier:

- One honest switch. `mode: enforce` + `enforceScope` cannot drift out of alignment,
  because the webhook selector and the RBAC grant are *derived*, not separately set.
- The default is provably the safe one: with `mode: audit` the derived scopes are the
  empty (audit-everywhere) `EnforceScope`s and the dry-run engine — byte-identical to
  the prior all-defaults-audit behavior.

Harder / watch:

- Flipping `enforce` now arms three surfaces at once, including the live cut. That is
  the point, and it is why `audit` is the default and the cut keeps all its own gates.
  Operators bake a scope in `audit` (watch the would-deny findings), then flip.
- Mixing `namespaces` *and* `labels` in one `enforceScope`: the in-process gate treats
  them as a union (enforce namespace `foo` OR any Pod labelled). The fail-closed
  *webhook* expresses the namespace axis as a `namespaceSelector` and the Pod-label axis
  as an `objectSelector`; a single webhook AND-s the two, so when both axes are set the
  webhook's *outage-blocking* set is their intersection. When protector is up, the union
  is still fully enforced (the always-on fail-open audit webhook routes every in-scope
  Pod to the in-process gate, which denies the union). Only during a protector *outage*
  does the non-intersection of a mixed scope fail open rather than closed — the
  conservative (availability-favouring) direction, never wider enforcement. Prefer a
  single axis per scope; mixing is supported but the fail-closed guarantee is the
  intersection.

## References

- ADR-0007 — live cuts via AdminNetworkPolicy (the surgical actuator).
- ADR-0010 — flannel actuator: workload isolation via default-deny NetworkPolicy.
- ADR-0009/0013 — the asymmetric action bar and the adjudicator veto that still gate
  every cut.
- ADR-0016 — presentation is a view, never a gate (the contrast: the cut *is* an
  action, and is why binding it to `enforceScope` is a security decision).
