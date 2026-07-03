# 0022. Quarantine the internet-facing entry is the default containment; the surgical edge-cut is the refinement

- Status: Accepted
- Date: 2026-07-03

## Context

[ADR-0007](0007-live-cuts-via-adminnetworkpolicy.md) and
[ADR-0010](0010-flannel-actuator-workload-isolation.md) gave the engine two live,
additive, reversible network controls: a surgical `AdminNetworkPolicy` edge-cut and a
default-deny `NetworkPolicy` quarantine. But the *selector* that decided which one to
propose — `MitigationLedger::reconcile` — only ever took a chain's **first single-edge
cut** (`chain.single_edge_cuts.first()`). That has a fatal blind spot against the
breach shape the product exists to stop.

Real breach chains are **direct**: an internet-facing pod (argocd-server,
watcher-server) that *itself* mounts the secret (`can-read`) or *itself* holds the RBAC
grant (`can-do`). Those single-edge cuts are **subtractive** edits to GitOps-managed
objects — durable-fix-PR territory, never live-actuatable
([`is_additive_live`](../../engine/src/engine/respond/mod.rs) is false for them). Broad
cluster grants have no single-edge cut at all. So on the direct breach the reconcile
selector produced a durable-fix or a no-cut — and the engine could auto-contain almost
*nothing*.

Worse, the ADR-0010 full-quarantine render (`policyTypes: [Ingress, Egress]`, no rules)
already existed but both renderers early-returned unless the action was
`DenyNetworkPath` — i.e. only for a `reaches`/`can-egress` **network** edge. A direct
mount/RBAC chain carries no such edge, so *neither* renderer ran and *nothing* was
quarantined. And when isolation did fire, it targeted the cut edge's *source*
(`cut.from`), which on a multi-hop chain is not the breach **entry**.

## Decision

We will make **quarantining the internet-facing entry the DEFAULT containment**, and
demote the surgical edge-cut to the refinement it always was — the narrowest control,
used only when it suffices.

A new action, `ProposedAction::QuarantineEntry`, is proposed by `containment_for(chain)`
on a precedence ladder (narrowest first):

1. **Surgical edge-cut** — a *reversible additive* `reaches`/`can-egress` single-edge
   cut exists → `DenyNetworkPath` (unchanged from ADR-0007/0010). Drops one edge, not
   the entry's whole reach; preferred whenever it exists.
2. **Default containment** — else, a **breach-relevant** chain (internet-facing entry)
   with a labelled entry → `QuarantineEntry`, a full default-deny `NetworkPolicy`
   selecting **only the entry** by label. Cutting the front door's entire reach
   contains the whole chain (lateral and direct) without touching anything deeper.
3. **Durable-fix / no-cut** — else, the first single-edge cut as a subtractive PR
   proposal, or an unsevered finding (unchanged).

`QuarantineEntry` is **additive** (a new object → never fights GitOps, ADR-0002) and
**reversible** (delete to lift), so `is_additive_live()` and `is_reversible()` are both
true and it is auto-actuatable under the same gate as the edge-cut. It reuses the
ADR-0010 `render_isolation` shape, driven from a synthetic `cut` link that is a
self-reference on the entry (`from == to == entry`, carrying the entry's labels) — so
the renderer's existing `cut.from` selector isolates the **entry**, and the link gives
the mitigation a stable per-entry signature for the ledger.

**The quarantine target is the ENTRY only — never a deeper or objective workload.** A
full default-deny on the entry cuts its egress, so lateral reach is contained at the
source. Quarantining a database (the objective) would have a huge blast radius and
punish the victim data plane; a deeper independently-internet-facing pod is its own
finding with its own entry. Without entry labels we decline the quarantine (falling
through to durable-fix) rather than widen to a whole namespace.

Self-revert is **unchanged** (ADR-0017): the mitigation is keyed on its `cut_signature`
(here, the per-entry quarantine signature), so the existing ledger/`ActionLog`
reconcile retires it the moment no proven chain still justifies it — same
chain ∧ enrichment-fingerprint lifecycle as an edge-cut.

Actuation stays gated by [ADR-0021](0021-two-setting-operating-posture.md): under
`audit` (the default) nothing is armed, so `QuarantineEntry` is **PROPOSED only**
(shadow) and the default posture is byte-identical to before this change. Under
`enforce`, the `network` action class arms *both* network denies (edge-cut and
quarantine) confined to `enforceScope`. The blast-radius guard, adjudicator veto, and
closed-loop self-revert remain in force — and because a default-deny cuts the entry's
whole egress, the blast-radius over-approximation routes a quarantine with any alive
peer to human approval automatically.

The dashboard disposition names the control: `quarantine entry (default-deny)`,
distinct from the surgical edge-cut and the durable-fix PR, and the detail names the
entry workload.

## Consequences

Easier:

- **The engine can now contain the breach shape it was built for** — a direct
  internet-facing mount/RBAC chain — instead of degrading to a durable-fix PR or a
  no-cut. Containment defaults to the safe, additive, reversible quarantine.
- One precedence function (`containment_for`) is the single source of truth for what
  the engine proposes *and* what the dashboard displays, so they never disagree.
- Both live actuators handle the quarantine: the flannel `IsolationActuator` natively,
  and the ANP `KubeActuator` via the same default-deny `NetworkPolicy` (standard
  NetworkPolicy is honored by Cilium/Calico too), so the default containment actuates
  on every supported CNI rather than silently no-op'ing on ANP clusters.

Harder / accepted downsides:

- **Quarantine is coarse by design.** It severs *all* of the entry's traffic, not one
  edge. Accepted because it targets only the internet-facing front door (never the
  data plane), is additive + reversible, self-reverts on health divergence or chain
  retirement, and only auto-fires under `enforce` with no alive collateral.
- **Two containment semantics** (surgical edge-cut vs entry quarantine) now sit behind
  one `network` action class. The precedence ladder makes the choice deterministic and
  the disposition/logs name which one fired.

Amends [ADR-0009](0009-asymmetric-action-bar.md) (the action bar now drives an
entry-quarantine default, not only an edge-cut) and
[ADR-0010](0010-flannel-actuator-workload-isolation.md) (isolation targets the breach
**entry** by default, not the cut edge's source, and is no longer gated on a network
edge existing).
