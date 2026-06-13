# 0007. Live network cuts are additive AdminNetworkPolicy Deny rules

- Status: Accepted
- Date: 2026-06-12

## Context

[ADR-0002](0002-change-driven-ir-loop.md) decided that hard-mode live mitigations
are **additive, engine-owned objects** — new resources Argo never tracked, so the
reconciler leaves them alone and the revert is a delete. Building the actuator
forced a sharper question that ADR-0002 glossed: *what additive object actually
severs one edge?*

Two findings fell out, and they narrowed the answer:

1. **Most edge classes can't be cut additively at all.** Revoking an RBAC grant,
   removing a secret mount, or removing a container-escape primitive are
   *subtractive* edits to git-managed objects — there is no additive object that
   removes a permission. Those are durable-fix-PR territory, not live actuation.
   The actuator already encodes this (`ProposedAction::is_additive_live` → only
   network denials qualify; everything else is `Forbidden` for auto-apply).

2. **Plain NetworkPolicy and Linkerd authz can't express a precise additive
   deny.** Both are *allow-list* models: a NetworkPolicy adds *allowed* ingress,
   and once a pod is selected it defaults to deny-the-rest — so "deny just this one
   source" means converting the target to default-deny and re-allowing everything
   else, which is neither additive nor surgical. Linkerd `AuthorizationPolicy` is
   likewise allow-based. Neither can add a single deny edge without restructuring
   the target's whole allow set.

The mechanism that *can* express an additive, precise deny is a **deny-capable
policy API**: the upstream `AdminNetworkPolicy` (ANP, `policy.networking.k8s.io`)
supports `action: Deny` ingress/egress rules, is cluster-scoped and additive, and
is vendor-neutral (implemented by Cilium, Calico, and others). It is exactly the
"new object that denies one edge" the additive-mitigation model needs.

## Decision

The default network Actuator renders a live cut as an **`AdminNetworkPolicy` with
an `action: Deny` ingress rule**, applied as an additive engine-owned object and
reverted by deletion.

- **Selection is pod-granularity when labels are known, namespace otherwise.**
  Workload nodes carry their pod labels, and the cut `Link` carries the endpoints'
  labels, so the rendered ANP narrows `subject`/`from` to a `podSelector` within
  the namespace — severing the specific source→target pair, not all cross-namespace
  traffic. When labels are absent (a non-workload endpoint, or a workload observed
  without labels) it falls back to a namespace selector. Even at pod-granularity
  the network class stays gated behind enablement, the live-collateral guard, and
  runtime corroboration, and is a human-reviewed proposal in easy mode.
- **The object is labeled `app.kubernetes.io/managed-by: protector`** and named
  deterministically from the cut signature, so it is unambiguously engine-owned,
  idempotent to re-apply, and safe to delete on revert.
- **It is a default adapter behind the Actuator port** (ADR-0003), not a
  hardcoded dependency. A cluster without ANP support (no implementing CNI) gets
  apply failures the engine logs; a Cilium-native or mesh-native actuator can
  replace it behind the same trait.
- **The manifest *rendering* is a pure, unit-tested function**; the apply/delete
  against the cluster is the untestable glue, exercised only against a real
  cluster and gated off by default (no enabled classes → dry-run actuator).

## Consequences

Easier:

- There is now a concrete, additive, reversible mechanism for the one auto-cuttable
  class, consistent with the GitOps-coexistence rule (ANP is a new object Argo
  never tracked).
- The renderer is testable in isolation, so the risky part (cluster mutation) is a
  thin, clearly-bounded shell around tested logic.

Harder / accepted downsides:

- **A real dependency on ANP support.** The cluster's CNI must implement
  `AdminNetworkPolicy`; without it, live network cuts fail (and are logged). This
  is the cost of a vendor-neutral deny.
- **Granularity is only as good as the labels.** Pod-granularity depends on the
  endpoints carrying distinguishing labels; a workload with no labels (or labels
  shared with siblings) falls back to — or effectively widens to — namespace
  scope, which over-cuts. The gates above keep that human-reviewed in practice.
- **Still only one auto-cuttable class.** ADR-0002's "additive object" vision is,
  in reality, network denials only; everything else is a durable-fix PR. That is a
  narrower live-actuation surface than the vision implied, and the honest one.
</content>
</invoke>
