# 0010. Flannel/Linkerd hard mode: workload isolation via default-deny NetworkPolicy

- Status: Accepted
- Date: 2026-06-12

## Context

[ADR-0007](0007-live-cuts-via-adminnetworkpolicy.md) made the live network cut an
additive `AdminNetworkPolicy` Deny rule — surgical (it severs one source→target
edge) but dependent on a CNI that implements ANP (Cilium, Calico). The target
cluster runs **K3s with flannel (WireGuard backend)**: its embedded kube-router
enforces standard `NetworkPolicy` but **not** ANP, and Linkerd's authorization is
allow-list with no deny primitive (a `Server` only default-denies *meshed* L7
ingress — it misses egress and non-meshed traffic). So ADR-0007's actuator can't
run here, and propose-only would gut the product's reason to exist: automated
remediation.

But there *is* a flannel-native additive primitive: a standard `NetworkPolicy`
that selects a pod and lists no rules **denies all of that pod's traffic**. Used
this way, allow-list NetworkPolicy expresses a deny — not of one edge, but of the
whole workload. That is the classic incident-response move: **quarantine the
compromised pod.**

## Decision

On clusters without ANP, the live actuator **isolates the source workload of the
cut** with an additive default-deny `NetworkPolicy`, and the actuator is
**selectable** so the right mechanism runs on each cluster:

- `PROTECTOR_ENGINE_ACTUATOR=networkpolicy` (default when a class is enabled) —
  the `IsolationActuator`: a `NetworkPolicy` in the source's namespace selecting
  the source pod by label, with `policyTypes: [Ingress, Egress]` and no rules
  (deny-all), labeled `managed-by: protector`. Additive, reversible by delete,
  enforced by flannel/kube-router.
- `PROTECTOR_ENGINE_ACTUATOR=adminnetworkpolicy` — the surgical ANP edge-cut
  (ADR-0007), for Cilium/Calico clusters.
- `PROTECTOR_ENGINE_ACTUATOR=dryrun` — log only.

This is **blunter than minimal-cut**: it quarantines the pod rather than snipping
one edge. That is acceptable, and well-matched to when it fires: the asymmetric
action bar (ADR-0009) only auto-acts on a chain with **live runtime corroboration
on its entry**, so the isolated pod is one we have live evidence is being
exploited. Quarantining it is the correct response, not collateral damage — so the
collateral guard **excludes the cut's source** (the action's intended subject)
from its protected set, while still protecting the downstream/target side. The
self-revert (health divergence / chain retirement) and the adjudicator's veto
remain in force, so a wrong isolation self-heals.

Requires a pod-label selector (the cut carries the endpoints' labels, ADR-0007);
without labels, isolation is declined rather than widening to the whole namespace.

## Consequences

Easier:

- **The product's whole point — automated remediation — works on the real
  cluster**, with no CNI migration, using the NetworkPolicy controller k3s already
  runs.
- One actuator port, three selectable mechanisms: blunt-but-portable
  (NetworkPolicy), surgical (ANP), and dry-run — the right tool per cluster.

Harder / accepted downsides:

- **Isolation is coarse.** It severs *all* of the source pod's traffic, not one
  edge — it can disrupt that pod's legitimate functions. Mitigated by: it fires
  only on a live-corroborated, adjudicator-confirmed chain (a pod we believe is
  actively compromised), it's reversible, and it self-reverts on health
  divergence. For multi-hop chains the cut's source may not be the entry, a known
  coarseness the self-revert backstops.
- **Downstream dependents are unpredicted.** We can't enumerate what depended on
  the quarantined pod without traffic data, so the closed-loop self-revert is the
  safety net rather than a pre-flight prediction.
- **Two cut semantics now exist** (edge-deny vs workload-isolation) behind one
  action class; operators must know which mechanism their cluster uses. The env
  switch and logs name it.
</content>
</invoke>
