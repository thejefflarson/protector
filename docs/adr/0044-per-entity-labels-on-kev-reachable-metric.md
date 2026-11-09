# 0044. Per-entity labels on the KEV-reachable findings metric

- Status: Accepted
- Date: 2026-11-08
- Relates to: [0009](0009-asymmetric-action-bar.md) (the `corroborated` runtime signal this
  metric is deliberately NOT keyed on), [0001](0001-async-mitigation-engine.md) /
  [0014](0014-behavioral-telemetry-ebpf.md) (the KEV / exploited-in-wild predicate), and the
  prior counts-only metric convention this reverses (`engine/src/engine/metrics.rs`)

## Context

Until now every OTLP instrument the engine emits was **counts-only**: a gauge or counter with,
at most, a low-cardinality variant label (`action`, `verdict`, `outcome`, a probe `reason`), and
never a label naming a specific workload, node, or image. The convention was written into the
instrument docstrings as a hard prohibition — a per-node or per-entry series "would be a
cardinality/DoS vector" because node/workload/image names are "attacker-influenceable." The
entity name was pushed into the accompanying structured log instead, and the metric carried only
the count.

That rule guarded two things: unbounded time-series cardinality (one series per distinct label
tuple), and a denial-of-service shape where an attacker who could mint arbitrary workload/node
names could explode the metrics store. Both are real concerns **on a large or multi-tenant
cluster.**

Protector runs on a **bounded, single-operator homelab**. The operator judged the rule
over-cautious there, for two reasons:

1. **The threat it guards presupposes prior compromise.** Workload, node, and image names come
   from the operator's own cluster. For an attacker to influence them — to drive cardinality or
   forge a misleading label — they must already be creating or renaming Kubernetes objects in
   this cluster. At that point the cardinality of a metric series is not the problem to solve;
   the attacker is already inside. The bound that makes the guard unnecessary (a small, operator-
   controlled namespace of names) is exactly the bound a large/multi-tenant cluster does not
   have.

2. **The response value is concrete and immediate.** A CVE that CISA KEV lists as
   exploited-in-wild, reachable on an internet-facing (or proven-foothold) entry, is the single
   highest-priority finding protector produces. Forcing the operator to cross-reference a bare
   count against a separate structured log to learn *which* workload and image to patch costs
   minutes at exactly the moment minutes matter. A per-finding labelled series routes the alert
   straight to the workload.

Weighed against each other for this deployment, rapid KEV response wins over a cardinality/DoS
guard whose precondition (an attacker who can forge cluster object names) already implies a
worse breach.

## Decision

**We will remove the "no per-entity labels on metrics" invariant and add a KEV-reachable
findings metric that carries per-finding entity labels.**

1. **New counter `protector.engine.kev_reachable_findings`.** Incremented once per pass per
   distinct entry workload that is both *reachable* — `is_breach_relevant()` (internet-facing
   entry) OR `foothold.is_some()` (a proven exploitable front door) — and *KEV-backed*: its
   entry image carries a `Vulnerability` with `exploited_in_wild` set (the CISA KEV catalogue
   flag, `observe/exploit_intel.rs`). Emitted from the per-pass chain-fold loop in
   `engine/src/engine/mod.rs`, beside the existing `breach_paths` / `corroborations` snapshot.

2. **Labels:** `k8s.namespace.name`, `k8s.workload.kind`, `k8s.workload.name` (all parsed from
   the entry `workload/<ns>/<kind>/<name>` key), `image.reference` (the entry's deployed image
   reference(s), via a new `SecurityGraph::entry_image_reference` walk over the `RunsImage`
   edge), and `cve.ids` (the entry image's exploited-in-wild CVE ids, sorted and joined into one
   value). These labels are **attacker-influenceable by design** — that is the protection this
   ADR removes, accepted for the homelab bound.

3. **"KEV" is `exploited_in_wild`, not `corroborated`.** This metric's gate is the static CISA
   KEV catalogue flag. It is unrelated to [ADR-0009](0009-asymmetric-action-bar.md)'s runtime
   `corroborated` signal, which the separate `protector.engine.corroborations` counter tracks.
   The two predicates must not be conflated: a finding can be KEV-reachable with no live runtime
   corroboration (the latent-foothold case) and vice versa.

4. **Series shape, chosen to avoid gratuitous blowup WITHOUT reinstating the removed guard.**
   The counter fires once per distinct entry workload per pass, de-duplicated by entry key. An
   entry yields one chain per reachable objective, but every label on this metric is
   entry-scoped, so counting each objective-chain would only inflate a single series' value, not
   add information — the dedupe keeps the series count equal to the number of KEV-reachable
   workloads. Likewise, the several exploited-in-wild CVE ids on one entry are joined into a
   single `cve.ids` value rather than fanned out into one series per CVE. This is a
   series-hygiene choice, **not** a cardinality cap or an entity-name guard; it does not limit
   how many distinct workloads may appear.

## Consequences

- An operator watching `/metrics` (or an alert rule) sees KEV-reachable findings broken down by
  the exact workload, image, and CVE — the fast path from "a KEV CVE is reachable" to "patch
  *this* image on *this* workload," with no structured-log cross-reference.
- The engine now emits at least one metric whose label values are attacker-influenceable. On
  this homelab that is bounded by the operator-controlled name space (see Context); the
  structured-log-only discipline no longer applies to new instruments, and the counts-only
  docstrings that stated the prohibition are reworded to say per-entity labels are permitted
  (the coverage/narrowing-delta gauges stay counts-only because *they* have no use for an entity
  label, not because one is forbidden).
- **Revisit trigger — large or multi-tenant deployment.** The entire justification rests on the
  single-operator, bounded-name-space bound. If protector is ever deployed on a cluster where
  workload/node/image names are not under one trusted operator's control — a shared or
  multi-tenant cluster — the cardinality/DoS guard this ADR removed becomes load-bearing again,
  and this metric's entity labels (and any that followed it) must be re-gated: bound the series
  (e.g. a top-N or a cardinality cap), drop to counts-only with the entity in a log, or
  otherwise constrain the attacker-influenceable dimension. This is a deployment-shape decision,
  recorded here so the reversal is not silently inherited.
- **Residual worth noting (a consideration, not a control):** even on the homelab the series set
  grows with the number of distinct KEV-reachable workloads over the exporter's retention
  window. For this cluster's scale that is a handful of series and a non-issue; were it to grow,
  a top-N or a cardinality cap would be the place to bound it. It is deliberately NOT added here
  — adding it now would reinstate the very protection this ADR removes.

## References

- `engine/src/engine/metrics.rs` — the instrument (`kev_reachable_findings`) and its
  `record_kev_reachable_finding` recorder.
- `engine/src/engine/mod.rs` — the per-pass emission in the chain-fold loop.
- `engine/src/engine/graph/mod.rs` — `entry_image_reference` (the `RunsImage` image-ref walk)
  and `NodeKey::workload_kind` (the kind-segment accessor) added for the labels.
- [ADR-0009](0009-asymmetric-action-bar.md) — the runtime `corroborated` signal this metric is
  explicitly NOT keyed on.
