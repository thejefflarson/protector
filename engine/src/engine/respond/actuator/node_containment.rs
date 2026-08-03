//! The [`ProposedAction::ContainNode`] actuator (ADR-0040 §4/§5): the cordon + co-resident
//! default-deny rendering, and the deterministic rails that gate it. Split out of the
//! actuator module root purely to keep every file under the 1,000-line cap (repo CLAUDE.md).
//!
//! **The apply side is unit-tested, wired nowhere live yet; the revert side IS wired into
//! `Engine::process`'s break-glass/self-revert loop.** `ContainNode` is
//! `is_additive_live() == false` ([`ProposedAction::is_additive_live`]), so
//! [`super::decide`] already routes every `ContainNode` mitigation to
//! [`super::Decision::Forbidden`] regardless of what these rails would say — there is no
//! `node` arming rung to escalate past (ADR-0040 §6, a separate ticket), so nothing here can
//! become live-*applied* through this module alone. But ADR-0040 §5 also requires
//! `ContainNode` to join the armed-set revert trigger (ADR-0036) and the standard ledger
//! self-revert (ADR-0017) — that half does not depend on the apply-side rung existing at
//! all, so it is wired now: `Engine::process`'s self-revert loop routes a standing
//! `ContainNode` reversion through [`NodeContainmentRevert`] rather than the generic network
//! `actuator`, whose `revert()` speaks a different object shape entirely and would silently
//! leave the node cordoned. What IS delivered:
//!
//! - [`render_cordon`]/[`render_uncordon`]: the pure `Node.spec.unschedulable` patch,
//!   carrying [`CORDON_OWNER_ANNOTATION`] so a revert only ever lifts a cordon protector
//!   itself placed (never a human's or the autoscaler's, ADR-0040 §5).
//! - [`co_resident_denies`]: the co-resident default-deny sweep, reusing
//!   [`crate::engine::respond::quarantine_workload_link`]'s exact self-reference shape (and
//!   therefore [`super::render_isolation`]'s renderer) per co-resident LABELLED workload
//!   ([`crate::engine::respond::co_resident_workloads`]) — an unlabeled pod declines exactly
//!   like every other quarantine candidate.
//! - [`cordon_decision`]/[`revert_decision`]: the deterministic rails (control-plane
//!   exclusion, one-node cap, the two-worker floor, ownership-gated revert), pure over a
//!   [`NodeFact`] fleet so they're unit-testable without a live cluster and independent of
//!   any arming/enabled state — a rail refusal is exactly as meaningful in shadow as it
//!   would be armed.
//! - [`live`]'s [`NodeContainmentActuator`]/[`NodeContainmentRevert`]: the cluster-facing
//!   apply/revert glue. Thin and untested against a real cluster, like
//!   [`super::KubeActuator`]/[`super::IsolationActuator`] — [`render_cordon`]/
//!   [`render_uncordon`] are the unit-tested pure half.
//!
//! **Node role/schedulability observation is a follow-up, not this ticket.** [`NodeFact`]
//! is the fleet-state shape the rails need, but nothing in the engine watches Kubernetes
//! `Node` objects today — only `Pod.spec.nodeName`-derived placement (the placement
//! adapter, ADR-0040 §3), which needs no new RBAC. Populating a
//! real `NodeFact` fleet needs a `nodes` `get/list/watch` grant this ticket deliberately
//! does not add (ADR-0040 §7 ships the actuator split from the chart/RBAC change; the
//! ticket that adds this observation is the natural place to also wire the apply side of
//! these rails into `Engine::process`'s per-pass loop, and to keep `Engine`'s attached
//! `NodeFact` fleet fresh every pass). Evaluating a rail against a fabricated "no data"
//! fleet would silently default it to PASS — exactly the "weakening the rail" the ADR's
//! build-settled note warns against — so the engine's self-revert loop skips (rather than
//! fabricates) a revert for any host with no attached [`NodeContainmentRevert`] or no
//! observed [`NodeFact`], the same discipline this doc already applied to the cordon rails.

use crate::engine::graph::{NodeKey, SecurityGraph};
use crate::engine::respond::{
    Mitigation, ProposedAction, co_resident_workloads, quarantine_workload_link,
};

mod live;
pub use live::{NodeContainmentActuator, NodeContainmentRevert};

/// The annotation a cordon carries to record that PROTECTOR placed it (ADR-0040 §5). A
/// revert only lifts a cordon carrying this — never a human's or the cluster
/// autoscaler's own cordon — so the engine can never fight another cordon owner.
/// `protector.jeffl.es/*` is the repo's existing annotation namespace (the egress adapter's
/// `EGRESS_ANNOTATION` is the sibling use).
pub const CORDON_OWNER_ANNOTATION: &str = "protector.jeffl.es/cordoned-by";

/// The fixed ownership-annotation value protector's own cordons carry.
pub const CORDON_OWNER_VALUE: &str = "protector";

/// Render the cordon patch for a [`ProposedAction::ContainNode`] `mitigation` (ADR-0040
/// §4): `Node.spec.unschedulable = true`, carrying [`CORDON_OWNER_ANNOTATION`]. `None` for
/// any other action — the actuator render path's own convention
/// ([`super::render_deny`]/[`super::render_isolation`] self-guard the same way), so this
/// joins them as the ContainNode line the render allowlist was previously missing. The
/// target host is `mitigation.cut.from.short()` — [`contain_node_link`](crate::engine::respond::contain_node_link)
/// keys a `ContainNode` cut on a `host/<name>` self-reference, and `short()` strips the
/// `host/` kind prefix. Applied via server-side apply under the `protector` field manager
/// ([`live::NodeContainmentActuator`]) — the manifest declares only these two fields, so SSA
/// never contends with any other manager's claim on the rest of the object.
pub fn render_cordon(mitigation: &Mitigation) -> Option<serde_json::Value> {
    if mitigation.action != ProposedAction::ContainNode {
        return None;
    }
    let host_name = mitigation.cut.from.short();
    Some(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": {
            "name": host_name,
            "annotations": { CORDON_OWNER_ANNOTATION: CORDON_OWNER_VALUE }
        },
        "spec": { "unschedulable": true }
    }))
}

/// Render the uncordon patch for a [`ProposedAction::ContainNode`] `mitigation`:
/// `Node.spec.unschedulable = false`, with the ownership annotation OMITTED — under the
/// SAME `protector` field manager [`render_cordon`] applies through, omitting a previously-
/// declared field releases it, so re-applying this removes the annotation rather than
/// leaving a stale "protector cordoned this" marker on a node that is no longer cordoned.
/// `None` for any other action, mirroring [`render_cordon`].
pub fn render_uncordon(mitigation: &Mitigation) -> Option<serde_json::Value> {
    if mitigation.action != ProposedAction::ContainNode {
        return None;
    }
    let host_name = mitigation.cut.from.short();
    Some(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": { "name": host_name },
        "spec": { "unschedulable": false }
    }))
}

/// The co-resident default-deny sweep for a `ContainNode` mitigation on `host` (ADR-0040
/// §4): one [`ProposedAction::QuarantineWorkload`] mitigation per co-resident LABELLED
/// workload, built through the exact SAME [`quarantine_workload_link`] self-reference shape
/// (and therefore [`super::render_isolation`]'s renderer) the chain-based workload
/// quarantine already uses, so the two paths can never diverge on how a pod-scoped deny is
/// rendered. `justifications` is empty on every returned mitigation: these are
/// node-containment-triggered, not chain-justified in the ledger's own
/// [`crate::engine::respond::MitigationLedger`] sense.
pub fn co_resident_denies(graph: &SecurityGraph, host: &NodeKey) -> Vec<Mitigation> {
    co_resident_workloads(graph, host)
        .into_iter()
        .filter_map(|(node, labels)| quarantine_workload_link(&node, &labels))
        .map(|cut| Mitigation {
            cut,
            action: ProposedAction::QuarantineWorkload,
            justifications: Vec::new(),
        })
        .collect()
}

/// A per-pass fact for one node in the fleet — the shape [`cordon_decision`]/
/// [`revert_decision`] need, sourced from an observed Kubernetes `Node` (name; the
/// `node-role.kubernetes.io/control-plane` label; `spec.unschedulable`; whether
/// [`CORDON_OWNER_ANNOTATION`] is set to [`CORDON_OWNER_VALUE`]) once that observation is
/// wired (see this module's doc — a follow-up). Deliberately a plain data type, not the
/// graph's [`crate::engine::graph::Node::Host`], so the rail predicates stay pure and
/// unit-testable over hand-built fixtures without a full [`SecurityGraph`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeFact {
    pub name: String,
    /// Carries a control-plane role label — VISION's "protector cannot touch the control
    /// plane" (ADR-0040 §5).
    pub control_plane: bool,
    /// `!Node.spec.unschedulable` — true unless something (protector, a human, the
    /// autoscaler) has already cordoned it.
    pub schedulable: bool,
    /// [`CORDON_OWNER_ANNOTATION`] is set to [`CORDON_OWNER_VALUE`] on this node right now.
    pub owned_by_protector: bool,
}

/// Why a deterministic node-containment rail refused (ADR-0040 §5) — the fixed vocabulary
/// [`Self::metric_reason`] labels the `rail_refused` metric with
/// ([`crate::engine::metrics::EngineMetrics::record_contain_node`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RailRefusal {
    /// The target node carries a control-plane role — never cordoned (VISION).
    ControlPlane,
    /// Some OTHER node is already cordoned by protector — at most one at a time.
    OneNodeCap,
    /// Cordoning the target would leave fewer than two schedulable workers.
    WorkerFloor,
    /// A co-resident pod carries no labels — declined rather than widened to a namespace.
    Unlabelled,
    /// The target node does not carry protector's own cordon-ownership annotation — never
    /// revert a cordon protector didn't place.
    NotOwned,
}

impl RailRefusal {
    /// The metrics `reason` label this refusal carries — the fixed vocabulary the
    /// actuation-metrics ticket requirement specifies.
    pub fn metric_reason(&self) -> &'static str {
        match self {
            Self::ControlPlane => "control-plane",
            Self::OneNodeCap => "one-node-cap",
            Self::WorkerFloor => "worker-floor",
            Self::Unlabelled => "unlabelled",
            Self::NotOwned => "not-owned",
        }
    }
}

/// The minimum number of schedulable, non-control-plane workers a cordon must leave behind
/// (ADR-0040 §5, build-settled 2026-08-02: "a floor that leaves a single worker is an
/// outage, not damage-limitation" — kept at 2 even on a small fleet where this can make
/// `ContainNode` correctly, permanently inert).
const WORKER_FLOOR: usize = 2;

/// Whether cordoning `target` is deterministically allowed, over the CURRENT `fleet`
/// (ADR-0040 §5's three cordon rails, checked in the order a human reviewing a refusal would
/// expect: is this even a candidate node, is protector already committed elsewhere, would
/// this cordon itself cause an outage). `fleet` must include `target`'s own current entry —
/// the worker-floor count is `fleet` minus `target`, not a separately-supplied total, so the
/// two can never drift apart.
///
/// Pure and independent of any [`super::EnabledActions`]/arming state by construction — the
/// rail is exactly as meaningful evaluated in shadow (nothing armed) as it would be once a
/// `node` rung exists, which is how a rail refusal can be counted regardless of mode
/// (this module's doc, and the actuation-metrics ticket requirement).
pub fn cordon_decision(target: &NodeFact, fleet: &[NodeFact]) -> Result<(), RailRefusal> {
    if target.control_plane {
        return Err(RailRefusal::ControlPlane);
    }
    let already_cordoned_elsewhere = fleet
        .iter()
        .any(|n| n.name != target.name && n.owned_by_protector && !n.schedulable);
    if already_cordoned_elsewhere {
        return Err(RailRefusal::OneNodeCap);
    }
    let workers_after = fleet
        .iter()
        .filter(|n| n.name != target.name && !n.control_plane && n.schedulable)
        .count();
    if workers_after < WORKER_FLOOR {
        return Err(RailRefusal::WorkerFloor);
    }
    Ok(())
}

/// Whether reverting (uncordoning) `target` is allowed: ownership-gated, and ONLY
/// ownership-gated (ADR-0040 §5) — a node protector never cordoned, or one a human/the
/// autoscaler has since re-cordoned over protector's own lifted control, must never be
/// touched. Unlike [`cordon_decision`] there is no control-plane/floor check here: lifting a
/// cordon can never cause the damage those rails guard against.
pub fn revert_decision(target: &NodeFact) -> Result<(), RailRefusal> {
    if target.owned_by_protector {
        Ok(())
    } else {
        Err(RailRefusal::NotOwned)
    }
}

#[cfg(test)]
mod tests;
