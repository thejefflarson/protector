//! The [`ProposedAction::ContainNode`] actuator (ADR-0040 §4/§5/§6): the cordon +
//! co-resident default-deny rendering, and the deterministic rails that gate it. Split out
//! of the actuator module root purely to keep every file under the 1,000-line cap (repo
//! CLAUDE.md).
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
//!   would be armed. These rails are a BOUND layered on top of the human-approval gate
//!   below, never a substitute for it.
//! - [`contain_node_in_scope`]: the `enforceScope` confinement check
//!   [`crate::engine::Engine::process`] uses in place of the generic
//!   [`super::ActuationScope::in_scope`] — `ContainNode`'s own cut is a `host/<name>`
//!   self-reference, which the generic check can't resolve a namespace for and so treats
//!   as vacuously in scope; this instead confines through the co-resident LABELLED
//!   workload set (ADR-0021: no enforce-everywhere).
//! - [`evaluate_proposal`]: the PROPOSAL-side gate [`crate::engine::Engine::process`] calls
//!   for every active `ContainNode` mitigation each pass — armed/in-scope/
//!   live-corroborated (mirroring [`super::decide`]'s own ordering), THEN the
//!   [`cordon_decision`] rail against the pass's observed [`NodeFact`] fleet, fail-closed on
//!   a target absent from the fleet ([`RailRefusal::UnknownNode`]) rather than fabricating a
//!   passing rail. Pure — the caller maps its result onto the `proposed`/`rail_refused`
//!   metric. **There is no `evaluate_apply` and no cluster write here**: ADR-0040 §5 is
//!   explicit that a node cut is propose-first BY CONSTRUCTION ("a real node always has
//!   alive collateral, so the existing blast/alive-collateral gate routes every node cut to
//!   human approval even at the armed rung; propose-first is structural, not a toggle") —
//!   these rails are bounds a human reviews the proposal against, never an auto-apply gate.
//! - [`live`]'s [`NodeContainmentActuator`]/[`NodeContainmentRevert`]: the cluster-facing
//!   REVERT glue only (lifting an already-standing cut via break-glass/self-revert,
//!   `crate::engine::node_containment_revert`) — there is no corresponding live APPLY call
//!   site; `NodeContainmentActuator::apply` exists and is unit-tested in isolation for a
//!   future human-approval-to-apply flow (out of scope here), but nothing in `Engine`
//!   invokes it. Thin and untested against a real cluster, like
//!   [`super::KubeActuator`]/[`super::IsolationActuator`] — [`render_cordon`]/
//!   [`render_uncordon`]/[`evaluate_proposal`]/[`contain_node_in_scope`] are the unit-tested
//!   pure half.
//!
//! `ContainNode` is `is_additive_live() == false` ([`ProposedAction::is_additive_live`]), so
//! [`super::decide`]'s generic AutoApply path always routes it to
//! [`super::Decision::Forbidden`] — a cordon mutates a shared field on a live object rather
//! than adding a new engine-owned one, so it can never ride the generic additive-object
//! auto-apply path, and (unlike every other class) arming the `node` rung
//! ([`super::arming_ladder::ArmingRung::Node`]) does not change that: [`evaluate_proposal`]
//! only ever answers "should this be SURFACED as an actionable proposal", never "should
//! this be applied".
//!
//! **Node role/schedulability observation** (ADR-0040 §3, `node_fact` fleet): a metadata-only
//! `Node` watch (name; the `node-role.kubernetes.io/control-plane` label, the legacy
//! `node-role.kubernetes.io/master` label, and a control-plane-shaped `NoSchedule` taint;
//! `spec.unschedulable`; [`CORDON_OWNER_ANNOTATION`]) —
//! [`crate::engine::observe::adapter::node_fact::observe_node_facts`] — is the sole source of
//! the [`NodeFact`] fleet [`evaluate_proposal`]/[`cordon_decision`] consult. See that
//! module's doc for why it does not implement the graph-contributing
//! [`crate::engine::observe::adapter::Adapter`] trait `PlacementAdapter` does: [`NodeFact`]
//! deliberately bypasses the [`crate::engine::graph::SecurityGraph`] entirely, to keep the
//! rails pure and testable without one.

use crate::engine::graph::{NodeKey, SecurityGraph};
use crate::engine::respond::{
    Mitigation, ProposedAction, co_resident_workloads, quarantine_workload_link,
};

use super::ActuationScope;

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
/// [`revert_decision`] need, sourced from an observed Kubernetes `Node`
/// ([`crate::engine::observe::adapter::node_fact::observe_node_facts`]): name; whether it
/// carries a control-plane role signal (the canonical or legacy label, or a control-plane
/// taint — see that module's doc); `spec.unschedulable`; whether
/// [`CORDON_OWNER_ANNOTATION`] is set to [`CORDON_OWNER_VALUE`]. Deliberately a plain data
/// type, not the graph's [`crate::engine::graph::Node::Host`], so the rail predicates stay
/// pure and unit-testable over hand-built fixtures without a full [`SecurityGraph`].
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
    /// The target host has no entry in the observed [`NodeFact`] fleet — the watch hasn't
    /// synced yet, or the mitigation names a host that no longer exists. FAIL CLOSED: a
    /// missing fact is refused, never treated as a passing rail
    /// ([`evaluate_proposal`]'s doc).
    UnknownNode,
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
            Self::UnknownNode => "unknown-node",
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

/// Whether a `ContainNode` mitigation targeting `host` is within `scope` (ADR-0021: no
/// enforce-everywhere). Unlike every other mitigation, `ContainNode`'s own cut is a
/// `host/<name>` self-reference — a non-workload key [`ActuationScope::in_scope`] can't
/// resolve a namespace for (`workload_namespace` returns `None`), so checking the cut
/// directly would be vacuously true regardless of `enforceScope`, a real scope bypass:
/// arming the `node` rung would then confine nothing. This confines it instead through the
/// SAME co-resident LABELLED workload set the default-deny sweep already computes
/// ([`co_resident_denies`]) — which structurally includes whichever workload's
/// `boundary_break` triggered the escalation, since it is scheduled on `host` by
/// construction ([`crate::engine::respond::contain_node_link`]'s own doc).
///
/// In scope iff `scope` is unscoped (the historical, no-`enforceScope`-configured
/// behavior), OR at least one co-resident deny target is itself in scope. A host with no
/// co-resident LABELLED pod at all (nothing for [`co_resident_denies`] to return) is never
/// presumed in scope once a scope IS configured — the same "decline rather than widen"
/// discipline [`co_resident_denies`] already applies to an unlabelled pod.
pub fn contain_node_in_scope(graph: &SecurityGraph, host: &NodeKey, scope: &ActuationScope) -> bool {
    if scope.is_unscoped() {
        return true;
    }
    co_resident_denies(graph, host)
        .iter()
        .any(|deny| scope.in_scope(deny))
}

/// What [`evaluate_proposal`] decided for one active `ContainNode` mitigation this pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalOutcome {
    /// Every deterministic rail passes: the cut is ELIGIBLE to be surfaced as an
    /// actionable proposal. This NEVER means it was applied — ADR-0040 §5 makes a node
    /// cut propose-first BY CONSTRUCTION, so there is no cluster write on this path at
    /// any rung; a human out-of-band action is the only route to an actual cordon.
    Proposed,
    /// A deterministic rail refused — includes [`RailRefusal::UnknownNode`] for a target
    /// absent from the observed fleet (fail closed).
    Refuse(RailRefusal),
}

/// The proposal-side decision for one active `ContainNode` mitigation this pass (ADR-0040
/// §5/§6): whether `mitigation` should be surfaced as a rails-clean, actionable proposal,
/// given this pass's arming/scope/corroboration state and the observed [`NodeFact`] fleet.
/// **Never an apply decision** — see this module's doc for why `ContainNode` has no
/// `evaluate_apply` counterpart: ADR-0040 §5 states plainly that "a real node always has
/// alive collateral, so the existing blast/alive-collateral gate routes every node cut to
/// human approval even at the armed rung; propose-first is structural, not a toggle." The
/// rails here are the SAME bound that gate carries — control-plane/one-node/worker-floor —
/// layered on top of the human-approval requirement, never a way to skip it.
///
/// `None` when the mitigation is not yet eligible to be evaluated against the rails at
/// all — not armed at the `node` rung, out of `enforceScope`
/// ([`contain_node_in_scope`]), or not live-corroborated (mirrors [`super::decide`]'s own
/// ordering for every other action class: the generic `Decision::Forbidden`/`Propose` path
/// above already explains a `None` case, so this function stays silent rather than
/// emitting a competing "reason"). `Some` once eligible: [`ProposalOutcome::Proposed`] if
/// [`cordon_decision`] passes (or the host is unrecognized, in which case this fails
/// closed to [`ProposalOutcome::Refuse`]`(`[`RailRefusal::UnknownNode`]`)` rather than
/// silently defaulting a missing fact to a passing rail — the exact "weakening the rail"
/// failure mode this ADR's build-settled note warns against), otherwise
/// [`ProposalOutcome::Refuse`] with the rail that blocked it.
///
/// Pure: takes the mitigation, the three upstream gates as bools, and the fleet — no
/// [`SecurityGraph`], no cluster client, no metrics/OTLP — so it is fully unit-testable and
/// the only thing [`Engine::process`](crate::engine::Engine::process) has to do with the
/// result is record the matching metric. There is no further action to take on
/// `Proposed`: it is surfaced, never applied.
pub fn evaluate_proposal(
    mitigation: &Mitigation,
    armed: bool,
    in_scope: bool,
    fleet: &[NodeFact],
) -> Option<ProposalOutcome> {
    if mitigation.action != ProposedAction::ContainNode {
        return None;
    }
    if !armed || !in_scope || !mitigation.is_live_corroborated() {
        return None;
    }
    let host_name = mitigation.cut.from.short();
    let Some(target) = fleet.iter().find(|n| n.name == host_name) else {
        return Some(ProposalOutcome::Refuse(RailRefusal::UnknownNode));
    };
    Some(match cordon_decision(target, fleet) {
        Ok(()) => ProposalOutcome::Proposed,
        Err(refusal) => ProposalOutcome::Refuse(refusal),
    })
}

#[cfg(test)]
mod tests;
