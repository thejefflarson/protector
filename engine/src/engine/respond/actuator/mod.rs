//! The Actuator port and closed-loop verification (ADR-0002, Question 4 hard
//! mode): turn a *proposed* mitigation into an *applied*, self-reverting action —
//! safely.
//!
//! This is where the engine first gains the power to change the cluster, so the
//! whole module is about the discipline that makes that safe (ADR-0001/0002):
//!
//! - **Enabling is opt-in, per action class.** Nothing is enabled by default; easy
//!   mode is just "everything none" — every proposal routes to a human.
//! - **Only deterministic proof moves privilege** — already guaranteed upstream:
//!   mitigations come from proof-grade chains, so the actuator never acts on a
//!   model's guess.
//! - **Reversible only.** Irreversible actions (removing an escape primitive)
//!   are never auto-enabled.
//! - **Predicted blast radius + guard.** An action that would take down a
//!   currently-alive *bystander* — a workload other than the cut's own endpoints,
//!   which are its intended subjects — is never auto-applied; it routes to a human.
//! - **Measured verification + self-revert.** After applying, the engine checks
//!   observed health against the prediction ([`verify`]); if a workload it
//!   predicted would stay alive did not, the action reverts. It also reverts once
//!   no proven chain still justifies it (retirement, Q5). Both run every tick via
//!   [`ActionLog::reconcile`], so a false positive self-heals and an over-stayed
//!   control retires. (A time-based dead-man TTL is a future backstop; it needs a
//!   clean re-apply path so it doesn't churn still-justified controls.)
//!
//! Two actuators implement the port: [`DryRunActuator`] (logs, touches nothing —
//! the default when no class is enabled) and [`KubeActuator`] (applies/reverts a
//! real object). The only live action is a network deny, rendered by
//! [`render_deny`] as an additive `AdminNetworkPolicy` Deny rule (ADR-0007);
//! `render_deny` is pure and unit-tested, while the apply/revert against the
//! cluster is the thin untestable glue. The decision logic — what's safe to
//! auto-apply, and whether an applied action held — is also pure and tested.

use std::collections::HashSet;

use petgraph::visit::EdgeRef;

use super::{Mitigation, ProposedAction};
use crate::engine::graph::{Node, Relation, SecurityGraph};
use crate::engine::observe::health::{Health, HealthReport};
use render::workload_namespace;

/// Map an operator-facing enable name to the action class it arms. Only `network` is
/// accepted, because only a network deny is **live-actuatable**: an additive,
/// engine-owned `NetworkPolicy`/`AuthorizationPolicy` the engine can apply and
/// self-revert ([`ProposedAction::is_additive_live`], ADR-0002/0007). The other cut
/// classes — `rbac`, `mount`, `identity` — are *subtractive* edits to GitOps-managed
/// objects, so [`decide`] forbids live actuation of them regardless; and `escape` is
/// irreversible. Accepting those names here would be a lie: the engine still *proposes*
/// those cuts (routed to a human / durable-fix PR), you just can't "enable" them.
fn action_from_name(name: &str) -> Option<ProposedAction> {
    match name.trim() {
        "network" => Some(ProposedAction::DenyNetworkPath),
        _ => None,
    }
}

/// Which action classes are enabled for automatic application. Default: none — the
/// shadow-first posture. Operators enable one reversible class at a time after a bake.
///
/// A **pure armed-classes type**: it answers "what is armed?" (which cut classes, and
/// whether model promotion is allowed) and nothing else. *Where* a cut may be actuated
/// is a separate concern owned by [`ActuationScope`] — keeping the two apart so "is this
/// class enabled" never blurs into "is this cut in scope" (JEF-104 follow-up).
#[derive(Debug, Default, Clone)]
pub struct EnabledActions {
    enabled: HashSet<ProposedAction>,
    /// The `judgement` opt-in (ADR-0011): allow the model to *promote* a proven,
    /// internet-exposed chain to auto-eligible. Separate from an action class — it
    /// gates promotion, not the cut; the cut still needs its own class (`network`).
    judgement: bool,
}

impl EnabledActions {
    /// Nothing enabled — every proposal routes to a human (easy mode).
    pub fn none() -> Self {
        Self::default()
    }

    /// Enable one action class (builder-style).
    pub fn enable(mut self, action: ProposedAction) -> Self {
        self.enabled.insert(action);
        self
    }

    /// Enable model promotion (builder-style, for tests).
    pub fn enable_judgement(mut self) -> Self {
        self.judgement = true;
        self
    }

    /// Build from operator-facing class names (e.g. `["network", "judgement"]`).
    /// `judgement` toggles model promotion; other unknown / non-enableable names
    /// (like `escape`) are ignored.
    pub fn from_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        let mut policy = Self::none();
        for name in names {
            if name.trim() == "judgement" {
                policy.judgement = true;
            } else if let Some(action) = action_from_name(name) {
                policy = policy.enable(action);
            }
        }
        policy
    }

    pub fn is_enabled(&self, action: ProposedAction) -> bool {
        self.enabled.contains(&action)
    }

    /// Whether model promotion (ADR-0011) is permitted.
    pub fn judgement_enabled(&self) -> bool {
        self.judgement
    }

    /// No action class enabled (the actuator is dry-run). Note `judgement` alone
    /// leaves this true: promotion surfaces findings but applies nothing until an
    /// action class (`network`) is also enabled.
    pub fn is_empty(&self) -> bool {
        self.enabled.is_empty()
    }
}

/// The per-namespace actuation allowlist (`PROTECTOR_ENGINE_ENFORCE_NAMESPACES`) — the
/// scope guard for *where* a cut may be auto-applied, distinct from [`EnabledActions`]
/// ("what classes are armed"). Empty (the default) = unscoped: every namespace is
/// eligible, preserving the historical behavior. Non-empty = confine the first live cut
/// to these namespaces (ADR-0009/0014 "one reversible class, watch, widen") — a cut that
/// would write into any *other* namespace is held as a proposal even when its class is
/// enabled and corroborated. Mirrors the webhook's `PROTECTOR_ENFORCE_NAMESPACES`
/// allowlist idiom. Passed to [`decide`] as its own parameter so the enable decision and
/// the scope decision stay separable.
#[derive(Debug, Default, Clone)]
pub struct ActuationScope {
    namespaces: HashSet<String>,
}

impl ActuationScope {
    /// Unscoped — every namespace eligible (the default, historical behavior).
    pub fn unscoped() -> Self {
        Self::default()
    }

    /// Confine actuation to a namespace allowlist. An empty list leaves it unscoped.
    pub fn enforce_namespaces(namespaces: impl IntoIterator<Item = String>) -> Self {
        Self {
            namespaces: namespaces.into_iter().collect(),
        }
    }

    /// Whether `mitigation`'s cut is within the actuation namespace allowlist. An empty
    /// allowlist is unscoped (always eligible) — the historical behavior. When the list
    /// is non-empty, **every** workload endpoint the cut would write into (source and
    /// target) must be listed: the live actuators write an `AdminNetworkPolicy`/
    /// `NetworkPolicy` selecting the target's and the source's namespaces, so an
    /// out-of-scope endpoint on either side would place an object in an unallowed
    /// namespace. Non-workload endpoints carry no namespace to scope on and so don't
    /// constrain (non-network cuts are forbidden upstream anyway).
    pub fn in_scope(&self, mitigation: &Mitigation) -> bool {
        if self.namespaces.is_empty() {
            return true;
        }
        [&mitigation.cut.from, &mitigation.cut.to]
            .iter()
            .filter_map(|key| workload_namespace(key))
            .all(|ns| self.namespaces.contains(ns))
    }
}

/// The predicted effect of a cut: currently-alive **bystander** workloads it would
/// disrupt. Both of the cut's own endpoints are excluded — they are the action's
/// intended subjects (the compromised source we isolate, and the target edge we
/// deliberately sever, ADR-0010), not bystanders to protect. Collateral is the set
/// of *other* alive workloads the action takes down as a side effect.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BlastRadius {
    pub alive_collateral: Vec<String>,
    /// Reachability could not be fully modeled (an adapter flagged the graph), so
    /// `alive_collateral` may be under-counted. The gate treats this as "unknown
    /// collateral" and refuses to auto-apply.
    pub reachability_incomplete: bool,
}

/// Predict the blast radius of a mitigation's cut against current health.
///
/// The flannel live actuator is a blunt default-deny that quarantines the cut's
/// *source*, cutting its **entire** egress (ADR-0010) — not just the one edge. So
/// every alive workload the source currently reaches, *other than the target we
/// meant to sever*, is genuine collateral and forces human approval. (A surgical
/// AdminNetworkPolicy edge-cut would drop only the single edge; modelling that
/// per-mechanism is a future refinement — the broad isolation blast is the safe
/// over-approximation, with the closed-loop self-revert as the backstop.)
pub fn predict_blast_radius(
    mitigation: &Mitigation,
    graph: &SecurityGraph,
    health: &HealthReport,
) -> BlastRadius {
    let reachability_incomplete = graph.reachability_incomplete();
    let source = &mitigation.cut.from;
    let target = &mitigation.cut.to;
    let Some(src_idx) = graph.index_of(source) else {
        return BlastRadius {
            alive_collateral: Vec::new(),
            reachability_incomplete,
        };
    };
    let g = graph.inner();
    let mut alive_collateral: Vec<String> = g
        .edges(src_idx)
        .filter(|e| matches!(e.weight().relation, Relation::Reaches { .. }))
        .filter(|e| matches!(graph.node(e.target()), Some(Node::Workload(_))))
        .filter_map(|e| graph.key_of(e.target()))
        .filter(|peer| peer != target) // the intended severance, not collateral
        .filter(|peer| health.of(peer) == Health::Alive)
        .map(|peer| peer.0)
        .collect();
    alive_collateral.sort();
    alive_collateral.dedup();
    BlastRadius {
        alive_collateral,
        reachability_incomplete,
    }
}

/// What to do with a proposed mitigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Safe to apply automatically: reversible, enabled, no live collateral.
    AutoApply,
    /// Route to a human, with why.
    Propose(String),
    /// Never auto-apply (irreversible / destructive class), with why.
    Forbidden(String),
}

/// Decide how to handle `mitigation` given the active policy, the actuation scope, and
/// the predicted blast radius. The order of checks is the safety order: irreversibility
/// first, then live-collateral guard, then active, then scope.
pub fn decide(
    mitigation: &Mitigation,
    active: &EnabledActions,
    scope: &ActuationScope,
    blast: &BlastRadius,
) -> Decision {
    if !mitigation.action.is_reversible() {
        return Decision::Forbidden("irreversible action is never auto-enabled".to_string());
    }
    if !mitigation.action.is_additive_live() {
        return Decision::Forbidden(
            "subtractive remediation — durable-fix PR only, not live-actuatable".to_string(),
        );
    }
    if blast.reachability_incomplete {
        return Decision::Propose(
            "reachability is not fully modeled (unmodeled NetworkPolicy peers/selectors), so \
             blast radius may be under-counted; needs approval"
                .to_string(),
        );
    }
    if !blast.alive_collateral.is_empty() {
        return Decision::Propose(format!(
            "would affect {} currently-alive workload(s); needs approval",
            blast.alive_collateral.len()
        ));
    }
    if !mitigation.is_live_corroborated() {
        return Decision::Propose(
            "no justifying chain is live-corroborated and adjudicator-confirmed".to_string(),
        );
    }
    if !active.is_enabled(mitigation.action) {
        return Decision::Propose("action class not enabled".to_string());
    }
    if !scope.in_scope(mitigation) {
        return Decision::Propose(
            "cut's namespace is outside the engine actuation allowlist \
             (PROTECTOR_ENGINE_ENFORCE_NAMESPACES); needs approval"
                .to_string(),
        );
    }
    Decision::AutoApply
}

/// The result of the measured post-apply check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The prediction held; keep the action.
    Hold,
    /// A workload predicted to stay alive did not — revert, with why.
    Revert(String),
}

/// Verify an applied action against the health we observe after it. We predicted
/// `predicted_alive` would stay alive; if any of them isn't, the lever did
/// something we didn't intend, so it must be reverted. This is how a lever is
/// *trustworthy*: it carries a pre-stated hypothesis and is checked against it.
pub fn verify(predicted_alive: &[String], observed: &HealthReport) -> Verdict {
    for key in predicted_alive {
        if observed.of(&crate::engine::graph::NodeKey(key.clone())) != Health::Alive {
            return Verdict::Revert(format!(
                "workload {key} is no longer alive after the action"
            ));
        }
    }
    Verdict::Hold
}

/// Whether an actuation actually touched the cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actuation {
    /// Logged only — nothing applied (dry run / easy mode).
    DryRun,
    Applied,
    Reverted,
}

/// Applies and reverts mitigations as additive, engine-owned cluster objects. The
/// concrete implementation is the cluster-facing glue; this trait is the seam the
/// decision logic acts through. Async because a real actuator talks to the API
/// server; `Send + Sync` so the engine can hold it across `await`.
#[async_trait::async_trait]
pub trait Actuator: Send + Sync {
    async fn apply(&self, mitigation: &Mitigation) -> Actuation;
    async fn revert(&self, mitigation: &Mitigation) -> Actuation;
}

/// A human-readable signature of a mitigation's cut, for logs.
pub(super) fn cut_label(mitigation: &Mitigation) -> String {
    super::cut_signature(&mitigation.cut)
}

/// The default, safe actuator: logs what it would do and changes nothing. The
/// engine uses this unless a class is enabled.
pub struct DryRunActuator;

#[async_trait::async_trait]
impl Actuator for DryRunActuator {
    async fn apply(&self, mitigation: &Mitigation) -> Actuation {
        tracing::info!(
            cut = %cut_label(mitigation),
            action = mitigation.action.describe(),
            "DRY RUN: would apply mitigation (no action taken)"
        );
        Actuation::DryRun
    }

    async fn revert(&self, mitigation: &Mitigation) -> Actuation {
        tracing::info!(cut = %cut_label(mitigation), "DRY RUN: would revert mitigation");
        Actuation::DryRun
    }
}

// Cohesive submodules, split out of this file to keep each under the 1,000-line cap
// (repo CLAUDE.md). The public surface (the renderers, the live actuators, and the
// action ledger) is re-exported here so external paths (`respond::actuator::...`)
// resolve unchanged.
mod kube;
mod log;
mod render;

pub use kube::{IsolationActuator, KubeActuator};
pub use log::{ActionLog, Reversion};
pub use render::{render_deny, render_isolation};

#[cfg(test)]
mod tests;
