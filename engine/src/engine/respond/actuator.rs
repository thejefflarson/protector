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
use crate::engine::graph::{Node, NodeKey, Relation, SecurityGraph};
use crate::engine::observe::health::{Health, HealthReport};

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

/// Decide how to handle `mitigation` given the active policy and predicted blast
/// radius. The order of checks is the safety order: irreversibility first, then
/// live-collateral guard, then active.
pub fn decide(mitigation: &Mitigation, active: &EnabledActions, blast: &BlastRadius) -> Decision {
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
fn cut_label(mitigation: &Mitigation) -> String {
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

/// The namespace component of a `workload/<ns>/<kind>/<name>` node key — `None` for any
/// non-workload key. The key seam (kind discriminant + namespace segment) is owned by
/// [`NodeKey`]; this is the workload-only wrapper the actuator needs for ANP selectors.
fn workload_namespace(key: &NodeKey) -> Option<&str> {
    (key.kind() == "workload").then(|| key.namespace())?
}

/// A deterministic, DNS-safe object name (`<prefix>-<hash of cut>`) so re-apply is
/// idempotent and revert can find the engine-owned object.
fn object_name(prefix: &str, mitigation: &Mitigation) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    mitigation.cut_signature().hash(&mut hasher);
    format!("{prefix}-{:016x}", hasher.finish())
}

/// An ANP namespaced-peer selector for `namespace`, narrowed to a `podSelector`
/// when `labels` are known (pod-granularity, ADR-0007) and a namespace-only
/// selector otherwise. Used for both the `subject` and the `from` peer.
fn selector(
    namespace: &str,
    labels: &std::collections::BTreeMap<String, String>,
) -> serde_json::Value {
    let namespace_selector =
        serde_json::json!({ "matchLabels": { "kubernetes.io/metadata.name": namespace } });
    if labels.is_empty() {
        serde_json::json!({ "namespaces": namespace_selector })
    } else {
        serde_json::json!({
            "pods": {
                "namespaceSelector": namespace_selector,
                "podSelector": { "matchLabels": labels }
            }
        })
    }
}

/// Render the additive deny object for a network cut (ADR-0007): an
/// `AdminNetworkPolicy` with an `action: Deny` ingress rule selecting the target
/// and denying ingress from the source. Pod-granularity when the cut carries the
/// endpoints' labels, namespace-granularity otherwise. Returns `None` for any
/// non-network or non-workload-endpoint cut.
pub fn render_deny(mitigation: &Mitigation) -> Option<serde_json::Value> {
    if mitigation.action != ProposedAction::DenyNetworkPath {
        return None;
    }
    let source_ns = workload_namespace(&mitigation.cut.from)?;
    let target_ns = workload_namespace(&mitigation.cut.to)?;
    Some(serde_json::json!({
        "apiVersion": "policy.networking.k8s.io/v1alpha1",
        "kind": "AdminNetworkPolicy",
        "metadata": {
            "name": object_name("protector-deny", mitigation),
            "labels": { "app.kubernetes.io/managed-by": "protector" }
        },
        "spec": {
            "priority": 1000,
            "subject": selector(target_ns, &mitigation.cut.to_labels),
            "ingress": [{
                "action": "Deny",
                "from": [selector(source_ns, &mitigation.cut.from_labels)]
            }]
        }
    }))
}

/// Live actuator: applies/reverts the rendered `AdminNetworkPolicy` against the
/// cluster (ADR-0007). This is the cluster-facing glue — exercised only against a
/// real cluster; [`render_deny`] is the unit-tested part.
pub struct KubeActuator {
    client: kube::Client,
}

impl KubeActuator {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }

    fn anp_api(&self) -> kube::Api<kube::core::DynamicObject> {
        let gvk = kube::core::GroupVersionKind::gvk(
            "policy.networking.k8s.io",
            "v1alpha1",
            "AdminNetworkPolicy",
        );
        let ar = kube::core::ApiResource::from_gvk(&gvk);
        kube::Api::all_with(self.client.clone(), &ar)
    }
}

#[async_trait::async_trait]
impl Actuator for KubeActuator {
    async fn apply(&self, mitigation: &Mitigation) -> Actuation {
        let Some(manifest) = render_deny(mitigation) else {
            // Not an additive-live action; decide() should already have filtered
            // these out, so reaching here means a renderer gap.
            tracing::warn!(cut = %cut_label(mitigation), "no additive object to apply");
            return Actuation::DryRun;
        };
        let name = object_name("protector-deny", mitigation);
        let object: kube::core::DynamicObject = match serde_json::from_value(manifest) {
            Ok(o) => o,
            Err(error) => {
                tracing::error!(%error, "failed to build AdminNetworkPolicy");
                return Actuation::DryRun;
            }
        };
        let params = kube::api::PatchParams::apply("protector").force();
        match self
            .anp_api()
            .patch(&name, &params, &kube::api::Patch::Apply(&object))
            .await
        {
            Ok(_) => {
                tracing::info!(cut = %cut_label(mitigation), %name, "applied deny AdminNetworkPolicy");
                Actuation::Applied
            }
            Err(error) => {
                tracing::error!(%error, %name, "failed to apply mitigation");
                Actuation::DryRun
            }
        }
    }

    async fn revert(&self, mitigation: &Mitigation) -> Actuation {
        let name = object_name("protector-deny", mitigation);
        match self
            .anp_api()
            .delete(&name, &kube::api::DeleteParams::default())
            .await
        {
            Ok(_) => {
                tracing::info!(cut = %cut_label(mitigation), %name, "reverted mitigation");
                Actuation::Reverted
            }
            Err(error) => {
                tracing::error!(%error, %name, "failed to revert mitigation");
                Actuation::DryRun
            }
        }
    }
}

/// One applied (or dry-run-applied) mitigation the engine is tracking so it can
/// revert it.
#[derive(Debug, Clone)]
struct ActiveAction {
    mitigation: Mitigation,
    /// Workloads that were alive at apply time and the action promised not to take
    /// down — the protected set the closed loop verifies against.
    baseline_alive: Vec<String>,
}

/// A reversion the lifecycle decided on, with why.
#[derive(Debug, Clone)]
pub struct Reversion {
    pub mitigation: Mitigation,
    pub reason: String,
}

/// Tracks active mitigations and decides when to revert them — the self-reverting
/// half of the closed loop (ADR-0002). Each cycle, an action is reverted if a
/// workload it promised to keep alive went down (the lever did something we didn't
/// intend) or if no proven chain still justifies it (posture improved). Both keep
/// the active set honest: a control exists only while it is both *needed* and *not
/// hurting*.
#[derive(Debug, Default)]
pub struct ActionLog {
    active: Vec<ActiveAction>,
}

impl ActionLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an applied mitigation so it can later be verified and reverted.
    pub fn record(&mut self, mitigation: Mitigation, baseline_alive: Vec<String>) {
        // Replace any existing record for the same cut so re-applies don't stack.
        let sig = mitigation.cut_signature();
        self.active.retain(|a| a.mitigation.cut_signature() != sig);
        self.active.push(ActiveAction {
            mitigation,
            baseline_alive,
        });
    }

    /// True if a mitigation for this cut is already tracked (so the caller doesn't
    /// re-apply it every cycle).
    pub fn is_active(&self, mitigation: &Mitigation) -> bool {
        let sig = mitigation.cut_signature();
        self.active
            .iter()
            .any(|a| a.mitigation.cut_signature() == sig)
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Reconcile tracked actions against current health and the set of cut
    /// signatures still justified by a proven chain. Returns the reversions to
    /// carry out and drops them from the active set.
    pub fn reconcile(
        &mut self,
        health: &HealthReport,
        justified_cuts: &HashSet<String>,
    ) -> Vec<Reversion> {
        let mut reversions = Vec::new();
        let mut keep = Vec::new();
        for action in std::mem::take(&mut self.active) {
            if let Verdict::Revert(reason) = verify(&action.baseline_alive, health) {
                reversions.push(Reversion {
                    mitigation: action.mitigation,
                    reason,
                });
            } else if !justified_cuts.contains(&action.mitigation.cut_signature()) {
                reversions.push(Reversion {
                    mitigation: action.mitigation,
                    reason: "no proven chain still justifies this control".to_string(),
                });
            } else {
                keep.push(action);
            }
        }
        self.active = keep;
        reversions
    }
}

/// Render the additive deny object for the **isolation** actuator (ADR-0010): a
/// default-deny `NetworkPolicy` selecting the cut's *source* workload by label, so
/// flannel/kube-router quarantines it. Returns `None` for a non-network cut, a
/// non-workload source, or a source with no labels (we will not widen to a whole
/// namespace).
pub fn render_isolation(mitigation: &Mitigation) -> Option<serde_json::Value> {
    if mitigation.action != ProposedAction::DenyNetworkPath {
        return None;
    }
    let source_ns = workload_namespace(&mitigation.cut.from)?;
    if mitigation.cut.from_labels.is_empty() {
        return None;
    }
    Some(serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": object_name("protector-isolate", mitigation),
            "namespace": source_ns,
            "labels": { "app.kubernetes.io/managed-by": "protector" }
        },
        // No ingress/egress rules + both policyTypes ⇒ deny all traffic to/from
        // the selected pod (quarantine).
        "spec": {
            "podSelector": { "matchLabels": mitigation.cut.from_labels },
            "policyTypes": ["Ingress", "Egress"]
        }
    }))
}

/// Isolation actuator (ADR-0010): applies/reverts the default-deny `NetworkPolicy`
/// that quarantines the cut's source workload. Works on flannel/kube-router — no
/// ANP needed. Cluster-facing glue; [`render_isolation`] is the tested part.
pub struct IsolationActuator {
    client: kube::Client,
}

impl IsolationActuator {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }

    /// A dynamic `Api` for the namespaced `NetworkPolicy` we apply/delete.
    fn np_api(&self, ns: &str) -> kube::Api<kube::core::DynamicObject> {
        let gvk = kube::core::GroupVersionKind::gvk("networking.k8s.io", "v1", "NetworkPolicy");
        let ar = kube::core::ApiResource::from_gvk(&gvk);
        kube::Api::namespaced_with(self.client.clone(), ns, &ar)
    }
}

#[async_trait::async_trait]
impl Actuator for IsolationActuator {
    async fn apply(&self, mitigation: &Mitigation) -> Actuation {
        let (Some(manifest), Some(ns)) = (
            render_isolation(mitigation),
            workload_namespace(&mitigation.cut.from),
        ) else {
            tracing::warn!(cut = %cut_label(mitigation), "no isolation NetworkPolicy to apply");
            return Actuation::DryRun;
        };
        let name = object_name("protector-isolate", mitigation);
        let object: kube::core::DynamicObject = match serde_json::from_value(manifest) {
            Ok(o) => o,
            Err(error) => {
                tracing::error!(%error, "failed to build isolation NetworkPolicy");
                return Actuation::DryRun;
            }
        };
        let api = self.np_api(ns);
        let params = kube::api::PatchParams::apply("protector").force();
        match api
            .patch(&name, &params, &kube::api::Patch::Apply(&object))
            .await
        {
            Ok(_) => {
                tracing::info!(cut = %cut_label(mitigation), %name, %ns, "isolated workload (default-deny NetworkPolicy)");
                Actuation::Applied
            }
            Err(error) => {
                tracing::error!(%error, %name, "failed to isolate workload");
                Actuation::DryRun
            }
        }
    }

    async fn revert(&self, mitigation: &Mitigation) -> Actuation {
        let Some(ns) = workload_namespace(&mitigation.cut.from) else {
            return Actuation::DryRun;
        };
        let name = object_name("protector-isolate", mitigation);
        let api = self.np_api(ns);
        match api.delete(&name, &kube::api::DeleteParams::default()).await {
            Ok(_) => {
                tracing::info!(cut = %cut_label(mitigation), %name, "lifted workload isolation");
                Actuation::Reverted
            }
            Err(error) => {
                tracing::error!(%error, %name, "failed to lift isolation");
                Actuation::DryRun
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::attack::CREDENTIAL_ACCESS;
    use crate::engine::graph::{
        Edge, Exposure, Grade, Node, NodeKey, Protocol, Provenance, Workload,
    };
    use crate::engine::reason::proof::Link;
    use crate::engine::respond::{Justification, ProposedAction};
    use std::time::SystemTime;

    fn mitigation(from: &str, relation: &str, to: &str, action: ProposedAction) -> Mitigation {
        Mitigation {
            cut: Link {
                from: NodeKey(from.to_string()),
                to: NodeKey(to.to_string()),
                relation: relation.to_string(),
                technique: None,
                from_labels: Default::default(),
                to_labels: Default::default(),
            },
            action,
            justifications: vec![],
        }
    }

    fn justification(foothold: bool, corroborated: bool, adjudicated: bool) -> Justification {
        Justification {
            entry: "workload/app/Pod/web".to_string(),
            objective: "secret/app/db-creds".to_string(),
            attack: CREDENTIAL_ACCESS,
            foothold,
            corroborated,
            adjudicated,
            promoted: false,
            // These tests exercise the corroboration/foothold/reversibility axes;
            // breach-relevance (internet-facing entry) is held true so it isn't the
            // gating factor here. The breach-relevance gate is tested in response.rs.
            breach_relevant: true,
        }
    }

    /// A justification that is live-actionable (corroborated + adjudicated).
    fn corroborated() -> Justification {
        justification(true, true, true)
    }

    /// A justification auto-actionable via model promotion, not runtime corroboration.
    fn promoted() -> Justification {
        Justification {
            promoted: true,
            ..justification(false, false, true)
        }
    }

    fn health(entries: &[(&str, Health)]) -> HealthReport {
        let mut r = HealthReport::default();
        for (k, h) in entries {
            r.insert(NodeKey(k.to_string()), *h);
        }
        r
    }

    /// An app-namespace Pod workload node (keyed `workload/app/Pod/<name>`).
    fn pod(name: &str) -> Node {
        Node::Workload(Workload {
            namespace: "app".to_string(),
            name: name.to_string(),
            kind: "Pod".to_string(),
            labels: Default::default(),
            meshed: false,
            exposure: Exposure::Internal,
            runtime: vec![],
            persistent: false,
        })
    }

    fn reaches() -> Edge {
        Edge {
            relation: Relation::Reaches {
                port: None,
                protocol: Protocol::Tcp,
            },
            provenance: Provenance::new("test", SystemTime::UNIX_EPOCH),
            grade: Grade::Proof,
        }
    }

    #[test]
    fn blast_radius_excludes_cut_endpoints_counts_other_reaches() {
        // Isolating `web` (default-deny on the source) cuts web's ENTIRE egress, so
        // the blast radius is every alive workload web reaches *except* the target
        // we deliberately sever. web reaches db (the cut target), metrics (a live
        // bystander), and ghost (down). Cut = web→db.
        let mut g = SecurityGraph::new();
        let web = g.upsert_node(pod("web"));
        let db = g.upsert_node(pod("db"));
        let metrics = g.upsert_node(pod("metrics"));
        let ghost = g.upsert_node(pod("ghost"));
        g.add_edge(web, db, reaches());
        g.add_edge(web, metrics, reaches());
        g.add_edge(web, ghost, reaches());

        let m = mitigation(
            "workload/app/Pod/web",
            "reaches/Tcp/5432",
            "workload/app/Pod/db",
            ProposedAction::DenyNetworkPath,
        );
        let h = health(&[
            ("workload/app/Pod/web", Health::Alive),
            ("workload/app/Pod/db", Health::Alive),
            ("workload/app/Pod/metrics", Health::Alive),
            ("workload/app/Pod/ghost", Health::Halted),
        ]);
        // db excluded (intended severance), web excluded (the subject), ghost
        // excluded (not alive) ⇒ only the live bystander `metrics` is collateral.
        assert_eq!(
            predict_blast_radius(&m, &g, &h).alive_collateral,
            vec!["workload/app/Pod/metrics".to_string()]
        );

        // A cut whose source reaches nothing else has no collateral ⇒ auto-eligible.
        let mut g2 = SecurityGraph::new();
        let only_web = g2.upsert_node(pod("web"));
        let only_db = g2.upsert_node(pod("db"));
        g2.add_edge(only_web, only_db, reaches());
        assert!(
            predict_blast_radius(&m, &g2, &h)
                .alive_collateral
                .is_empty()
        );

        // can-do from an Identity to a Capability ⇒ source has no reaches edges, no
        // collateral (the workload-key guard prevents the false positive).
        let rbac = mitigation(
            "identity/ops/ops-sa",
            "can-do/create/pods",
            "capability/cluster/create/pods",
            ProposedAction::RevokeRbacGrant,
        );
        assert!(
            predict_blast_radius(&rbac, &g, &health(&[]))
                .alive_collateral
                .is_empty()
        );
    }

    #[test]
    fn decide_forbids_irreversible() {
        let m = mitigation(
            "workload/ci/Pod/runner",
            "escapes-to/privileged",
            "host/node-1",
            ProposedAction::RemoveEscapePrimitive,
        );
        let d = decide(&m, &EnabledActions::none(), &BlastRadius::default());
        assert!(matches!(d, Decision::Forbidden(_)));
    }

    #[test]
    fn decide_proposes_on_live_collateral_even_when_enabled() {
        let m = mitigation(
            "workload/app/Pod/web",
            "reaches/Tcp/5432",
            "workload/app/Pod/db",
            ProposedAction::DenyNetworkPath,
        );
        let active = EnabledActions::none().enable(ProposedAction::DenyNetworkPath);
        let blast = BlastRadius {
            alive_collateral: vec!["workload/app/Pod/web".to_string()],
            ..Default::default()
        };
        assert!(matches!(decide(&m, &active, &blast), Decision::Propose(_)));

        // Even with no collateral, an incompletely-modeled graph fails safe.
        let unknown = BlastRadius {
            alive_collateral: vec![],
            reachability_incomplete: true,
        };
        let live = Mitigation {
            justifications: vec![corroborated()],
            ..m
        };
        assert!(matches!(
            decide(
                &live,
                &EnabledActions::none().enable(ProposedAction::DenyNetworkPath),
                &unknown
            ),
            Decision::Propose(_)
        ));
    }

    #[test]
    fn action_bar_is_asymmetric_live_acts_latent_proposes() {
        let armed = EnabledActions::none().enable(ProposedAction::DenyNetworkPath);
        let net = |justifications: Vec<Justification>| Mitigation {
            justifications,
            ..mitigation(
                "workload/app/Pod/web",
                "reaches/Tcp/5432",
                "workload/ext/Pod/attacker",
                ProposedAction::DenyNetworkPath,
            )
        };

        // Live evidence (corroborated + adjudicated), no KEV foothold ⇒ auto-apply.
        assert_eq!(
            decide(
                &net(vec![justification(false, true, true)]),
                &armed,
                &BlastRadius::default()
            ),
            Decision::AutoApply
        );
        // Latent foothold (KEV, exposed) but no live activity ⇒ propose, not act.
        assert!(matches!(
            decide(
                &net(vec![justification(true, false, true)]),
                &armed,
                &BlastRadius::default()
            ),
            Decision::Propose(_)
        ));
        // Live but adjudicator-vetoed ⇒ propose.
        assert!(matches!(
            decide(
                &net(vec![justification(false, true, false)]),
                &armed,
                &BlastRadius::default()
            ),
            Decision::Propose(_)
        ));
    }

    #[test]
    fn decide_forbids_subtractive_rbac() {
        // RBAC revocation is subtractive — never live-actuatable, even enabled.
        let m = mitigation(
            "identity/ops/ops-sa",
            "can-do/create/pods",
            "capability/cluster/create/pods",
            ProposedAction::RevokeRbacGrant,
        );
        let enabled = EnabledActions::none().enable(ProposedAction::RevokeRbacGrant);
        assert!(matches!(
            decide(&m, &enabled, &BlastRadius::default()),
            Decision::Forbidden(_)
        ));
    }

    #[test]
    fn decide_network_needs_corroboration_and_active_to_auto_apply() {
        let net = || Mitigation {
            justifications: vec![corroborated()],
            ..mitigation(
                "workload/app/Pod/web",
                "reaches/Tcp/5432",
                "workload/ext/Pod/attacker",
                ProposedAction::DenyNetworkPath,
            )
        };
        let enabled = EnabledActions::none().enable(ProposedAction::DenyNetworkPath);

        // Corroborated + enabled + no live collateral ⇒ auto-apply.
        assert_eq!(
            decide(&net(), &enabled, &BlastRadius::default()),
            Decision::AutoApply
        );
        // Enabled but the justifying chain isn't corroborated ⇒ propose.
        let uncorroborated = mitigation(
            "workload/app/Pod/web",
            "reaches/Tcp/5432",
            "workload/ext/Pod/attacker",
            ProposedAction::DenyNetworkPath,
        );
        assert!(matches!(
            decide(&uncorroborated, &enabled, &BlastRadius::default()),
            Decision::Propose(_)
        ));
        // Corroborated but not enabled ⇒ propose.
        assert!(matches!(
            decide(&net(), &EnabledActions::none(), &BlastRadius::default()),
            Decision::Propose(_)
        ));
    }

    #[test]
    fn decide_auto_applies_a_model_promoted_chain() {
        // ADR-0011: a model-promoted justification (no runtime corroboration) is
        // auto-actionable just like a live one, gated by the same bounded action.
        let promoted_net = Mitigation {
            justifications: vec![promoted()],
            ..mitigation(
                "workload/app/Pod/web",
                "reaches/Tcp/5432",
                "workload/ext/Pod/attacker",
                ProposedAction::DenyNetworkPath,
            )
        };
        let enabled = EnabledActions::none().enable(ProposedAction::DenyNetworkPath);
        assert_eq!(
            decide(&promoted_net, &enabled, &BlastRadius::default()),
            Decision::AutoApply
        );
        // The `judgement` opt-in toggles promotion (consumed in the engine loop), not
        // the cut's action class.
        assert!(EnabledActions::from_names(["judgement"]).judgement_enabled());
        assert!(!EnabledActions::from_names(["network"]).judgement_enabled());
    }

    #[test]
    fn verify_holds_when_prediction_holds_and_reverts_otherwise() {
        let predicted = vec!["workload/app/Pod/api".to_string()];
        assert_eq!(
            verify(
                &predicted,
                &health(&[("workload/app/Pod/api", Health::Alive)])
            ),
            Verdict::Hold
        );
        assert!(matches!(
            verify(
                &predicted,
                &health(&[("workload/app/Pod/api", Health::Halted)])
            ),
            Verdict::Revert(_)
        ));
    }

    #[test]
    fn render_deny_builds_namespace_scoped_anp_for_network_cuts_only() {
        let net = mitigation(
            "workload/app/Pod/web",
            "reaches/Tcp/5432",
            "workload/data/Pod/db",
            ProposedAction::DenyNetworkPath,
        );
        let anp = render_deny(&net).expect("network cut renders an ANP");
        assert_eq!(anp["kind"], "AdminNetworkPolicy");
        assert_eq!(
            anp["metadata"]["labels"]["app.kubernetes.io/managed-by"],
            "protector"
        );
        assert_eq!(anp["spec"]["ingress"][0]["action"], "Deny");
        // Subject = target namespace; deny from = source namespace.
        assert_eq!(
            anp["spec"]["subject"]["namespaces"]["matchLabels"]["kubernetes.io/metadata.name"],
            "data"
        );
        assert_eq!(
            anp["spec"]["ingress"][0]["from"][0]["namespaces"]["matchLabels"]["kubernetes.io/metadata.name"],
            "app"
        );

        // A non-network (RBAC) cut isn't additive-live — renders nothing.
        let rbac = mitigation(
            "identity/ops/ops-sa",
            "can-do/create/pods",
            "capability/cluster/create/pods",
            ProposedAction::RevokeRbacGrant,
        );
        assert!(render_deny(&rbac).is_none());
    }

    #[test]
    fn render_deny_uses_pod_selector_when_labels_are_known() {
        let mut net = mitigation(
            "workload/app/Pod/web",
            "reaches/Tcp/5432",
            "workload/data/Pod/db",
            ProposedAction::DenyNetworkPath,
        );
        net.cut.from_labels =
            std::collections::BTreeMap::from([("role".to_string(), "web".to_string())]);
        net.cut.to_labels =
            std::collections::BTreeMap::from([("role".to_string(), "db".to_string())]);

        let anp = render_deny(&net).expect("renders");
        // Subject narrows to the target pod by label, within its namespace.
        let subject = &anp["spec"]["subject"]["pods"];
        assert_eq!(
            subject["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
            "data"
        );
        assert_eq!(subject["podSelector"]["matchLabels"]["role"], "db");
        // Deny-from narrows to the source pod by label.
        let from = &anp["spec"]["ingress"][0]["from"][0]["pods"];
        assert_eq!(from["podSelector"]["matchLabels"]["role"], "web");
    }

    #[test]
    fn render_isolation_builds_deny_all_networkpolicy_on_the_source() {
        let mut net = mitigation(
            "workload/app/Pod/web",
            "reaches/Tcp/5432",
            "workload/data/Pod/db",
            ProposedAction::DenyNetworkPath,
        );
        net.cut.from_labels =
            std::collections::BTreeMap::from([("role".to_string(), "web".to_string())]);

        let np = render_isolation(&net).expect("renders");
        assert_eq!(np["kind"], "NetworkPolicy");
        // In the *source's* namespace, selecting the source pod.
        assert_eq!(np["metadata"]["namespace"], "app");
        assert_eq!(np["spec"]["podSelector"]["matchLabels"]["role"], "web");
        // Deny-all: both policy types, no rules.
        assert_eq!(np["spec"]["policyTypes"][0], "Ingress");
        assert_eq!(np["spec"]["policyTypes"][1], "Egress");
        assert!(np["spec"]["ingress"].is_null());
        assert!(np["spec"]["egress"].is_null());

        // Without source labels we decline rather than isolate the whole namespace.
        let mut no_labels = net.clone();
        no_labels.cut.from_labels.clear();
        assert!(render_isolation(&no_labels).is_none());
    }

    #[test]
    fn from_names_arms_only_network_and_ignores_non_actuatable_classes() {
        // Only `network` is live-actuatable, so only it arms. The subtractive classes
        // (rbac/mount/identity), irreversible `escape`, and unknown names are ignored —
        // the engine still proposes those cuts, they just can't be enabled for actuation.
        let policy = EnabledActions::from_names(["network", "rbac", "mount", "escape", "bogus"]);
        assert!(policy.is_enabled(ProposedAction::DenyNetworkPath));
        assert!(!policy.is_enabled(ProposedAction::RevokeRbacGrant));
        assert!(!policy.is_enabled(ProposedAction::RemoveSecretMount));
        assert!(!policy.is_enabled(ProposedAction::RebindIdentity));
        assert!(!policy.is_enabled(ProposedAction::RemoveEscapePrimitive));
    }

    #[test]
    fn lifecycle_reverts_on_health_divergence_and_retirement_else_holds() {
        let rbac = mitigation(
            "identity/ops/ops-sa",
            "can-do/create/pods",
            "capability/cluster/create/pods",
            ProposedAction::RevokeRbacGrant,
        );
        let net = mitigation(
            "workload/app/Pod/web",
            "reaches/Tcp/5432",
            "workload/app/Pod/db",
            ProposedAction::DenyNetworkPath,
        );

        // rbac promised api stays alive; net promised nothing live was affected.
        let mut log = ActionLog::new();
        log.record(rbac.clone(), vec!["workload/app/Pod/api".to_string()]);
        log.record(net.clone(), vec![]);
        assert_eq!(log.active_count(), 2);
        assert!(log.is_active(&rbac));

        // api went down (divergence) ⇒ rbac reverts; net's chain is unjustified
        // (empty set) ⇒ net reverts.
        let reversions = log.reconcile(
            &health(&[("workload/app/Pod/api", Health::Halted)]),
            &HashSet::new(),
        );
        assert_eq!(reversions.len(), 2);
        assert_eq!(log.active_count(), 0);

        // A still-justified action whose baseline stayed alive is held.
        let mut log = ActionLog::new();
        log.record(rbac.clone(), vec!["workload/app/Pod/api".to_string()]);
        let justified = HashSet::from([rbac.cut_signature()]);
        assert!(
            log.reconcile(
                &health(&[("workload/app/Pod/api", Health::Alive)]),
                &justified
            )
            .is_empty()
        );
        assert_eq!(log.active_count(), 1);
    }
}
