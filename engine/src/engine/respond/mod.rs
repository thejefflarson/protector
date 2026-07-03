//! The response layer in **easy mode** (ADR-0002, Questions 4 and 5): turn proven
//! chains into *proposed* minimal-cut mitigations, and track them as debt.
//!
//! This takes no privileged action — it proposes. The central invariant it
//! realizes (ADR-0002 Q5) is:
//!
//! > The set of active compensating controls is exactly the set whose justifying
//! > attack chain is currently proven.
//!
//! So [`MitigationLedger::reconcile`] is the whole thing: given this cycle's proven
//! chains, a mitigation is *proposed* when a new severing cut appears and *retired*
//! when no remaining chain justifies it. Adding controls (Q4) and retiring them as
//! posture improves (Q5) are the same operation, run in both directions, both
//! gated by deterministic proof. Hard mode (actually applying/reverting the
//! engine-owned object) bolts onto this via the Actuator port; the ledger is its
//! source of truth.

pub mod actuator;

use std::collections::BTreeMap;

use crate::engine::graph::attack::AttackRef;
use crate::engine::reason::proof::{Link, ProvenChain};

/// How a cut edge would be severed by an additive, engine-owned object (ADR-0002).
/// Descriptive here — the Actuator port renders these into concrete objects in
/// hard mode. Reversibility is noted so destructive actions are never auto-enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProposedAction {
    /// Sever a `reaches` edge with a scoped deny NetworkPolicy / AuthorizationPolicy.
    DenyNetworkPath,
    /// Sever a `can-do` RBAC grant by removing the binding that confers it.
    RevokeRbacGrant,
    /// Sever a `can-read` edge by removing the secret mount/reference.
    RemoveSecretMount,
    /// Sever an `escapes-to` edge by removing the escape primitive — disruptive,
    /// proposal-only, never auto-enabled.
    RemoveEscapePrimitive,
    /// Sever a `runs-as` edge by rebinding the workload to a least-privilege identity.
    RebindIdentity,
    /// Quarantine the internet-facing breach **entry** with a full default-deny
    /// `NetworkPolicy` (ADR-0010) — the *default* containment when a chain has no
    /// reversible additive edge-cut (a direct mount/RBAC chain, or a broad grant).
    /// Additive (a new object) and reversible (delete to lift), so it can be applied
    /// live without fighting GitOps. It targets the entry *only* — never a deeper or
    /// objective workload — cutting the front door's whole reach, which contains the
    /// lateral chain without punishing the victim data plane.
    QuarantineEntry,
    /// A cut whose remediation isn't yet mapped to an action.
    Unclassified,
}

impl ProposedAction {
    /// Classify the action from the cut edge's relation label.
    pub fn for_cut(cut: &Link) -> Self {
        let r = cut.relation.as_str();
        if r.starts_with("reaches") || r.starts_with("can-egress") {
            // Both are severable by an additive, reversible network deny — ingress for
            // reaches, egress for the exfil channel.
            ProposedAction::DenyNetworkPath
        } else if r.starts_with("can-do") {
            ProposedAction::RevokeRbacGrant
        } else if r == "can-read" {
            ProposedAction::RemoveSecretMount
        } else if r.starts_with("escapes-to") {
            ProposedAction::RemoveEscapePrimitive
        } else if r == "runs-as" {
            ProposedAction::RebindIdentity
        } else {
            ProposedAction::Unclassified
        }
    }

    /// Whether the action self-reverts cleanly (deleting an additive object). All
    /// current actions are reversible except escape-primitive removal, which
    /// changes the workload itself.
    pub fn is_reversible(&self) -> bool {
        !matches!(self, ProposedAction::RemoveEscapePrimitive)
    }

    /// Whether this cut can be made live as an **additive, engine-owned object**
    /// (ADR-0002) — the only thing the engine may apply without fighting GitOps.
    /// Only network denials qualify: a deny `NetworkPolicy`/`AuthorizationPolicy`
    /// is a *new* object. Revoking an RBAC grant, removing a secret mount, or
    /// removing an escape primitive are *subtractive* edits to git-managed objects,
    /// so they can't be applied additively — they are durable-fix-PR territory, not
    /// live actuation. [`QuarantineEntry`](Self::QuarantineEntry) also qualifies: a
    /// full default-deny `NetworkPolicy` on the entry is a *new* object (ADR-0010).
    pub fn is_additive_live(&self) -> bool {
        matches!(
            self,
            ProposedAction::DenyNetworkPath | ProposedAction::QuarantineEntry
        )
    }

    pub fn describe(&self) -> &'static str {
        match self {
            ProposedAction::DenyNetworkPath => {
                "add a scoped deny NetworkPolicy/AuthorizationPolicy"
            }
            ProposedAction::RevokeRbacGrant => "remove the RBAC binding granting this verb",
            ProposedAction::RemoveSecretMount => "remove the secret mount/reference",
            ProposedAction::RemoveEscapePrimitive => "remove the container-escape primitive",
            ProposedAction::RebindIdentity => "rebind to a least-privilege ServiceAccount",
            ProposedAction::QuarantineEntry => {
                "quarantine the internet-facing entry with a default-deny NetworkPolicy"
            }
            ProposedAction::Unclassified => "manual remediation (no automatic action mapped)",
        }
    }
}

/// Why a mitigation exists: a proven chain it severs. When no justification
/// remains, the mitigation retires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Justification {
    pub entry: String,
    pub objective: String,
    pub attack: AttackRef,
    /// Whether the justifying chain had a proven foothold, live corroboration, and
    /// model adjudication — i.e. met the full action bar and wasn't vetoed. Carried
    /// here so the actuator can require it before auto-applying.
    pub foothold: bool,
    pub corroborated: bool,
    pub adjudicated: bool,
    /// The model promoted this chain (ADR-0011) — a positive judgement standing in
    /// for runtime corroboration as the auto-action trigger.
    pub promoted: bool,
    /// Whether the justifying chain is breach-relevant (internet-facing entry).
    /// Required for auto-action: the engine protects against *remote* exploitation,
    /// so it never auto-cuts an internal-only path even when corroborated.
    pub breach_relevant: bool,
}

impl Justification {
    fn of(chain: &ProvenChain) -> Self {
        Self {
            entry: chain.entry.0.clone(),
            objective: chain.objective.0.clone(),
            attack: chain.attack,
            foothold: chain.foothold.is_some(),
            corroborated: chain.corroborated,
            adjudicated: chain.adjudicated,
            promoted: chain.promoted,
            breach_relevant: chain.is_breach_relevant(),
        }
    }
}

/// A proposed compensating control: one edge to cut, the action that would cut it,
/// and every proven chain that justifies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mitigation {
    pub cut: Link,
    pub action: ProposedAction,
    pub justifications: Vec<Justification>,
}

impl Mitigation {
    /// Stable identity of this mitigation: the edge it cuts. Shared with the action
    /// lifecycle so a recorded action can be matched back to the chains that still
    /// justify it.
    pub fn cut_signature(&self) -> String {
        cut_signature(&self.cut)
    }

    /// Whether some justifying chain is **auto-actionable**: a breach-relevant
    /// (internet-facing entry) chain that is either live-corroborated (ADR-0009) or
    /// model-promoted (ADR-0011), and not vetoed by the adjudicator (ADR-0013). A KEV
    /// foothold is not required, but an internet-facing entry is — the engine
    /// auto-acts only on remote-exploitation paths, never on internal-only activity.
    /// The actuator requires this before any auto-application.
    pub fn is_live_corroborated(&self) -> bool {
        self.justifications
            .iter()
            .any(|j| (j.corroborated || j.promoted) && j.adjudicated && j.breach_relevant)
    }
}

/// Stable identity of a cut edge. One cut can break several chains, so this is
/// keyed on the edge, not the chain.
pub fn cut_signature(cut: &Link) -> String {
    format!("{} -[{}]-> {}", cut.from.0, cut.relation, cut.to.0)
}

/// The synthetic relation on a [`ProposedAction::QuarantineEntry`] mitigation's
/// `cut` link. A quarantine severs no single edge — it default-denies the entry
/// itself — so its `Link` is a self-reference on the entry (`from == to == entry`)
/// carrying the entry's labels. That gives it a stable per-entry signature for the
/// ledger/self-revert lifecycle, distinct from any edge-cut, and lets the isolation
/// renderer reuse the `cut.from` selector path unchanged.
const QUARANTINE_RELATION: &str = "quarantine-entry";

/// Build the quarantine `Link` for a chain: a self-reference on the internet-facing
/// entry, carrying the entry's labels so the isolation `NetworkPolicy` selects the
/// entry pod precisely (ADR-0010). Returns `None` when the entry has no labels — we
/// will not widen a quarantine to a whole namespace (that would punish bystanders);
/// such a chain falls through to durable-fix/no-cut instead.
fn quarantine_link(chain: &ProvenChain) -> Option<Link> {
    // The first hop's `from` is always the entry (the path is reconstructed from the
    // entry outward), and its `from_labels` are the entry workload's labels.
    let first = chain.links.first()?;
    if first.from_labels.is_empty() {
        return None;
    }
    Some(Link {
        from: chain.entry.clone(),
        to: chain.entry.clone(),
        relation: QUARANTINE_RELATION.to_string(),
        technique: None,
        from_labels: first.from_labels.clone(),
        to_labels: first.from_labels.clone(),
    })
}

/// Choose the single containment for a chain, by the ADR-0009/0010 precedence — the
/// narrowest control first, the entry quarantine as the default, durable-fix last:
///
/// 1. a **reversible additive** `reaches`/`can-egress` single-edge cut exists → the
///    surgical [`DenyNetworkPath`](ProposedAction::DenyNetworkPath) edge-cut
///    (unchanged — the narrowest control, preferred whenever it suffices);
/// 2. else, a **breach-relevant** chain (internet-facing entry) with a labelled entry
///    → [`QuarantineEntry`](ProposedAction::QuarantineEntry), the *default*
///    containment — a full default-deny on the entry contains the whole chain without
///    touching the objective/data plane;
/// 3. else → the first single-edge cut as a durable-fix/no-cut proposal (unchanged):
///    subtractive RBAC/mount edits route to a PR, and a chain with no single cut is
///    surfaced as unsevered.
///
/// Returns the `(cut, action)` seed for a mitigation, or `None` when nothing severs
/// the chain (an unsevered finding).
pub fn containment_for(chain: &ProvenChain) -> Option<(Link, ProposedAction)> {
    // 1. Surgical network edge-cut: the first single-edge cut that is additive-live
    //    and reversible (i.e. a `reaches`/`can-egress` DenyNetworkPath). Preferred
    //    whenever it exists — it drops one edge, not the entry's whole reach.
    if let Some(cut) = chain.single_edge_cuts.iter().find(|c| {
        let action = ProposedAction::for_cut(c);
        action.is_additive_live() && action.is_reversible()
    }) {
        // The only edge relation that is both additive-live and reversible is a
        // network deny, so the action is DenyNetworkPath by construction.
        return Some((cut.clone(), ProposedAction::DenyNetworkPath));
    }
    // 2. Default containment: quarantine the internet-facing entry.
    if chain.is_breach_relevant()
        && let Some(cut) = quarantine_link(chain)
    {
        return Some((cut, ProposedAction::QuarantineEntry));
    }
    // 3. Durable-fix / no-cut: the first single-edge cut (subtractive → PR), if any.
    chain
        .single_edge_cuts
        .first()
        .map(|cut| (cut.clone(), ProposedAction::for_cut(cut)))
}

/// What changed in the ledger this cycle.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LedgerDelta {
    /// Mitigations newly justified this cycle (Q4 — add a control).
    pub proposed: Vec<Mitigation>,
    /// Mitigations no longer justified by any proven chain (Q5 — retire as posture
    /// improves).
    pub retired: Vec<Mitigation>,
    /// Chains with no single-edge cut: breaking them needs more than one action, so
    /// no minimal-cut mitigation is proposed. Surfaced, not silently dropped.
    pub unsevered: Vec<Justification>,
}

impl LedgerDelta {
    pub fn is_empty(&self) -> bool {
        self.proposed.is_empty() && self.retired.is_empty() && self.unsevered.is_empty()
    }

    /// Log proposed and retired mitigations, plus any chain that can't be cut with
    /// a single action.
    pub fn emit(&self) {
        for m in &self.proposed {
            tracing::info!(
                cut = %cut_signature(&m.cut),
                action = m.action.describe(),
                reversible = m.action.is_reversible(),
                justified_by = m.justifications.len(),
                "mitigation proposed"
            );
        }
        for m in &self.retired {
            tracing::info!(cut = %cut_signature(&m.cut), "mitigation retired (chain no longer proven)");
        }
        // Chains with no single reversible cut (typically broad multi-verb / cluster-
        // wide secret RBAC, severable only by narrowing the grant). These are in the findings
        // snapshot already and recomputed every pass, so log a one-line summary
        // at info and the per-chain detail at debug — not a WARN per chain per pass.
        if !self.unsevered.is_empty() {
            tracing::info!(
                count = self.unsevered.len(),
                "chains with no single-edge cut (need deeper remediation, e.g. narrow an RBAC grant)"
            );
            for j in &self.unsevered {
                tracing::debug!(
                    entry = %j.entry,
                    objective = %j.objective,
                    technique = j.attack.technique_id,
                    "no single-edge cut"
                );
            }
        }
    }
}

/// The mitigation ledger: the set of active compensating-control proposals, keyed
/// by the edge each cuts. Stateful across cycles so it can detect what newly
/// appears and what should retire.
#[derive(Debug, Default)]
pub struct MitigationLedger {
    active: BTreeMap<String, Mitigation>,
}

impl MitigationLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconcile the ledger against this cycle's proven chains. The active set
    /// becomes exactly the mitigations justified by a current chain; the delta
    /// reports what that added and removed.
    pub fn reconcile(&mut self, chains: &[ProvenChain]) -> LedgerDelta {
        let mut desired: BTreeMap<String, Mitigation> = BTreeMap::new();
        let mut unsevered = Vec::new();

        for chain in chains {
            // Choose the containment by precedence (surgical edge-cut → entry
            // quarantine → durable-fix). A chain with none can't be severed by one
            // action, so it is surfaced as unsevered.
            match containment_for(chain) {
                Some((cut, action)) => {
                    desired
                        .entry(cut_signature(&cut))
                        .or_insert_with(|| Mitigation {
                            cut,
                            action,
                            justifications: Vec::new(),
                        })
                        .justifications
                        .push(Justification::of(chain));
                }
                None => unsevered.push(Justification::of(chain)),
            }
        }

        let proposed = desired
            .iter()
            .filter(|(k, _)| !self.active.contains_key(*k))
            .map(|(_, m)| m.clone())
            .collect();
        let retired = self
            .active
            .iter()
            .filter(|(k, _)| !desired.contains_key(*k))
            .map(|(_, m)| m.clone())
            .collect();

        self.active = desired;
        LedgerDelta {
            proposed,
            retired,
            unsevered,
        }
    }

    /// The currently-active mitigation proposals.
    pub fn active(&self) -> impl Iterator<Item = &Mitigation> {
        self.active.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::observe::Snapshot;
    use crate::engine::observe::adapter::{build_graph, default_adapters};
    use crate::engine::reason::proof::prove;
    use serde_json::json;

    /// A lateral chain web →reaches→ db →can-read→ secret, whose first cut is the
    /// `reaches` edge → a DenyNetworkPath proposal.
    fn lateral_chain_snapshot() -> Snapshot {
        let web = json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "web", "namespace": "app", "labels": {"role": "web"}},
            "spec": {"containers": [{"name": "c", "image": "web:1"}]}
        });
        let db = json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "db", "namespace": "app", "labels": {"role": "db"}},
            "spec": {"containers": [{
                "name": "db", "image": "db:1",
                "envFrom": [{"secretRef": {"name": "db-creds"}}]
            }]}
        });
        let policy = json!({
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "db-ingress", "namespace": "app"},
            "spec": {
                "podSelector": {"matchLabels": {"role": "db"}},
                "policyTypes": ["Ingress"],
                "ingress": [{"from": [{"podSelector": {"matchLabels": {"role": "web"}}}]}]
            }
        });
        Snapshot {
            pods: vec![
                serde_json::from_value(web).unwrap(),
                serde_json::from_value(db).unwrap(),
            ],
            network_policies: vec![serde_json::from_value(policy).unwrap()],
            ..Default::default()
        }
    }

    #[test]
    fn proposes_a_mitigation_for_a_cuttable_chain() {
        let chains = prove(&build_graph(&lateral_chain_snapshot(), &default_adapters()));
        let mut ledger = MitigationLedger::new();
        let delta = ledger.reconcile(&chains);

        assert!(
            !delta.proposed.is_empty(),
            "a cuttable chain proposes a mitigation"
        );
        assert!(
            delta
                .proposed
                .iter()
                .any(|m| m.action == ProposedAction::DenyNetworkPath
                    || m.action == ProposedAction::RemoveSecretMount),
            "the web→db→secret cut is a network or mount action"
        );
    }

    /// Auto-action requires an internet-facing entry: a corroborated, adjudicated
    /// chain whose entry is internal-only is NOT live-actionable — the engine acts
    /// on remote exploitation, not normal internal activity.
    #[test]
    fn auto_action_requires_a_breach_relevant_entry() {
        use crate::engine::graph::NodeKey;
        use crate::engine::graph::attack::CREDENTIAL_ACCESS;

        let justify = |breach_relevant: bool| Justification {
            entry: "workload/app/Pod/x".into(),
            objective: "secret/app/s".into(),
            attack: CREDENTIAL_ACCESS,
            foothold: false,
            corroborated: true,
            adjudicated: true,
            promoted: false,
            breach_relevant,
        };
        let mitigation = |breach_relevant: bool| Mitigation {
            cut: Link {
                from: NodeKey("workload/app/Pod/x".into()),
                to: NodeKey("workload/app/Pod/y".into()),
                relation: "reaches/Tcp".into(),
                technique: None,
                from_labels: Default::default(),
                to_labels: Default::default(),
            },
            action: ProposedAction::DenyNetworkPath,
            justifications: vec![justify(breach_relevant)],
        };
        assert!(
            mitigation(true).is_live_corroborated(),
            "internet-facing + corroborated ⇒ auto-actionable"
        );
        assert!(
            !mitigation(false).is_live_corroborated(),
            "internal-only corroborated ⇒ NOT auto-actionable (context, not a breach)"
        );
    }

    #[test]
    fn reconcile_is_idempotent_then_retires_when_chains_vanish() {
        let chains = prove(&build_graph(&lateral_chain_snapshot(), &default_adapters()));
        let mut ledger = MitigationLedger::new();

        let first = ledger.reconcile(&chains);
        assert!(!first.proposed.is_empty());
        let active_after_first = ledger.active().count();

        // Same chains again: nothing new proposed, nothing retired.
        let second = ledger.reconcile(&chains);
        assert!(second.proposed.is_empty());
        assert!(second.retired.is_empty());
        assert_eq!(ledger.active().count(), active_after_first);

        // Posture improves — all chains gone. Every mitigation retires (Q5).
        let third = ledger.reconcile(&[]);
        assert!(third.proposed.is_empty());
        assert_eq!(third.retired.len(), active_after_first);
        assert_eq!(ledger.active().count(), 0);
    }

    // --- ADR-0010 default containment: quarantine the internet-facing entry ---

    /// A LoadBalancer Service selecting `app` labels — the exposure adapter marks the
    /// selected pod internet-facing (`Exposure::Internet`), making its chains
    /// breach-relevant.
    fn internet_lb(namespace: &str, app: &str) -> serde_json::Value {
        json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": format!("{app}-lb"), "namespace": namespace},
            "spec": {"type": "LoadBalancer", "selector": {"app": app}}
        })
    }

    /// A DIRECT breach chain: an internet-facing pod that itself mounts the secret
    /// (`entry -can-read-> secret`). Its only cut is the subtractive mount — no
    /// reversible additive edge-cut — so containment defaults to quarantining the entry.
    fn direct_mount_internet_snapshot() -> Snapshot {
        let web = json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "argocd-server", "namespace": "edge", "labels": {"app": "argocd-server"}},
            "spec": {"containers": [{
                "name": "c", "image": "argo:1",
                "envFrom": [{"secretRef": {"name": "repo-creds"}}]
            }]}
        });
        Snapshot {
            pods: vec![serde_json::from_value(web).unwrap()],
            services: vec![serde_json::from_value(internet_lb("edge", "argocd-server")).unwrap()],
            ..Default::default()
        }
    }

    /// The single QuarantineEntry mitigation in a delta (asserting exactly one).
    fn only_quarantine(delta: &LedgerDelta) -> Mitigation {
        let quarantines: Vec<_> = delta
            .proposed
            .iter()
            .filter(|m| m.action == ProposedAction::QuarantineEntry)
            .collect();
        assert_eq!(
            quarantines.len(),
            1,
            "exactly one QuarantineEntry proposed, got {:?}",
            delta.proposed
        );
        quarantines[0].clone()
    }

    #[test]
    fn direct_mount_chain_quarantines_the_entry_not_the_objective() {
        let chains = prove(&build_graph(
            &direct_mount_internet_snapshot(),
            &default_adapters(),
        ));
        let mut ledger = MitigationLedger::new();
        let delta = ledger.reconcile(&chains);

        let q = only_quarantine(&delta);
        // Targets ONLY the internet-facing entry (from == to == entry), never the secret.
        assert_eq!(q.cut.from.0, "workload/edge/Pod/argocd-server");
        assert_eq!(q.cut.to.0, "workload/edge/Pod/argocd-server");
        assert_eq!(
            q.cut.from_labels.get("app").map(String::as_str),
            Some("argocd-server")
        );
        assert!(
            delta
                .proposed
                .iter()
                .all(|m| !m.cut.from.0.starts_with("secret/") && !m.cut.to.0.starts_with("secret/")),
            "no mitigation ever targets the objective secret"
        );
    }

    #[test]
    fn direct_rbac_chain_quarantines_the_entry() {
        use crate::engine::observe::SecretMeta;
        use k8s_openapi::api::rbac::v1::{Role, RoleBinding};

        let app = json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "watcher-server", "namespace": "edge", "labels": {"app": "watcher-server"}},
            "spec": {
                "serviceAccountName": "watcher-sa",
                "containers": [{"name": "c", "image": "watcher:1"}]
            }
        });
        let role: Role = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": "reader", "namespace": "edge"},
            "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]
        }))
        .unwrap();
        let binding: RoleBinding = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": "reader-binding", "namespace": "edge"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "reader"},
            "subjects": [{"kind": "ServiceAccount", "name": "watcher-sa", "namespace": "edge"}]
        }))
        .unwrap();
        let snap = Snapshot {
            pods: vec![serde_json::from_value(app).unwrap()],
            services: vec![serde_json::from_value(internet_lb("edge", "watcher-server")).unwrap()],
            secrets: vec![SecretMeta {
                namespace: "edge".into(),
                name: "api-key".into(),
            }],
            roles: vec![role],
            role_bindings: vec![binding],
            ..Default::default()
        };
        let chains = prove(&build_graph(&snap, &default_adapters()));
        let mut ledger = MitigationLedger::new();
        let delta = ledger.reconcile(&chains);

        let q = only_quarantine(&delta);
        // The entry pod is quarantined — never the RBAC identity or the secret.
        assert_eq!(q.cut.from.0, "workload/edge/Pod/watcher-server");
        assert_eq!(
            q.cut.from_labels.get("app").map(String::as_str),
            Some("watcher-server")
        );
    }

    #[test]
    fn lateral_chain_with_reversible_reaches_stays_surgical() {
        use crate::engine::graph::{Provenance, Severity, Vulnerability};
        use crate::engine::observe::ImageVulnerabilities;
        use std::time::SystemTime;

        // A REAL lateral breach: an internet-facing `web` entry reaches a
        // *compromisable* `db` (a critical CVE lets the walk pivot through it) that
        // mounts the secret. The `reaches` edge is a reversible additive edge-cut, so
        // containment stays the surgical DenyNetworkPath — quarantine is only the
        // fallback when no such edge-cut exists.
        let web = json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "web", "namespace": "app", "labels": {"role": "web"}},
            "spec": {"containers": [{"name": "c", "image": "web:1"}]}
        });
        let db = json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "db", "namespace": "app", "labels": {"role": "db"}},
            "spec": {"containers": [{
                "name": "db", "image": "db:1",
                "envFrom": [{"secretRef": {"name": "db-creds"}}]
            }]}
        });
        let policy = json!({
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "db-ingress", "namespace": "app"},
            "spec": {
                "podSelector": {"matchLabels": {"role": "db"}},
                "policyTypes": ["Ingress"],
                "ingress": [{"from": [{"podSelector": {"matchLabels": {"role": "web"}}}]}]
            }
        });
        let lb = json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "web-lb", "namespace": "app"},
            "spec": {"type": "LoadBalancer", "selector": {"role": "web"}}
        });
        let snap = Snapshot {
            pods: vec![
                serde_json::from_value(web).unwrap(),
                serde_json::from_value(db).unwrap(),
            ],
            network_policies: vec![serde_json::from_value(policy).unwrap()],
            services: vec![serde_json::from_value(lb).unwrap()],
            image_vulns: vec![ImageVulnerabilities {
                image: "db:1".into(),
                vulnerabilities: vec![Vulnerability {
                    id: "CVE-2026-0001".into(),
                    severity: Severity::Critical,
                    exploited_in_wild: false,
                    epss: Some(0.5),
                    sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
                    ..Default::default()
                }],
            }],
            ..Default::default()
        };

        let chains = prove(&build_graph(&snap, &default_adapters()));
        let mut ledger = MitigationLedger::new();
        let delta = ledger.reconcile(&chains);

        // The internet-facing web→db→secret chain is contained by the surgical reaches cut.
        assert!(
            delta
                .proposed
                .iter()
                .any(|m| m.action == ProposedAction::DenyNetworkPath
                    && m.cut.relation.starts_with("reaches")
                    && m.cut.from.0 == "workload/app/Pod/web"),
            "a reversible reaches edge-cut is chosen surgically, got {:?}",
            delta.proposed
        );
        // The web (internet-facing) entry is never quarantined — the edge-cut suffices.
        assert!(
            delta
                .proposed
                .iter()
                .all(|m| !(m.action == ProposedAction::QuarantineEntry
                    && m.cut.from.0 == "workload/app/Pod/web")),
            "no quarantine of the entry when a surgical edge-cut suffices, got {:?}",
            delta.proposed
        );
    }

    #[test]
    fn internal_direct_mount_is_not_quarantined() {
        // The same direct mount chain but with NO internet exposure: not breach-relevant,
        // so it stays a durable-fix (RemoveSecretMount), never a quarantine.
        let mut snap = direct_mount_internet_snapshot();
        snap.services.clear();

        let chains = prove(&build_graph(&snap, &default_adapters()));
        let mut ledger = MitigationLedger::new();
        let delta = ledger.reconcile(&chains);

        assert!(
            delta
                .proposed
                .iter()
                .all(|m| m.action != ProposedAction::QuarantineEntry),
            "no internet-facing entry ⇒ no quarantine"
        );
        assert!(
            delta
                .proposed
                .iter()
                .any(|m| m.action == ProposedAction::RemoveSecretMount),
            "an internal direct mount stays a durable-fix PR"
        );
    }

    #[test]
    fn quarantine_entry_self_reverts_when_its_chain_is_gone() {
        // ADR-0017: a QuarantineEntry mitigation retires on the same lifecycle as an
        // edge-cut — keyed on the chain, it drops out when no chain still justifies it.
        let chains = prove(&build_graph(
            &direct_mount_internet_snapshot(),
            &default_adapters(),
        ));
        let mut ledger = MitigationLedger::new();

        let first = ledger.reconcile(&chains);
        let q = only_quarantine(&first);
        assert!(
            ledger
                .active()
                .any(|m| m.cut_signature() == q.cut_signature())
        );

        // Posture improves — the chain is gone. The quarantine retires (Q5).
        let retired = ledger.reconcile(&[]);
        assert!(
            retired
                .retired
                .iter()
                .any(|m| m.action == ProposedAction::QuarantineEntry
                    && m.cut_signature() == q.cut_signature()),
            "the quarantine retires when its justifying chain vanishes"
        );
        assert_eq!(ledger.active().count(), 0);
    }
}
