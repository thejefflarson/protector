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

use std::collections::BTreeMap;

use super::attack::AttackRef;
use super::proof::{Link, ProvenChain};

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
    /// A cut whose remediation isn't yet mapped to an action.
    Unclassified,
}

impl ProposedAction {
    /// Classify the action from the cut edge's relation label.
    pub fn for_cut(cut: &Link) -> Self {
        let r = cut.relation.as_str();
        if r.starts_with("reaches") {
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
    /// live actuation.
    pub fn is_additive_live(&self) -> bool {
        matches!(self, ProposedAction::DenyNetworkPath)
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
        for j in &self.unsevered {
            tracing::warn!(
                entry = %j.entry,
                objective = %j.objective,
                technique = j.attack.technique_id,
                "no single-edge cut — chain needs deeper remediation"
            );
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
            // Choose the narrowest action: the first single-edge cut. A chain with
            // none can't be severed by one action.
            match chain.single_edge_cuts.first() {
                Some(cut) => {
                    desired
                        .entry(cut_signature(cut))
                        .or_insert_with(|| Mitigation {
                            cut: cut.clone(),
                            action: ProposedAction::for_cut(cut),
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
    use crate::engine::adapter::{build_graph, default_adapters};
    use crate::engine::observe::Snapshot;
    use crate::engine::proof::prove;
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
        use crate::engine::attack::CREDENTIAL_ACCESS;
        use crate::engine::graph::NodeKey;

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
}
