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
use crate::engine::reason::proof::{Link, ProvenChain, QuarantineTarget};

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
    /// Quarantine a **compromised workload on the chain** — not the entry — with the
    /// same full default-deny `NetworkPolicy` (ADR-0010), driven from the qualifying
    /// pod's labels (JEF-284). Proposed for a pod that is either *remotely exploitable*
    /// (network-reachable from an internet foothold AND running a critical/KEV CVE) or
    /// *actively exploited* (a live on-pod runtime alert / hands-on-keyboard exec) —
    /// see [`crate::engine::reason::proof::QuarantineReason`]. Additive + reversible +
    /// self-reverting, gated identically to [`QuarantineEntry`](Self::QuarantineEntry).
    /// Never targets a merely-reached objective (reached ≠ exploited).
    QuarantineWorkload,
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
            ProposedAction::DenyNetworkPath
                | ProposedAction::QuarantineEntry
                | ProposedAction::QuarantineWorkload
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
            ProposedAction::QuarantineWorkload => {
                "quarantine the compromised workload with a default-deny NetworkPolicy"
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
        // A workload quarantine (JEF-284) already cleared a HIGH *per-pod* exploitation
        // bar at target selection in the proof layer: either a critical/KEV CVE running
        // on a pod network-reachable from an internet foothold (remotely exploitable), or
        // a live on-pod alert / hands-on-keyboard exec (actively exploited). That per-pod
        // evidence — not the entry-scoped, breach-relevant corroboration below — is the
        // auto-action trigger, and it deliberately holds for INTERNAL actively-exploited
        // pods too (condition 2 acts regardless of network position). The remaining safety
        // gates (blast-radius, enabled class, scope) still apply in [`decide`]; audit arms
        // nothing, so this stays PROPOSE-only until an operator enforces `network`.
        if self.action == ProposedAction::QuarantineWorkload {
            return true;
        }
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

/// The synthetic relation on a [`ProposedAction::QuarantineWorkload`] mitigation's
/// `cut` link (JEF-284). Like the entry quarantine it is a self-reference on the pod
/// (`from == to == pod`) carrying the pod's labels, so the isolation renderer's
/// `cut.from` selector isolates exactly that pod. It is **pod-only** (reason-independent)
/// so a pod that qualifies on more than one chain — remotely-exploitable on one,
/// actively-exploited on another — collapses to a single quarantine, never two competing
/// isolation objects. The dashboard names the WHY from the chain's
/// [`QuarantineReason`](crate::engine::reason::proof::QuarantineReason), not this relation.
const QUARANTINE_WORKLOAD_RELATION: &str = "quarantine-workload";

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

/// Build the quarantine `Link` for a JEF-284 workload target: a self-reference on the
/// qualifying pod, carrying its labels so the isolation `NetworkPolicy` selects that
/// pod precisely (ADR-0010). Returns `None` when the pod has no labels — we decline
/// (never widen a quarantine to a whole namespace, punishing bystanders), exactly as
/// [`quarantine_link`] does for the entry.
fn quarantine_workload_link(target: &QuarantineTarget) -> Option<Link> {
    if target.labels.is_empty() {
        return None;
    }
    Some(Link {
        from: target.node.clone(),
        to: target.node.clone(),
        relation: QUARANTINE_WORKLOAD_RELATION.to_string(),
        technique: None,
        from_labels: target.labels.clone(),
        to_labels: target.labels.clone(),
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
            let primary = containment_for(chain);
            match &primary {
                Some((cut, action)) => {
                    desired
                        .entry(cut_signature(cut))
                        .or_insert_with(|| Mitigation {
                            cut: cut.clone(),
                            action: *action,
                            justifications: Vec::new(),
                        })
                        .justifications
                        .push(Justification::of(chain));
                }
                None => unsevered.push(Justification::of(chain)),
            }

            // Sibling pass (JEF-284): additionally quarantine each *compromised workload
            // on the chain* — a remotely-exploitable or actively-exploited pod. Independent
            // of the primary containment, so several qualifying pods on one chain are each
            // isolated (independent compromises). The chain **entry** is governed entirely
            // by the primary above: when the primary already contains it with an additive-
            // live control (surgical edge-cut or entry quarantine) we skip the entry here,
            // preserving JEF-279's behavior and the "prefer the narrower surgical cut"
            // invariant. The entry is quarantined here only when nothing else contained it —
            // the internal actively-exploited pod whose primary is a durable-fix / no-cut.
            let entry_additively_contained = primary
                .as_ref()
                .is_some_and(|(_, action)| action.is_additive_live());
            for target in &chain.quarantine_targets {
                if target.node == chain.entry && entry_additively_contained {
                    continue;
                }
                let Some(cut) = quarantine_workload_link(target) else {
                    continue; // no labels — decline rather than widen to a namespace
                };
                desired
                    .entry(cut_signature(&cut))
                    .or_insert_with(|| Mitigation {
                        cut,
                        action: ProposedAction::QuarantineWorkload,
                        justifications: Vec::new(),
                    })
                    .justifications
                    .push(Justification::of(chain));
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
mod tests;
