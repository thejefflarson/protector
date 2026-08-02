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

use petgraph::visit::EdgeRef;

use crate::engine::graph::attack::AttackRef;
use crate::engine::graph::{Node, NodeKey, Relation, SecurityGraph};
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
    /// pod's labels. Proposed for a pod that is either *remotely exploitable*
    /// (network-reachable from an internet foothold AND running a critical/KEV CVE) or
    /// *actively exploited* (a live on-pod runtime alert / hands-on-keyboard exec) —
    /// see [`crate::engine::reason::proof::QuarantineReason`]. Additive + reversible +
    /// self-reverting, gated identically to [`QuarantineEntry`](Self::QuarantineEntry).
    /// Never targets a merely-reached objective (reached ≠ exploited).
    QuarantineWorkload,
    /// Contain a **proven pod-boundary break** ([`crate::engine::reason::proof::boundary_break`],
    /// ADR-0040) at the NODE, not the pod: cordon the `Host` the model-named workload is
    /// scheduled on, plus a default-deny `NetworkPolicy` per co-resident labelled pod. The
    /// deterministic escalation of a model-named workload whose own evidence proves a
    /// `podSelector` policy no longer constrains it — never a model-selectable mechanism
    /// (the model still only names the workload; [`crate::engine::reason::adjudicate::incident::menu`]
    /// resolves the escalation the moment `boundary_break` holds). Reversible (an uncordon
    /// lifts it) but deliberately **not** [`is_additive_live`](Self::is_additive_live): a
    /// cordon mutates a shared field on a live `Node` object rather than adding a new
    /// engine-owned one, so this class can never auto-apply — every node cut is
    /// propose-first by construction, routed to a human via the existing blast/alive-
    /// collateral gate. Shadow-complete as of this ticket: the actuator that would render
    /// the cordon + co-resident denies lands separately (ADR-0040 §7).
    ContainNode,
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
            ProposedAction::ContainNode => {
                "cordon the node and default-deny its co-resident pods (proven pod-boundary \
                 break — a pod-scoped policy can no longer contain this workload)"
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
    ///
    /// **`QuarantineWorkload` clears the SAME gate as every other action —
    /// no special case.** A workload quarantine still identifies its target
    /// deterministically at the proof layer (a pod on-path that is either network-
    /// reachable + running a critical/KEV CVE, or carries a live on-pod exploitation
    /// signal — `reason::proof::chain::quarantine_targets_on_path`), but that
    /// per-pod evidence is now only a *proposal* trigger. Auto-*action* additionally
    /// requires the pod's justifying chain — the one whose internet-facing entry it
    /// sits on — to be corroborated/promoted, adjudicated, and breach-relevant, per
    /// ADR-0032 ("the model is the incident responder"): a downstream
    /// `RemotelyExploitable` pod behind a clean/unpromoted edge is propose-only, and
    /// an internal-only actively-exploited pod (no internet-facing entry) is
    /// propose-only too. This is a **reduction** in auto-action versus the prior
    /// unconditional-`true` special case — it can only move a mitigation from
    /// AutoApply to Propose, never the reverse.
    pub fn is_live_corroborated(&self) -> bool {
        self.live_corroborating_entries().next().is_some()
    }

    /// The internet-facing entries whose justification clears the SAME bar
    /// [`is_live_corroborated`](Self::is_live_corroborated) checks — corroborated or
    /// promoted, adjudicated, and breach-relevant — yielding the entry keys rather than a
    /// bool. Exposed separately so the engine's actuation-freshness gate can check THOSE
    /// SPECIFIC entries' verdict age against the verdict store, without `respond`/`actuator`
    /// taking a dependency on `state::VerdictStore` (this module stays pure over its own
    /// types). The one predicate lives here; `is_live_corroborated` is just "any at all".
    pub fn live_corroborating_entries(&self) -> impl Iterator<Item = &str> {
        self.justifications
            .iter()
            .filter(|j| (j.corroborated || j.promoted) && j.adjudicated && j.breach_relevant)
            .map(|j| j.entry.as_str())
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
/// `cut` link. Like the entry quarantine it is a self-reference on the pod
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
///
/// `pub(crate)`: the ADR-0034 `incident/` menu resolver's entry line reuses the
/// SAME [`containment_for`] ladder this module's own `reconcile` runs, so a helper it calls
/// (this one, transitively) must be visible outside `respond`. `reconcile` itself is
/// untouched — only this pure builder's visibility widens.
pub(crate) fn quarantine_link(chain: &ProvenChain) -> Option<Link> {
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

/// Build the quarantine `Link` for a workload target: a self-reference on the
/// qualifying pod, carrying its labels so the isolation `NetworkPolicy` selects that
/// pod precisely (ADR-0010). Returns `None` when the pod has no labels — we decline
/// (never widen a quarantine to a whole namespace, punishing bystanders), exactly as
/// [`quarantine_link`] does for the entry.
///
/// `pub(crate)`: the ADR-0034 `incident/` menu resolver's downstream lines
/// resolve each `quarantine_targets` workload through this exact builder — the SAME
/// `None`-on-unlabeled decline the ledger's `reconcile` uses — so the menu and the ledger
/// can never disagree on which downstream nodes are containable. `reconcile` itself is
/// untouched — only this pure builder's visibility widens.
pub(crate) fn quarantine_workload_link(target: &QuarantineTarget) -> Option<Link> {
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

/// The synthetic relation on a [`ProposedAction::ContainNode`] mitigation's `cut` link — a
/// self-reference on the `Host` node (`from == to == host`), never on the model-named
/// workload. See [`contain_node_link`].
const CONTAIN_NODE_RELATION: &str = "contain-node";

/// Build the [`ProposedAction::ContainNode`] `Link` for a model-named workload `x` whose
/// pod boundary is proven broken ([`crate::engine::reason::proof::boundary_break`],
/// ADR-0040 §3): a self-reference on the `Host` node `x` is scheduled onto (the
/// `Relation::ScheduledOn` placement edge, ADR-0040) — never on `x` itself, because
/// cordoning is a NODE mechanism. Keying the cut on the host (not on `x`) means two
/// co-resident boundary-broken workloads collapse onto ONE containment proposal
/// (`cut_signature` is per-node), matching ADR-0040 §5's "at most one node cordoned
/// concurrently" rather than a duplicate cut per named workload. Carries no labels: cordon
/// acts on `Node.spec.unschedulable`, not a pod selector, so there is nothing to widen
/// (contrast [`quarantine_link`]/[`quarantine_workload_link`]'s label-selector decline).
/// `None` when `x` carries no `ScheduledOn` edge — unscheduled, nothing to cordon (every
/// `boundary_break` trigger needs a live, scheduled pod, so this is not actually reachable
/// in practice; kept fallible rather than panicking).
///
/// `pub(crate)`: the ADR-0034 `incident/` menu resolver calls this the moment
/// `boundary_break(x)` holds, in the SAME `build_menu` pass that would otherwise have
/// resolved `x` to its ordinary pod-scoped cut — the discipline [`quarantine_workload_link`]
/// already documents for its own visibility widening.
pub(crate) fn contain_node_link(graph: &SecurityGraph, x: &NodeKey) -> Option<Link> {
    let x_idx = graph.index_of(x)?;
    let host_idx = graph
        .inner()
        .edges(x_idx)
        .find(|e| matches!(e.weight().relation, Relation::ScheduledOn))
        .map(|e| e.target())?;
    let host = graph.key_of(host_idx)?;
    Some(Link {
        from: host.clone(),
        to: host,
        relation: CONTAIN_NODE_RELATION.to_string(),
        technique: None,
        from_labels: BTreeMap::new(),
        to_labels: BTreeMap::new(),
    })
}

/// Whether cordoning the `Host` node keyed `host` would collaterally sever one of
/// protector's OWN components — the eBPF agent DaemonSet's pod on this node, or the
/// engine's own control-plane pod under the chart's default naming (ADR-0040 "New
/// failure/interaction surfaces": "the approval UI names protector components in the
/// collateral list explicitly"). Checked over every workload with a `ScheduledOn` edge into
/// `host`. Presentation-only — feeds the honest proposal note
/// ([`crate::engine::reason::adjudicate::incident::cut_blast_note`]), never gates anything;
/// the alive-collateral/freshness/break-glass rails the ADR cites are the actual safety
/// backstop, so a label-matching miss here (e.g. under a customized Helm `nameOverride`)
/// only means a milder note, never a functional gap.
pub(crate) fn self_severance(graph: &SecurityGraph, host: &NodeKey) -> bool {
    let Some(host_idx) = graph.index_of(host) else {
        return false;
    };
    graph
        .inner()
        .edges_directed(host_idx, petgraph::Direction::Incoming)
        .filter(|e| matches!(e.weight().relation, Relation::ScheduledOn))
        .filter_map(|e| graph.node(e.source()))
        .any(is_protector_component)
}

/// Label-based identification of protector's own chart-rendered workloads: the agent
/// DaemonSet's `app.kubernetes.io/component: agent` label (`charts/protector/templates/
/// _helpers.tpl`'s `protector.agentLabels`), or the engine Deployment's default
/// `app.kubernetes.io/name: protector` (`protector.selectorLabels` under an un-overridden
/// chart name). See [`self_severance`] for why a miss here is safe.
fn is_protector_component(node: &Node) -> bool {
    let Node::Workload(w) = node else {
        return false;
    };
    w.labels
        .get("app.kubernetes.io/component")
        .is_some_and(|v| v == "agent")
        || w.labels
            .get("app.kubernetes.io/name")
            .is_some_and(|v| v == "protector")
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

/// The `containment_for` human-proposal fallback for one breach-relevant chain's entry (ADR-0034
/// D6) — stamped `adjudicated = false` so [`Mitigation::is_live_corroborated`] can never clear
/// it, no matter how corroborated the chain actually is. Used both when there is no standing
/// cut to carry forward ([`carry_forward_or_fallback`]) and for a decisive `Attack` that named
/// no cut (D1 — a decisive omission).
fn fallback_proposal(chain: &ProvenChain, desired: &mut BTreeMap<String, Mitigation>) {
    let Some((cut, action)) = containment_for(chain) else {
        return;
    };
    let mut justification = Justification::of(chain);
    justification.adjudicated = false;
    desired
        .entry(cut_signature(&cut))
        .or_insert_with(|| Mitigation {
            cut,
            action,
            justifications: Vec::new(),
        })
        .justifications
        .push(justification);
}

/// ADR-0034 D7 (the retirement asymmetry, safety-critical): when this pass has no decisive
/// decision for `chain`'s entry (no decision at all, or a fresh `Uncertain` — model
/// unavailable, not yet judged, or the cold-start window after a restart), it must be INERT —
/// neither open a live attack path nor sever one. A previous pass's model-chosen cut (its
/// signature generally differs from `containment_for`'s own default — a downstream
/// `QuarantineWorkload` line always does) must NOT quietly drop out of the desired set just
/// because this pass rebuilt it from scratch: dropping it would read to the caller as "no
/// longer justified" and trigger the self-revert loop, tearing down a live isolation control on
/// a transient model wobble. So: carry every mitigation ALREADY active for this entry forward
/// unchanged (re-justified against THIS pass's chain, so a genuine chain-clear next pass still
/// retires it structurally, exactly like any other mitigation) — never rebuild from
/// `containment_for` while a standing cut exists. Only when there is NO standing cut for this
/// entry does the `containment_for` fallback apply, so a human still has something to review.
fn carry_forward_or_fallback(
    chain: &ProvenChain,
    active: &BTreeMap<String, Mitigation>,
    desired: &mut BTreeMap<String, Mitigation>,
) {
    let standing: Vec<&Mitigation> = active
        .values()
        .filter(|m| m.justifications.iter().any(|j| j.entry == chain.entry.0))
        .collect();
    if standing.is_empty() {
        fallback_proposal(chain, desired);
        return;
    }
    for mitigation in standing {
        desired
            .entry(mitigation.cut_signature())
            .or_insert_with(|| Mitigation {
                cut: mitigation.cut.clone(),
                action: mitigation.action,
                justifications: Vec::new(),
            })
            .justifications
            .push(Justification::of(chain));
    }
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

    /// Reconcile the ledger against this cycle's proven chains AND this pass's per-entry
    /// cut-choice decisions (ADR-0034 D6/D7). The active set becomes exactly:
    ///
    /// - **model-chosen cuts** whose entry still has a proven, breach-relevant justifying
    ///   chain and a DECISIVE `Attack` decision naming them (they clear the
    ///   `is_live_corroborated` auto-action gate on their own justifications, same as before);
    /// - **carried-forward standing cuts** (D7's retirement asymmetry, safety-critical) — when
    ///   this pass has NO decisive decision for a breach-relevant entry (no decision at all, or
    ///   a fresh `Uncertain`: model unavailable, not yet judged, or the cold-start window after
    ///   a restart), any mitigation ALREADY active for that entry stays active, UNCHANGED, this
    ///   cycle — a transient model wobble/outage must never look like a decisive omission and
    ///   sever a standing, possibly downstream, cut (that would tear down a live isolation
    ///   NetworkPolicy in enforce mode, reopening the path). Re-justified against this pass's
    ///   chain (so a genuine chain-clear still retires it structurally, next pass, exactly as
    ///   for any other mitigation);
    /// - **`containment_for` FALLBACK proposals** — the entry's own ladder result only, never a
    ///   downstream workload — for a breach-relevant entry with no decisive cut AND no standing
    ///   cut to carry forward, OR a decisive `Attack` with an empty `contain` (D1's "attack, but
    ///   no cut warranted" — a decisive OMISSION, so it retires same as `NoAttack` and offers
    ///   only the fallback). Stamped `adjudicated = false` so
    ///   [`Mitigation::is_live_corroborated`] can never clear it — the human-proposal fallback,
    ///   never auto-applied. A decisive `NoAttack` gets NEITHER (the model confidently cleared
    ///   the entry — nothing to propose, and any standing cut retires).
    ///
    /// The deterministic `quarantine_targets` desired-set insertion is **deleted** for
    /// breach-relevant chains — completing the ADR-0032 auto-fire removal — but UNCHANGED for
    /// a non-breach-relevant (internal-only) chain's condition-2 targets: those never
    /// reach the model at all (`adj_pass` only judges breach-relevant entries) and stay outside
    /// the north star's two lanes (ADR-0032 §6 propose-only, deferred by ADR-0034), so their
    /// proposal mechanism is untouched by this ticket.
    pub fn reconcile(
        &mut self,
        chains: &[ProvenChain],
        decisions: &BTreeMap<String, crate::engine::reason::adjudicate::incident::IncidentDecision>,
    ) -> LedgerDelta {
        use crate::engine::reason::adjudicate::incident::Assessment;

        let mut desired: BTreeMap<String, Mitigation> = BTreeMap::new();
        let mut unsevered = Vec::new();

        for chain in chains {
            // Structural report only (independent of any decision): a chain with no
            // single-edge cut can't be severed by one action.
            if containment_for(chain).is_none() {
                unsevered.push(Justification::of(chain));
            }

            if chain.is_breach_relevant() {
                match decisions.get(&chain.entry.0) {
                    // A decisive Attack that named cuts: the model-chosen desired set.
                    Some(d) if d.assessment == Assessment::Attack && !d.cuts.is_empty() => {
                        for cut in &d.cuts {
                            desired
                                .entry(cut.cut_signature.clone())
                                .or_insert_with(|| Mitigation {
                                    cut: cut.cut.clone(),
                                    action: cut.action,
                                    justifications: Vec::new(),
                                })
                                .justifications
                                .push(Justification::of(chain));
                        }
                    }
                    // A decisive, confident NoAttack: the model cleared this entry — no
                    // fallback proposal either (nothing to hand a human to review), and any
                    // standing cut is deliberately NOT carried forward (it retires).
                    Some(d) if d.assessment == Assessment::NoAttack => {}
                    // No decision at all, or a fresh Uncertain: D7's retirement asymmetry —
                    // INERT. Carry any standing cut for this entry forward unchanged; only
                    // when there is none do we offer the fallback proposal.
                    None => carry_forward_or_fallback(chain, &self.active, &mut desired),
                    Some(d) if d.assessment == Assessment::Uncertain => {
                        carry_forward_or_fallback(chain, &self.active, &mut desired)
                    }
                    // A decisive Attack naming no cut (D1): a decisive OMISSION — retires any
                    // standing cut and offers only the containment_for fallback.
                    Some(_) => fallback_proposal(chain, &mut desired),
                }
                continue;
            }

            // Non-breach-relevant (internal-only): UNCHANGED pre-ADR-0034 behavior — never
            // reaches the model, so it is governed entirely by determinism, exactly as before.
            let primary = containment_for(chain);
            if let Some((cut, action)) = &primary {
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
            // Sibling pass: additionally quarantine each *compromised workload on
            // the chain* — an internal-only actively-exploited pod (condition 2), outside the
            // north star's two lanes. The chain's entry is governed entirely by the primary
            // above: skip it here when the primary already additively contains it (
            // "prefer the narrower surgical cut").
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

// ADR-0034: the cut-choice decision-consumption tests, split into their own file
// (rather than growing `tests.rs` toward the 1,000-line cap, CLAUDE.md) — the D6 desired-set
// rules (model cuts / fallback / confident-clear) and D5's non-member whole-decision degrade
// reaching `reconcile` end to end.
#[cfg(test)]
mod decisions_tests;

// ADR-0040: `contain_node_link`/`self_severance` unit coverage, split into their own file —
// `tests.rs` is already near the 1,000-line cap (CLAUDE.md).
#[cfg(test)]
mod contain_node_tests;
