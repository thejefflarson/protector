//! The proof layer (ADR-0002, Question 2): find **provable** attack chains in the
//! graph and the single edge that breaks each one.
//!
//! This is the deterministic half of "a model may propose; only deterministic
//! proof may move privilege." It walks the graph directly — no model — and it
//! traverses **only proof-grade edges** ([`Edge::is_proof_grade`]), so a chain it
//! reports is grounded entirely in deterministic facts. A hypothesis-grade edge
//! (a future model's guess) is invisible here and can never appear in a proven
//! chain.
//!
//! ## What "proven" means in this slice
//!
//! A chain is a proof-grade path from an **entry** (a workload an attacker is
//! assumed to control) to an **objective** (a Secret — the thing worth reaching).
//! Traversal follows attacker *movement* edges: `reaches` (lateral movement),
//! `runs-as` (assume the workload's identity), `can-read` and `can-do` (use that
//! position to reach data). `runs-image` is deliberately excluded — it is how a
//! workload becomes *compromisable* (an entry-enabler), not how an attacker moves
//! toward an objective; it re-enters the bar when the Vulnerability/exposure ports
//! land.
//!
//! The exposure and vulnerability ports now provide the entry side of the bar: a
//! chain whose entry is internet-exposed **and** runs an exploited-in-wild image
//! carries a proven foothold (T1190). Per ADR-0009 the action bar is *asymmetric*:
//! a live-corroborated chain is auto-actionable on its own
//! ([`ProvenChain::meets_action_bar`]), while a foothold without live activity is
//! the weaker, propose-only [`ProvenChain::is_latent_foothold`] case.
//!
//! ## Entries
//!
//! Every workload is still a candidate *starting point* (assume-breach), so we
//! surface structural chains even without vuln data — but each chain is now
//! classified by whether its entry is a *proven foothold* (see [`entry_foothold`]).
//! A chain with no foothold is "if this workload were compromised…"; a chain with
//! one is "this workload is a real, exploitable front door."

use std::collections::BTreeMap;

use petgraph::stable_graph::NodeIndex;

use super::objective::{ObjectiveRecognizer, default_recognizers};
use crate::engine::graph::attack::AttackRef;
use crate::engine::graph::{Node, NodeKey, SecurityGraph};

/// One proven edge on a chain: a proof-grade relation from one node to the next,
/// with the ATT&CK technique it realizes (if it is an attack step rather than
/// structural substrate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub from: NodeKey,
    pub to: NodeKey,
    pub relation: String,
    pub technique: Option<AttackRef>,
    /// Labels of the `from`/`to` workloads (empty for non-workload endpoints), so a
    /// cut on this edge can be rendered as a precise pod selector (ADR-0007).
    pub from_labels: BTreeMap<String, String>,
    pub to_labels: BTreeMap<String, String>,
}

/// Why a workload on a proven chain qualifies for a full-isolation quarantine
/// (JEF-284). Both bars are HIGH — full isolation of a pod is coarse, so it is
/// reserved for a pod with real *exploitation* evidence, never a merely-reached one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineReason {
    /// **Remotely exploitable** — the pod is network-reachable from an internet
    /// foothold (directly or through `reaches`/`can-egress` hops tracing back to an
    /// internet-exposed entry) AND carries strong on-pod exploitation evidence: a
    /// critical/KEV CVE actually running on it (the [`compromisable`] predicate). A
    /// popped app two hops in counts; a merely-reached clean objective does not.
    RemotelyExploitable,
    /// **Actively exploited** — the pod has direct live on-pod runtime evidence (any
    /// "alarming-now" signal: an `Alert`, a hands-on-keyboard `notable_exec`, or
    /// an alarming file write — sensitive-path drop-and-execute / config tamper, JEF-309) —
    /// exploitation *now* — regardless of its network position (internal pods included).
    ActivelyExploited,
}

impl QuarantineReason {
    /// A stable, human-facing disposition label naming the containment and its WHY —
    /// distinct from the entry-foothold quarantine (ADR-0022) and from a durable-fix.
    /// A fixed internal string (never untrusted input).
    pub fn disposition(&self) -> &'static str {
        match self {
            QuarantineReason::RemotelyExploitable => "quarantine — remotely exploitable",
            QuarantineReason::ActivelyExploited => "quarantine — actively exploited",
        }
    }
}

/// A workload on a proven chain that qualifies for a full-isolation quarantine
/// (JEF-284) — the node, its labels (so the isolation `NetworkPolicy` selects it
/// precisely), and the reason it qualifies. Never the merely-reached objective:
/// only a pod with its own exploitation evidence appears here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineTarget {
    pub node: NodeKey,
    pub labels: BTreeMap<String, String>,
    pub reason: QuarantineReason,
}

/// A proven attack chain: a proof-grade path from `entry` to `objective`, plus the
/// edges that individually sever it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenChain {
    pub entry: NodeKey,
    pub objective: NodeKey,
    /// The ATT&CK technique this chain achieves by reaching `objective`.
    pub attack: AttackRef,
    /// The Initial Access technique that proves the *entry* is a real foothold —
    /// `Some(EXPLOIT_PUBLIC_FACING)` when the entry workload is internet-exposed
    /// **and** runs an image with an exploited-in-wild vulnerability. `None` means
    /// the entry is an assume-breach starting point, not a proven foothold. This is
    /// the entry side of the action bar: a chain with both a foothold and a
    /// privileged objective has reachable ∧ exploited ∧ privileged proven; only
    /// runtime corroboration (the RuntimeEvidence port) is then still missing.
    pub foothold: Option<AttackRef>,
    /// Whether the entry workload has a live runtime signal (RuntimeEvidence port)
    /// — the `corroborated-now` predicate. With a foothold, this completes the full
    /// action bar: the front door is exploitable *and* something is happening on it
    /// right now.
    pub corroborated: bool,
    /// Whether the model adjudicator confirmed this is a real, contextually-
    /// exploitable attack (ADR-0013). Defaults `true`; the veto direction of the
    /// model's judgement sets it `false`, demoting an eligible auto-action to a human
    /// proposal. Absent a model it stays `true` and the deterministic bar governs.
    /// (The promote direction is the separate [`promoted`](Self::promoted) flag.)
    pub adjudicated: bool,
    /// Whether the model *promoted* this proven-but-uncorroborated chain to
    /// auto-eligible (ADR-0011) — its positive "game-over" judgement on an
    /// internet-exposed entry. Defaults `false`; only an affirmative model verdict
    /// (never `NullAdjudicator`) sets it, and only behind the `judgement` opt-in.
    pub promoted: bool,
    /// Whether the **entry** workload is internet-facing (`Exposure::Internet`) — a
    /// front door an external attacker can actually start from. This is the
    /// discriminator between a *breach path* (internet → entry → objective) and the
    /// assume-breach blast-radius map ("if this internal workload were compromised,
    /// what could it reach"). An internal-only entry reaching a secret is normal
    /// Kubernetes topology, not a breach. See [`ProvenChain::is_breach_relevant`].
    pub exposed_entry: bool,
    /// The model's adjudication summary for this chain, when it was judged (ADR-0013)
    /// — both positive ("exploitable — …") and negative ("not exploitable — …")
    /// calls, kept so a consumer can show *why* the model did or didn't act. `None`
    /// when no model was consulted (no evidence to weigh, or no model configured).
    pub verdict: Option<String>,
    /// The path, entry → objective, in order. This is the REPRESENTATIVE (shortest) path —
    /// the one the response layer reasons about (its cut, its strength). See
    /// [`paths`](Self::paths) for the complete set when an objective is reachable several ways.
    pub links: Vec<Link>,
    /// EVERY proven path entry → objective, bounded to [`chain::MAX_PROVEN_PATHS`] and
    /// shortest-first (the first entry mirrors [`links`](Self::links)). A wide objective —
    /// reachable by several redundant paths — carries them all here, so the finding detail can
    /// show the whole reachability picture rather than one path (JEF-281). Crucially, multiple
    /// paths ARE the explanation for an empty [`single_edge_cuts`](Self::single_edge_cuts): a
    /// chain is no-single-edge-cut precisely because redundant paths route around any one edge.
    pub paths: Vec<Vec<Link>>,
    /// `true` when there are MORE proven paths than the [`chain::MAX_PROVEN_PATHS`] bound shown
    /// in [`paths`](Self::paths) (or the enumeration budget was hit) — the detail renders a
    /// bounded "+N more" note rather than an unbounded wall (JEF-281).
    pub paths_truncated: bool,
    /// Edges on the path whose removal alone disconnects `entry` from `objective`
    /// — the minimal-cut candidates (ADR-0002). Empty means no single edge
    /// suffices: redundant paths exist, and breaking the chain needs more than one
    /// cut. That emptiness is itself a finding, not a failure.
    pub single_edge_cuts: Vec<Link>,
    /// Workloads *on this chain* that carry their own exploitation evidence and so
    /// qualify for a full-isolation quarantine (JEF-284) — remotely-exploitable pods
    /// reachable from an internet foothold with a critical/KEV CVE, and
    /// actively-exploited pods with a live on-pod runtime signal. The chain **entry**
    /// is deliberately excluded from the remotely-exploitable set: its containment is
    /// owned by the ADR-0022 precedence (`respond::containment_for`). The merely-reached
    /// objective never appears here (reached ≠ exploited). Empty on a chain whose only
    /// evidence is at the entry / whose nodes are merely reached.
    pub quarantine_targets: Vec<QuarantineTarget>,
}

impl ProvenChain {
    /// The quarantine reason for the chain's **entry**, if the entry itself is an
    /// actively-exploited target (JEF-284 condition 2). The entry is never a
    /// remotely-exploitable target (that set excludes it, deferring to the ADR-0022
    /// precedence), so this surfaces only the "actively exploited" case — the internal
    /// hands-on-keyboard pod that is the front of its own (non-breach) chain. Drives the
    /// dashboard disposition.
    pub fn entry_quarantine_reason(&self) -> Option<QuarantineReason> {
        self.quarantine_targets
            .iter()
            .find(|t| t.node == self.entry)
            .map(|t| t.reason)
    }
    /// Chain strength is the number of proven links — the ADR-0001 measure.
    pub fn strength(&self) -> usize {
        self.links.len()
    }

    /// The *latent-exposure* signal (ADR-0009): a proven foothold at the entry
    /// (internet-exposed ∧ exploited-in-wild) on a privileged path, but **no** live
    /// activity. This is the weaker, propose-only case — a real exploitable front
    /// door that isn't being exploited yet.
    pub fn is_latent_foothold(&self) -> bool {
        self.foothold.is_some() && !self.corroborated
    }

    /// Whether this chain is a real **breach path** worth flagging, versus
    /// assume-breach context. True only when the entry is internet-facing — an
    /// origin an external attacker can actually reach. A purely-internal access path
    /// (a control-plane workload that can read a secret, a backend that can reach the
    /// database) is the *normal* shape of a cluster, not a breach; it belongs in the
    /// blast-radius map you consult after a compromise, not on a to-do list. The
    /// engine still proves and surfaces those chains — just as context, not findings.
    pub fn is_breach_relevant(&self) -> bool {
        self.exposed_entry
    }

    /// Whether the chain is **live-actionable**: a breach-relevant (internet-facing
    /// entry) chain that is either live-corroborated (ADR-0009) or model-promoted
    /// (ADR-0011). Both are filtered by the adjudicator's veto and bounded by the
    /// reversible, self-reverting action. Auto-action is reserved for *remote*
    /// exploitation paths, so an internal-only corroborated chain — normal cluster
    /// activity, not a breach — never clears the bar. This gates auto-action.
    pub fn meets_action_bar(&self) -> bool {
        self.is_breach_relevant() && (self.corroborated || self.promoted)
    }

    /// Log the chain as a structured line, including the ATT&CK technique it
    /// achieves, whether the entry is a proven foothold, and whether a single-edge
    /// cut exists (the surgical action a response layer would later take).
    pub fn emit(&self) {
        tracing::info!(
            entry = %self.entry.0,
            objective = %self.objective.0,
            tactic = self.attack.tactic.id(),
            technique = self.attack.technique_id,
            technique_name = self.attack.technique,
            foothold = self.foothold.map(|f| f.technique_id).unwrap_or("none"),
            corroborated = self.corroborated,
            exposed_entry = self.exposed_entry,
            breach_relevant = self.is_breach_relevant(),
            action_bar = self.meets_action_bar(),
            strength = self.strength(),
            single_edge_cuts = self.single_edge_cuts.len(),
            "proven chain"
        );
    }
}

// Cohesive submodules, split out of this file to keep each under the 1,000-line cap
// (repo CLAUDE.md). The public surface (`Link`, `ProvenChain`, `prove`/`prove_with`)
// stays here so external paths (`reason::proof::...`) resolve unchanged.
mod chain;
mod corroborate;

use chain::{
    MAX_PROVEN_PATHS, entry_exposed, entry_foothold, is_cuttable_edge, link_of, movement_tree,
    path_steps, proven_paths, quarantine_targets_on_path, reachable_without,
};
use corroborate::{corroborated_for, entry_runtime};

/// Find every proven chain in `graph` using the default objective recognizers
/// (ADR-0005).
pub fn prove(graph: &SecurityGraph) -> Vec<ProvenChain> {
    prove_with(graph, &default_recognizers())
}

/// As [`prove`], but with an explicit recognizer set. For each workload entry,
/// each recognized objective node it can reach over proof-grade movement edges
/// yields one chain — tagged with the objective's ATT&CK technique — plus its
/// minimal-cut candidates.
pub fn prove_with(
    graph: &SecurityGraph,
    recognizers: &[Box<dyn ObjectiveRecognizer>],
) -> Vec<ProvenChain> {
    let g = graph.inner();
    let entries: Vec<NodeIndex> = g
        .node_indices()
        .filter(|&i| matches!(g.node_weight(i), Some(Node::Workload(_))))
        .collect();
    // Recognized objective nodes, resolved to indices and paired with their
    // ATT&CK technique.
    let objectives: Vec<(NodeIndex, AttackRef)> = recognizers
        .iter()
        .flat_map(|r| r.recognize(graph))
        .filter_map(|o| graph.index_of(&o.node).map(|i| (i, o.attack)))
        .collect();

    let mut chains = Vec::new();
    for &entry in &entries {
        let tree = movement_tree(graph, entry, None);
        let foothold = entry_foothold(graph, entry);
        let exposed_entry = entry_exposed(graph, entry);
        // The entry node is constant across objectives, so resolve its runtime signals
        // once here rather than re-looking-up the node inside `corroborated_for` per
        // objective.
        let runtime = entry_runtime(graph, entry);
        for &(objective, attack) in &objectives {
            if objective == entry || !tree.contains_key(&objective) {
                continue;
            }
            // Per-objective: this objective's technique decides which behaviors corroborate
            // — plus the entry's foothold tactic, when it has one (JEF-77), so a vuln-matched
            // library load on the front door corroborates the foothold even though no
            // objective is ever tagged INITIAL_ACCESS.
            let corroborated = corroborated_for(runtime, &attack, foothold.as_ref());
            let steps = path_steps(&tree, entry, objective);
            let links = steps
                .iter()
                .map(|&(u, v, e)| link_of(graph, u, v, e))
                .collect();
            let single_edge_cuts = steps
                .iter()
                .filter(|&&(_, _, e)| {
                    is_cuttable_edge(graph, e) && !reachable_without(graph, entry, objective, e)
                })
                .map(|&(u, v, e)| link_of(graph, u, v, e))
                .collect();
            // Enumerate EVERY proven path to this objective (bounded), not just the shortest —
            // the multi-path picture the finding detail restores (JEF-281). Redundant paths are
            // exactly why `single_edge_cuts` can be empty.
            let (path_steps_all, paths_truncated) =
                proven_paths(graph, entry, objective, MAX_PROVEN_PATHS);
            let paths: Vec<Vec<Link>> = path_steps_all
                .iter()
                .map(|p| p.iter().map(|&(u, v, e)| link_of(graph, u, v, e)).collect())
                .collect();
            let quarantine_targets =
                quarantine_targets_on_path(graph, entry, &steps, exposed_entry);
            chains.push(ProvenChain {
                entry: graph.key_of(entry).expect("entry exists"),
                objective: graph.key_of(objective).expect("objective exists"),
                attack,
                foothold,
                corroborated,
                adjudicated: true,
                promoted: false,
                exposed_entry,
                verdict: None,
                links,
                paths,
                paths_truncated,
                single_edge_cuts,
                quarantine_targets,
            });
        }
    }
    chains
}

#[cfg(test)]
mod corroborate_tests;
#[cfg(test)]
mod tests;
