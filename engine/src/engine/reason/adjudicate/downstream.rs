//! Per-node downstream evidence for the adjudication prompt (JEF-565, ADR-0032 violation #1):
//! the model was entry-scoped — it saw only the ENTRY's CVEs/secrets/behavior, and every
//! downstream objective on the entry's proven paths was one line (name + reach tag + ATT&CK
//! outcome). A popped pod two hops in was invisible. This module renders one evidence block
//! PER WORKLOAD on the entry's proven paths (`ProvenChain::paths`), reusing the exact same
//! evidence functions, JEF-453 reachable-CVE filter, fencing, and per-field caps the entry's own
//! block uses (`evidence::{reachable_cve_lines_budgeted, entry_findings_budgeted,
//! render_behavior_lines_budgeted}`) — no second rendering path to drift from.
//!
//! Split out of `prompt.rs` purely to keep every file under the 1,000-line cap (repo CLAUDE.md).
//!
//! Scope is deliberately ALL workload nodes on the proven paths, not just
//! [`super::super::proof::QuarantineTarget`]s: `quarantine_targets` is narrower (only nodes that
//! ALREADY carry their own exploitation evidence), so it can't distinguish "checked this hop,
//! found nothing" from "never looked" — the clean one-line marker below is exactly that
//! distinction, and it matters for the model's confidence in a `refuted` call.

use crate::engine::graph::{NodeKey, SecurityGraph};
use crate::engine::observe::asn::AsnDb;

use super::evidence::{
    entry_findings_budgeted, reachable_cve_lines_budgeted, render_behavior_lines_budgeted,
};
use super::guards::{fence, fence_list};

/// The per-incident AGGREGATE free-text budget (chars) shared across EVERY downstream node
/// rendered for one entry's prompt (JEF-565) — the downstream counterpart of
/// [`super::evidence::ENTRY_FREETEXT_BUDGET`], which is per-node. Without an incident-wide cap a
/// wide entry (argo, ~110 objectives, though typically far fewer distinct downstream WORKLOADS)
/// could multiply the per-node budget into an unbounded prompt. Structural fields (CVE
/// id/severity/reachability/fix, secret id/severity, behavior KIND) are NEVER dropped — only
/// the free-text beyond the budget (JEF-106 structural-first stance), exactly like the entry's
/// own budget. CVE prose, finding prose, and behavior-line prose (a security-review follow-up:
/// `Behavior::summary` embeds attacker-influenced free-text — an exec'd path, a file path, a raw
/// peer string — fenced+sanitized but otherwise unbounded) are each charged to their OWN
/// independent pool of this size — mirroring the entry's own independent `ENTRY_FREETEXT_BUDGET`
/// pools (`entry_evidence` for CVEs, `entry_findings` for secrets+posture,
/// `render_behavior_lines` for behaviors).
pub(crate) const INCIDENT_DOWNSTREAM_FREETEXT_BUDGET: usize = 4000;

/// The rendered downstream-evidence section: one block per node (spliced into the prompt) and
/// the flat set of lines behind them (fed into [`super::surface::JudgedSurface`] so a change
/// here is visible to the re-judge gate, not just the prompt — the trap this ticket closes).
pub(crate) struct DownstreamRendered {
    /// One rendered line per downstream node, in sorted node-key order (deterministic — same
    /// evidence always yields the same blocks in the same order, so the prompt is a stable
    /// verdict-cache key). Either the fenced evidence block or the clean one-line marker.
    pub blocks: Vec<String>,
    /// The flat, node-prefixed evidence lines behind `blocks` — the surface category JEF-565
    /// adds to [`super::surface::JudgedSurface`]. Node-prefixed so the SAME evidence text on two
    /// different nodes can't collide in the set, and so a node transitioning
    /// clean→evidence-bearing (or the reverse) reads as a genuine line change.
    pub surface_lines: Vec<String>,
}

/// Render the downstream-evidence section for one entry's prompt (JEF-565). `nodes` is the
/// caller's deduped, sorted set of workload [`NodeKey`]s on the entry's proven paths, EXCLUDING
/// the entry itself (its own evidence is the entry's dedicated prompt fields). Defensively
/// sorts + dedups again here so this function is correct standalone, regardless of what the
/// caller already did.
pub(crate) fn render_downstream(
    graph: &SecurityGraph,
    nodes: &[NodeKey],
    asn: &AsnDb,
) -> DownstreamRendered {
    let mut sorted: Vec<NodeKey> = nodes.to_vec();
    sorted.sort();
    sorted.dedup();

    let mut cve_budget = INCIDENT_DOWNSTREAM_FREETEXT_BUDGET;
    let mut finding_budget = INCIDENT_DOWNSTREAM_FREETEXT_BUDGET;
    // A THIRD independent incident-wide pool for behavior-line free text (security-review
    // follow-up to JEF-565): `Behavior::summary` embeds attacker-influenced free-text (an
    // exec'd path, a file path, a raw peer string) fenced+sanitized but previously uncapped and
    // unbudgeted — harmless on one entry, but multiplied across every downstream node here.
    let mut behavior_budget = INCIDENT_DOWNSTREAM_FREETEXT_BUDGET;
    let mut blocks = Vec::with_capacity(sorted.len());
    let mut surface_lines = Vec::new();

    for node in &sorted {
        let (mut cves, behaviors) = reachable_cve_lines_budgeted(graph, node, &mut cve_budget);
        cves.sort();
        cves.dedup();
        let behavior_lines = render_behavior_lines_budgeted(&behaviors, asn, &mut behavior_budget);
        let (mut secret_lines, mut posture_lines) =
            entry_findings_budgeted(graph, node, &mut finding_budget);
        secret_lines.sort();
        secret_lines.dedup();
        posture_lines.sort();
        posture_lines.dedup();

        let evidenced = !cves.is_empty() || !secret_lines.is_empty() || !behavior_lines.is_empty();
        let name = fence(&node.0);
        if evidenced {
            blocks.push(format!(
                "  - {name}: CVEs observed loading at runtime: {} | Exposed secrets baked into this image: {} | Observed runtime behavior: {} | Static posture findings: {}",
                fence_list(&cves),
                fence_list(&secret_lines),
                fence_list(&behavior_lines),
                fence_list(&posture_lines),
            ));
        } else {
            blocks.push(format!("  - {name}: no evidence observed."));
        }

        // Node-prefixed surface lines (see the struct doc): a category on ONE node must never
        // be conflated with the same text on another node, and a clean node still needs a line
        // so the transition clean→evidenced is a detectable addition (not just an absence
        // becoming a presence with nothing to diff against).
        let prefix = |line: &str| format!("{}: {}", node.0, line);
        surface_lines.extend(cves.iter().map(|l| prefix(l)));
        surface_lines.extend(secret_lines.iter().map(|l| prefix(l)));
        surface_lines.extend(behavior_lines.iter().map(|l| prefix(l)));
        surface_lines.extend(posture_lines.iter().map(|l| prefix(l)));
        if !evidenced {
            surface_lines.push(format!("{}: no evidence observed", node.0));
        }
    }

    DownstreamRendered {
        blocks,
        surface_lines,
    }
}
