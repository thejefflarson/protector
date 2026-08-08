//! The narrowing-delta comparator (ADR-0041 §6): a read-only bake instrument that counts the
//! cases the retiring blanket notable-exec corroboration arm would have flipped to
//! `corroborated` — a breach-relevant chain whose entry carries a **notable exec** (an
//! interactive shell or package-manager `ProcessExec`,
//! [`crate::engine::observe::exec_class::notable_exec`]) on its on-pod runtime, but whose
//! chain is `!corroborated` today. This is the Falco-retirement parity-matrix input: the
//! recall the `Behavior::Alert` arm currently backstops (see
//! `docs/adr/0041-narrow-blanket-notable-exec-corroboration.md` §6).
//!
//! **View only** (ADR-0016 — presentation is a view, never a gate): [`compute`] takes its
//! inputs by shared reference and returns owned data; there is no path from this module back
//! into the ledger, the actuator, or the arming state. Mirrors
//! [`crate::engine::cut_divergence`]'s read-only-bake shape (ADR-0037), scoped to a single
//! predicate rather than a cut-set comparison.
//!
//! Before the narrowing this counter measures lands (a separate change), a bare notable exec
//! still corroborates via the blanket arm, so `compute` reads empty in practice — expected,
//! not a bug: the counter is a bake instrument for the AFTER state, and its unit tests
//! construct both states directly rather than depending on the narrowing to land first.

use crate::engine::graph::{Node, NodeKey, SecurityGraph};
use crate::engine::observe::exec_class;
use crate::engine::reason::proof::ProvenChain;

/// One breach-relevant chain where the old blanket notable-exec corroboration arm would have
/// flipped `corroborated`, but the chain is `!corroborated` today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarrowingDeltaRecord {
    /// The internet-facing entry carrying the notable exec.
    pub entry: String,
    /// The objective this chain targets.
    pub objective: String,
    /// The ATT&CK technique this chain's objective achieves — a fixed internal string
    /// (never untrusted input), safe to log.
    pub technique_id: &'static str,
}

impl NarrowingDeltaRecord {
    /// Log this record as a structured line — the parity-matrix / bake-review artifact
    /// (ADR-0041 §6). A view-only side effect: logging never mutates anything else.
    pub fn emit(&self) {
        tracing::info!(
            entry = %self.entry,
            objective = %self.objective,
            technique = self.technique_id,
            "narrowing delta: notable exec present, chain uncorroborated"
        );
    }
}

/// Whether `entry`'s on-pod runtime carries a notable exec — an interactive shell or
/// package-manager `ProcessExec` ([`exec_class::notable_exec`]). Non-workload nodes, and an
/// entry key the graph no longer carries, are never notable. Deliberately scoped to
/// `notable_exec` rather than the broader
/// [`crate::engine::observe::alarm_class::is_alarming_now`] family: an `Alert` or an alarming
/// file write still corroborates through their OWN (unnarrowed) arms, so only the notable-exec
/// shape is the narrowing's delta.
fn entry_has_notable_exec(graph: &SecurityGraph, entry: &NodeKey) -> bool {
    graph.index_of(entry).is_some_and(|idx| {
        matches!(
            graph.inner().node_weight(idx),
            Some(Node::Workload(w))
                if w.runtime.iter().any(|s| exec_class::notable_exec(&s.behavior).is_some())
        )
    })
}

/// Compute this pass's narrowing-delta records: every breach-relevant chain whose entry has a
/// notable exec in its runtime AND whose chain is `!corroborated`. Pure: reads
/// `graph`/`chains`, returns owned records; mutates neither.
pub fn compute(graph: &SecurityGraph, chains: &[ProvenChain]) -> Vec<NarrowingDeltaRecord> {
    chains
        .iter()
        .filter(|c| c.is_breach_relevant() && !c.corroborated)
        .filter(|c| entry_has_notable_exec(graph, &c.entry))
        .map(|c| NarrowingDeltaRecord {
            entry: c.entry.0.clone(),
            objective: c.objective.0.clone(),
            technique_id: c.attack.technique_id,
        })
        .collect()
}

#[cfg(test)]
#[path = "narrowing_delta_tests.rs"]
mod tests;
