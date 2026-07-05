//! The corroboration-parity report (JEF-310, Falco-retirement F6): the read-only measurement
//! that answers "does the first-party agent corroborate every breach chain Falco does?" — the
//! go/no-go signal for retiring Falco (JEF-56).
//!
//! While both sensors run, every breach-relevant corroboration is attributed to its SOURCE
//! (`ProvenChain::corroborated_by_falco` / `_by_agent`, derived from the corroborating behavior
//! in `reason::proof::corroborate`). This module folds those per-chain booleans into the
//! parity counts and the HONEST retirement reading. The count that matters is **agent-uncovered**
//! — chains a Falco `Alert` corroborated with NO agent-equivalent signal on the same workload;
//! that trending to ≈0 over a bake is what clears Falco for retirement (the F7 gate consumes it).
//!
//! **Honesty (ADR-0016).** A window with no Falco corroboration is [`ParityReadiness::NothingToCompare`],
//! explicitly NOT "0 uncovered = safe to retire": absence of Falco activity is not evidence the
//! agent has parity. Missing/ambiguous data must never read as a reassuring green. This is derived,
//! read-only state — it measures, it never influences corroboration or actuation.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::engine::reason::proof::ProvenChain;

/// How many agent-uncovered entry names to retain for the operator-facing view. A cluster under
/// active dual-sensor bake has a handful of breach front doors; this bounds the render (and the
/// serialized shape) rather than letting a pathological graph list unboundedly.
const MAX_UNCOVERED_ENTRIES: usize = 32;

/// The per-pass corroboration-parity counts (JEF-310), over the breach-relevant chains only —
/// the same population the `corroborations` metric counts. Every field is a COUNT with no
/// per-pod payload except [`uncovered_entries`](Self::uncovered_entries), which carries cluster
/// names (untrusted-adjacent: escaped at render, never `PreEscaped`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CorroborationParity {
    /// Breach-relevant chains a Falco `Alert` corroborated this pass.
    pub falco_corroborated: u64,
    /// Breach-relevant chains a first-party agent behavior corroborated this pass.
    pub agent_corroborated: u64,
    /// Chains corroborated by BOTH sensors — the parity we want (the agent already covers what
    /// Falco saw).
    pub both: u64,
    /// Chains corroborated by a Falco `Alert` with NO agent-equivalent signal on the same
    /// workload — **agent-uncovered**. THE headline metric: this trending to ≈0 is the signal
    /// that Falco can be retired (JEF-56).
    pub agent_uncovered: u64,
    /// Chains the agent corroborated with no Falco alert — agent-only. Already covered; counted
    /// for completeness, never a retirement blocker.
    pub agent_only: u64,
    /// The distinct entry (front-door workload) keys of the agent-uncovered chains, sorted and
    /// bounded to [`MAX_UNCOVERED_ENTRIES`] — so an operator can see WHICH workload the agent
    /// isn't covering. UNTRUSTED-adjacent: escaped at render (maud default), never `PreEscaped`.
    pub uncovered_entries: Vec<String>,
}

impl CorroborationParity {
    /// The honest retirement reading of this window (JEF-310) — kept DISTINCT from the raw
    /// counts so "nothing to compare" can never collapse into a reassuring "0 uncovered".
    pub fn readiness(&self) -> ParityReadiness {
        if self.falco_corroborated == 0 {
            // Falco corroborated nothing this window: there is NOTHING to compare. This is NOT
            // "0 uncovered = safe" — absence of Falco activity is not evidence of parity.
            ParityReadiness::NothingToCompare
        } else if self.agent_uncovered > 0 {
            ParityReadiness::Uncovered {
                count: self.agent_uncovered,
            }
        } else {
            ParityReadiness::Parity
        }
    }
}

/// The honest retirement-readiness state of a parity window (JEF-310). The three states are
/// deliberately not orderable numerically: "nothing to compare" is a distinct epistemic state,
/// not a better-or-worse point on the uncovered scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParityReadiness {
    /// No Falco `Alert` corroborated any breach chain this window — there is nothing to compare
    /// the agent against. Explicitly NOT a green "safe to retire" (honesty invariant, ADR-0016).
    NothingToCompare,
    /// Falco corroborated `count` breach chain(s) the agent did NOT — not yet safe to retire.
    Uncovered { count: u64 },
    /// Every Falco-corroborated breach chain was ALSO agent-corroborated — parity this window.
    Parity,
}

/// Fold the pass's proven chains into the corroboration-parity counts (JEF-310), over the
/// **breach-relevant** chains only (the population the action bar and the `corroborations`
/// metric care about). Pure and total — read-only measurement, no decision (ADR-0016).
pub(crate) fn derive_parity(chains: &[ProvenChain]) -> CorroborationParity {
    let mut parity = CorroborationParity::default();
    let mut uncovered: BTreeSet<String> = BTreeSet::new();
    for c in chains.iter().filter(|c| c.is_breach_relevant()) {
        let by_falco = c.corroborated_by_falco;
        let by_agent = c.corroborated_by_agent;
        if by_falco {
            parity.falco_corroborated += 1;
        }
        if by_agent {
            parity.agent_corroborated += 1;
        }
        match (by_falco, by_agent) {
            (true, true) => parity.both += 1,
            (true, false) => {
                parity.agent_uncovered += 1;
                uncovered.insert(c.entry.0.clone());
            }
            (false, true) => parity.agent_only += 1,
            // Uncorroborated (or corroborated by neither source) — not part of the parity fold.
            (false, false) => {}
        }
    }
    parity.uncovered_entries = uncovered.into_iter().take(MAX_UNCOVERED_ENTRIES).collect();
    parity
}

#[cfg(test)]
#[path = "parity_tests.rs"]
mod tests;
