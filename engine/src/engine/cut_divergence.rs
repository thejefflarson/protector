//! The shadow-bake divergence comparator: for each breach-relevant entry with a DECISIVE
//! cut-choice decision this pass (ADR-0034), compares the model-chosen cut-set against the
//! deterministic fallback set determinism alone would have proposed for the SAME chains —
//! [`crate::engine::respond::containment_for`]'s entry ladder plus
//! [`crate::engine::respond::quarantine_workload_link`] over each chain's
//! [`crate::engine::reason::proof::ProvenChain::quarantine_targets`] downstream candidates. These
//! are the EXACT resolvers [`crate::engine::respond::MitigationLedger::reconcile`]'s
//! non-breach-relevant branch and the ADR-0034 `incident::menu` builder already reuse, so this
//! comparator can never invent a "deterministic" cut neither of those would themselves propose.
//!
//! **View only** (ADR-0016 — presentation is a view, never a gate): every function here takes its
//! inputs by shared reference and returns owned data; there is no path from this module back into
//! the ledger, the actuator, or the arming state. It answers one question for the human bake
//! review — "had determinism alone been deciding, would it agree with the model?" — it never
//! decides that question itself, and computing/journaling/viewing a divergence record can never
//! arm or mutate anything. See `docs/adr/0037-shadow-bake-arm-readiness.md` for the exit criterion this
//! feeds (a human-read bar, not an auto-arm).
//!
//! An entry with no decision this pass, or a fresh `Uncertain` (model unavailable / not yet
//! judged), carries no new information — mirrors the durable journal's own "only decisive
//! decisions are recorded" discipline — so [`compute`] skips it rather than manufacturing a
//! divergence signal out of a model outage.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::engine::reason::adjudicate::incident::{Assessment, IncidentDecision};
use crate::engine::reason::proof::ProvenChain;
use crate::engine::respond::{containment_for, quarantine_workload_link};

/// How the model's chosen cut-set compares to what determinism alone would have proposed for
/// the same entry, this pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceClass {
    /// The model's cut-set is byte-identical to the deterministic fallback set (both may be
    /// empty — a decisive `NoAttack` agreeing with a chain that has nothing containable).
    Agree,
    /// The model's cut-set is a STRICT SUPERSET of the deterministic set: it cut everything
    /// determinism would have, plus at least one more node.
    ModelOverCut,
    /// The model's cut-set is a STRICT SUBSET of the deterministic set: it left out at least
    /// one node determinism would have cut (including the empty set on a decisive `NoAttack`
    /// over a chain determinism would have contained).
    ModelUnderCut,
    /// Neither set contains the other: some node only the model cut, some node only
    /// determinism would have.
    Mixed,
}

/// One entry's divergence classification for one pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceRecord {
    /// The internet-facing entry this classification was computed for.
    pub entry: String,
    pub class: DivergenceClass,
    /// Node keys the model named this pass (sorted, deduped) — empty for a decisive `NoAttack`.
    pub model_cuts: Vec<String>,
    /// Node keys `containment_for` + the quarantine-target resolvers would propose for the
    /// same chains, independent of the model's call (sorted, deduped).
    pub deterministic_cuts: Vec<String>,
}

/// The deterministic fallback node-key set for one entry: the union, over every proven chain on
/// that entry, of [`containment_for`]'s entry-ladder result (when additive-live + reversible —
/// the only kind an entry line is ever selectable for, mirroring `incident::menu::build_menu`)
/// and each additive-live + reversible + labeled `quarantine_targets` downstream node, minus the
/// entry itself (ADR-0022 entry-exclusion). A node with no additive-live+reversible mechanism, or
/// no Pod labels, is never a candidate cut for anyone — determinism declines it exactly as the
/// menu's `uncontainable` line does — so it is never counted here either.
fn deterministic_targets(chains: &[&ProvenChain]) -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    for &chain in chains {
        if let Some((_cut, action)) = containment_for(chain)
            && action.is_additive_live()
            && action.is_reversible()
        {
            targets.insert(chain.entry.0.clone());
        }
        for target in &chain.quarantine_targets {
            if target.node == chain.entry {
                continue;
            }
            if quarantine_workload_link(target).is_some() {
                targets.insert(target.node.0.clone());
            }
        }
    }
    targets
}

/// Classify a model cut-set against a deterministic one.
fn classify(model: &BTreeSet<String>, deterministic: &BTreeSet<String>) -> DivergenceClass {
    if model == deterministic {
        DivergenceClass::Agree
    } else if deterministic.is_subset(model) {
        DivergenceClass::ModelOverCut
    } else if model.is_subset(deterministic) {
        DivergenceClass::ModelUnderCut
    } else {
        DivergenceClass::Mixed
    }
}

/// Compute one [`DivergenceRecord`] per breach-relevant entry with a DECISIVE decision this pass
/// (`Attack` or `NoAttack`; a fresh `Uncertain`, or an entry with no decision at all, is skipped —
/// see the module docs). Pure: reads `chains` and `decisions`, returns owned records; mutates
/// neither (view-never-mutates, ADR-0016).
pub fn compute(
    chains: &[ProvenChain],
    decisions: &BTreeMap<String, IncidentDecision>,
) -> Vec<DivergenceRecord> {
    let mut by_entry: BTreeMap<&str, Vec<&ProvenChain>> = BTreeMap::new();
    for chain in chains {
        if chain.is_breach_relevant() {
            by_entry
                .entry(chain.entry.0.as_str())
                .or_default()
                .push(chain);
        }
    }

    let mut records = Vec::new();
    for (entry, entry_chains) in by_entry {
        let Some(decision) = decisions.get(entry) else {
            continue;
        };
        let model_cuts: BTreeSet<String> = match decision.assessment {
            Assessment::Attack => decision.cuts.iter().map(|c| c.node.0.clone()).collect(),
            Assessment::NoAttack => BTreeSet::new(),
            // Not decisive this pass — no fresh signal, never a divergence claim.
            Assessment::Uncertain => continue,
        };
        let deterministic_cuts = deterministic_targets(&entry_chains);
        records.push(DivergenceRecord {
            entry: entry.to_string(),
            class: classify(&model_cuts, &deterministic_cuts),
            model_cuts: model_cuts.into_iter().collect(),
            deterministic_cuts: deterministic_cuts.into_iter().collect(),
        });
    }
    records
}

#[cfg(test)]
#[path = "cut_divergence_tests.rs"]
mod tests;
