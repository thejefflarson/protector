//! The attack-vectors view-model (ADR-0019, the DATA layer): a pure function aggregating
//! the breach-relevant [`Finding`]s into the per-technique "what an attacker could reach"
//! rows the `components::panels::attack_vectors` renderer consumes. No maud, no markup —
//! the aggregation (distinct objectives reachable vs model-flagged, by ATT&CK technique)
//! lives here; the renderer only escapes + lays out the resulting rows.

use crate::engine::dashboard::model::Finding;
use crate::engine::dashboard::view_model::findings::flagged;
use std::collections::{BTreeMap, BTreeSet};

/// One attack-vector row: a tactic→technique pair with how many distinct objectives are
/// reachable and how many the model has affirmed exploitable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackVectorRow {
    /// The ATT&CK tactic name (the human label).
    pub tactic: String,
    /// The ATT&CK technique id (`T1552`, …) — shown in the `<abbr title>`.
    pub technique_id: String,
    /// The ATT&CK technique name — the `<abbr>` text and part of its title.
    pub technique_name: String,
    /// How many distinct objectives this technique can reach (proven-reachable).
    pub reachable: usize,
    /// How many distinct objectives the model affirmed exploitable via this technique. Zero
    /// renders as the muted dash; nonzero as the flagged count.
    pub flagged: usize,
}

/// The attack-vectors panel props: the per-technique rows, ordered by tactic then
/// technique (stable). An empty `rows` renders the "no internet-facing service can reach a
/// target" empty state. Plain data — `components::panels::attack_vectors` renders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackVectorsProps {
    /// One row per reachable tactic→technique pair, in a stable tactic/technique order.
    pub rows: Vec<AttackVectorRow>,
}

/// Build the attack-vectors props from the findings (ADR-0013: proof winnows the reachable
/// set, the model decides which are genuinely exploitable). PURE: aggregates the
/// breach-relevant findings into distinct-objective counts per tactic→technique, in a
/// stable order, mirroring the legacy `attack_vectors` aggregation.
pub fn attack_vectors_props(findings: &[Finding]) -> AttackVectorsProps {
    // (tactic, technique_id, technique_name) → (objectives reachable, objectives flagged).
    // BTreeMap keeps the table stable, ordered by tactic then technique.
    type VectorKey = (String, String, String);
    type VectorCounts = (BTreeSet<String>, BTreeSet<String>);
    let mut acc: BTreeMap<VectorKey, VectorCounts> = BTreeMap::new();
    for f in findings.iter().filter(|f| f.breach_relevant) {
        let entry = acc
            .entry((
                f.tactic_name.clone(),
                f.technique.clone(),
                f.technique_name.clone(),
            ))
            .or_default();
        entry.0.insert(f.objective.clone());
        if flagged(f.verdict.as_deref()) {
            entry.1.insert(f.objective.clone());
        }
    }

    let rows = acc
        .into_iter()
        .map(
            |((tactic, technique_id, technique_name), (reachable, flagged))| AttackVectorRow {
                tactic,
                technique_id,
                technique_name,
                reachable: reachable.len(),
                flagged: flagged.len(),
            },
        )
        .collect();
    AttackVectorsProps { rows }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::model::EntryEvidence;

    fn finding(objective: &str, breach_relevant: bool, verdict: Option<&str>) -> Finding {
        Finding {
            entry: "workload/app/Pod/web".into(),
            objective: objective.into(),
            tactic: "TA0006".into(),
            tactic_name: "Credential Access".into(),
            technique: "T1552".into(),
            technique_name: "Unsecured Credentials".into(),
            foothold: false,
            corroborated: false,
            adjudicated: true,
            promoted: false,
            disposition: "no-cut".into(),
            cut: None,
            breach_relevant,
            killchain: String::new(),
            verdict: verdict.map(str::to_string),
            path: Vec::new(),
            evidence: EntryEvidence::default(),
            recency: None,
        }
    }

    #[test]
    fn no_breach_relevant_findings_yield_no_rows() {
        let props = attack_vectors_props(&[finding("secret/app/s", false, None)]);
        assert!(props.rows.is_empty());
    }

    #[test]
    fn rows_count_distinct_objectives_reachable_and_flagged() {
        let props = attack_vectors_props(&[
            finding("secret/app/a", true, Some("exploitable — RCE")),
            finding("secret/app/b", true, None),
            // Duplicate objective on the same technique ⇒ counted once.
            finding("secret/app/a", true, Some("exploitable — RCE")),
        ]);
        assert_eq!(props.rows.len(), 1, "one tactic→technique pair");
        let row = &props.rows[0];
        assert_eq!(row.tactic, "Credential Access");
        assert_eq!(row.technique_id, "T1552");
        assert_eq!(row.reachable, 2, "two distinct objectives reachable");
        assert_eq!(row.flagged, 1, "one distinct objective flagged");
    }
}
