//! The counts-only ATT&CK-outcome reducer: turn the per-objective (target, technique)
//! pairs a decision reached into the redacted "outcome" — WHICH techniques, never the
//! targets — so the caller keeps only a COUNT of the crown-jewel objectives.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::sanitize;
use crate::engine::graph::attack::AttackRef;

/// Reduce the reached ATT&CK `refs` to the redacted outcome: the DISTINCT
/// `(tactic, technique_id, technique)` triples, ordered deterministically, each technique
/// name sanitized, capped at `cap`.
///
/// This is the counts-only redaction rule ADR-0018 §2 / ADR-0031 §2 draw: it surfaces the
/// low-cardinality technique IDs from our own ATT&CK table (the "outcome") but drops the
/// per-objective TARGETS — the secret names and peer nodes — by construction, since it
/// takes only the `AttackRef`s, never the objective keys. The caller surfaces a COUNT of
/// the objectives alongside it (`objectives.len()`), never the list. Shared by the notifier
/// and the MCP `list_findings` / `explain_verdict` tools so the two egress paths agree on
/// what an "outcome" is allowed to disclose.
///
/// The technique name is a `'static` constant from our own table, not cluster data, but it
/// is sanitized anyway so every field of the outcome is uniformly structure-safe.
pub(crate) fn redacted_attack_outcome<'a>(
    refs: impl IntoIterator<Item = &'a AttackRef>,
    cap: usize,
) -> Vec<Value> {
    // A BTreeSet dedups and orders the triples deterministically (stable payloads = stable
    // tests). Every element is `'static`, so the set outlives the borrowed `refs`.
    let mut distinct: BTreeSet<(&'static str, &'static str, &'static str)> = BTreeSet::new();
    for a in refs {
        distinct.insert((a.tactic.id(), a.technique_id, a.technique));
    }
    distinct
        .into_iter()
        .take(cap)
        .map(|(tactic, technique_id, technique)| {
            json!({
                "tactic": tactic,
                "technique_id": technique_id,
                "technique": sanitize(technique),
            })
        })
        .collect()
}
