//! Tests for the corroboration-parity fold (JEF-310). The tested core is source attribution
//! (which chain counts as agent-uncovered) and the HONESTY invariant: a window with no Falco
//! corroboration reads "nothing to compare", never a reassuring "0 uncovered = safe".

use super::*;
use crate::engine::graph::NodeKey;
use crate::engine::graph::attack::{CREDENTIAL_ACCESS, EXPLOIT_PUBLIC_FACING};
use crate::engine::reason::proof::ProvenChain;

/// Build a breach-relevant (or not) chain with an explicit per-source corroboration split — the
/// exact seam the parity fold reads. Everything else is inert.
fn chain(entry: &str, exposed: bool, by_falco: bool, by_agent: bool) -> ProvenChain {
    ProvenChain {
        entry: NodeKey(entry.into()),
        objective: NodeKey("secret/app/s".into()),
        attack: CREDENTIAL_ACCESS,
        foothold: Some(EXPLOIT_PUBLIC_FACING),
        corroborated: by_falco || by_agent,
        corroborated_by_falco: by_falco,
        corroborated_by_agent: by_agent,
        adjudicated: true,
        promoted: false,
        exposed_entry: exposed,
        verdict: None,
        links: vec![],
        paths: vec![],
        paths_truncated: false,
        single_edge_cuts: vec![],
        quarantine_targets: vec![],
    }
}

#[test]
fn chain_corroborated_by_both_is_not_uncovered() {
    let parity = derive_parity(&[chain("workload/app/Pod/web", true, true, true)]);
    assert_eq!(parity.both, 1);
    assert_eq!(parity.agent_uncovered, 0);
    assert_eq!(parity.falco_corroborated, 1);
    assert_eq!(parity.agent_corroborated, 1);
    assert!(parity.uncovered_entries.is_empty());
    // Falco fired and the agent matched it → parity this window.
    assert_eq!(parity.readiness(), ParityReadiness::Parity);
}

#[test]
fn falco_only_chain_is_agent_uncovered() {
    let parity = derive_parity(&[chain("workload/app/Pod/web", true, true, false)]);
    assert_eq!(parity.agent_uncovered, 1);
    assert_eq!(parity.falco_corroborated, 1);
    assert_eq!(parity.agent_corroborated, 0);
    assert_eq!(parity.both, 0);
    assert_eq!(parity.uncovered_entries, vec!["workload/app/Pod/web"]);
    assert_eq!(
        parity.readiness(),
        ParityReadiness::Uncovered { count: 1 },
        "Falco saw a chain the agent didn't — not safe to retire"
    );
}

#[test]
fn agent_only_chain_is_not_uncovered() {
    let parity = derive_parity(&[chain("workload/app/Pod/web", true, false, true)]);
    assert_eq!(parity.agent_only, 1);
    assert_eq!(parity.agent_uncovered, 0);
    assert_eq!(parity.agent_corroborated, 1);
    assert_eq!(parity.falco_corroborated, 0);
    // Falco corroborated nothing this window, so there is nothing to compare — the agent covering
    // it on its own does NOT read as a reassuring "0 uncovered = safe".
    assert_eq!(parity.readiness(), ParityReadiness::NothingToCompare);
}

#[test]
fn empty_window_reads_nothing_to_compare_not_safe() {
    // No corroborations at all this window: the honest reading is "nothing to compare", the same
    // as a Falco-silent window — NEVER "0 uncovered = safe to retire" (ADR-0016 honesty).
    let empty = derive_parity(&[]);
    assert_eq!(empty.falco_corroborated, 0);
    assert_eq!(empty.agent_uncovered, 0);
    assert_eq!(
        empty.readiness(),
        ParityReadiness::NothingToCompare,
        "an empty window is 'nothing to compare', not a green go-signal"
    );
    // A window with only UNCORROBORATED breach chains is likewise nothing-to-compare, not safe.
    let uncorroborated = derive_parity(&[chain("workload/app/Pod/web", true, false, false)]);
    assert_eq!(
        uncorroborated.readiness(),
        ParityReadiness::NothingToCompare
    );
}

#[test]
fn non_breach_relevant_chains_are_excluded() {
    // An internal-only (not internet-facing) chain is not a breach path — it must not enter the
    // parity population even if a Falco alert corroborated it (mirrors the `corroborations` scope).
    let parity = derive_parity(&[chain("workload/app/Pod/internal", false, true, false)]);
    assert_eq!(parity.falco_corroborated, 0);
    assert_eq!(parity.agent_uncovered, 0);
    assert_eq!(parity.readiness(), ParityReadiness::NothingToCompare);
}

#[test]
fn mixed_window_counts_each_source_and_dedups_uncovered_entries() {
    // A realistic dual-sensor window: one both, one Falco-only, one agent-only, plus a SECOND
    // Falco-only chain on the SAME entry (a broad entry reaches several objectives) — the entry
    // list dedups, but the chain count does not.
    let parity = derive_parity(&[
        chain("workload/app/Pod/web", true, true, true),
        chain("workload/app/Pod/api", true, true, false),
        chain("workload/app/Pod/api", true, true, false),
        chain("workload/app/Pod/db", true, false, true),
    ]);
    assert_eq!(parity.both, 1);
    assert_eq!(parity.agent_uncovered, 2, "two Falco-only chains counted");
    assert_eq!(parity.agent_only, 1);
    assert_eq!(parity.falco_corroborated, 3);
    assert_eq!(parity.agent_corroborated, 2);
    assert_eq!(
        parity.uncovered_entries,
        vec!["workload/app/Pod/api"],
        "uncovered entries dedup by workload"
    );
    assert_eq!(parity.readiness(), ParityReadiness::Uncovered { count: 2 });
}
