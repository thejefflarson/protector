//! Unit tests for [`rearm_restored_decision`] — the ADR-0034 D8 double replay-lock,
//! pure and directly testable without spinning up a whole `Engine`. The end-to-end restart
//! behavior (journal write → boot restore → live re-arm, including the enforce-mode standing-
//! cut acceptance case) is covered by the `engine::journal_tests` integration tests instead —
//! this file is scoped to the lock's own pass/fail logic.

use super::*;
use crate::engine::graph::NodeKey;
use crate::engine::reason::proof::Link;
use crate::engine::respond::ProposedAction;
use std::collections::BTreeMap;

/// A minimal, hand-built selectable menu line for `node` — a self-reference quarantine cut,
/// the same shape [`crate::engine::respond::quarantine_link`] would build. `resolve` only
/// reads `node`/`cut_signature` (plus the fields it copies verbatim into `ChosenCut`), so this
/// is a faithful stand-in without needing a real `ProvenChain`/graph.
fn quarantine_line(node: &str) -> incident::MenuLine {
    let key = NodeKey(node.to_string());
    incident::MenuLine {
        node: key.clone(),
        action: ProposedAction::QuarantineEntry,
        cut: Link {
            from: key.clone(),
            to: key,
            relation: "quarantine-entry".to_string(),
            technique: None,
            from_labels: BTreeMap::new(),
            to_labels: BTreeMap::new(),
        },
        cut_signature: format!("{node} -[quarantine-entry]-> {node}"),
        blast_note: "blast radius: no alive collateral".to_string(),
    }
}

fn menu_with(nodes: &[&str]) -> incident::Menu {
    incident::Menu {
        selectable: nodes.iter().map(|n| quarantine_line(n)).collect(),
        uncontainable: Vec::new(),
    }
}

fn restored(fingerprint: &str, cuts: Vec<journal::JournaledCut>) -> RestoredDecision {
    RestoredDecision {
        fingerprint: fingerprint.to_string(),
        assessment: incident::Assessment::Attack,
        reason: "RCE reaches the secret".to_string(),
        cuts,
    }
}

/// The success path: an unchanged fingerprint AND every cut re-resolving to its recorded
/// signature re-arms the EXACT restored decision.
#[test]
fn matching_fingerprint_and_signatures_rearms_the_exact_decision() {
    let menu = menu_with(&["workload/app/Pod/web"]);
    let r = restored(
        "fp-1",
        vec![journal::JournaledCut {
            node: "workload/app/Pod/web".into(),
            cut_signature: "workload/app/Pod/web -[quarantine-entry]-> workload/app/Pod/web".into(),
        }],
    );
    let decision =
        rearm_restored_decision(&r, "fp-1", &menu).expect("both locks hold — must re-arm");
    assert_eq!(decision.assessment, incident::Assessment::Attack);
    assert_eq!(decision.cuts.len(), 1);
    assert_eq!(
        decision.cuts[0].node,
        NodeKey("workload/app/Pod/web".into())
    );
    assert_eq!(
        decision.cuts[0].cut_signature,
        "workload/app/Pod/web -[quarantine-entry]-> workload/app/Pod/web"
    );
}

/// A decisive `NoAttack`/`Uncertain`-shaped restored decision with NO cuts re-arms on a
/// fingerprint match alone — the cut-resolution loop is vacuously satisfied over an empty set.
#[test]
fn an_empty_cut_set_rearms_on_fingerprint_match_alone() {
    let menu = incident::Menu::default();
    let mut r = restored("fp-1", Vec::new());
    r.assessment = incident::Assessment::NoAttack;
    let decision = rearm_restored_decision(&r, "fp-1", &menu).expect("no cuts to fail on");
    assert_eq!(decision.assessment, incident::Assessment::NoAttack);
    assert!(decision.cuts.is_empty());
}

/// Lock 1 (ADR-0034 D8): a fingerprint that no longer matches the entry's recomputed
/// full-prompt hash — evidence (or the rendered menu) drifted since the decision was
/// journaled — re-arms NOTHING, even though the cut would otherwise resolve cleanly.
#[test]
fn fingerprint_mismatch_rearms_nothing() {
    let menu = menu_with(&["workload/app/Pod/web"]);
    let r = restored(
        "fp-old",
        vec![journal::JournaledCut {
            node: "workload/app/Pod/web".into(),
            cut_signature: "workload/app/Pod/web -[quarantine-entry]-> workload/app/Pod/web".into(),
        }],
    );
    assert!(
        rearm_restored_decision(&r, "fp-new", &menu).is_none(),
        "a changed fingerprint must re-arm nothing (cold re-judge)"
    );
}

/// Lock 2 (ADR-0034 D8): the fingerprint matches, but the recomputed node→mechanism
/// resolution no longer yields the SAME cut signature (a label/ladder resolver drift) —
/// re-arms NOTHING rather than silently repointing the cut to a changed object.
#[test]
fn cut_signature_mismatch_rearms_nothing() {
    let menu = menu_with(&["workload/app/Pod/web"]);
    let r = restored(
        "fp-1",
        vec![journal::JournaledCut {
            node: "workload/app/Pod/web".into(),
            // A signature that does NOT match what `menu_with` resolves this node to.
            cut_signature: "workload/app/Pod/web -[deny-network-path]-> workload/app/Pod/db".into(),
        }],
    );
    assert!(
        rearm_restored_decision(&r, "fp-1", &menu).is_none(),
        "a cut signature that no longer matches the fresh resolution must re-arm nothing"
    );
}

/// A journaled cut whose node isn't on the CURRENT menu at all (it dropped out — the object
/// is gone, or no longer containable) re-arms nothing, same as a signature mismatch.
#[test]
fn a_node_missing_from_the_current_menu_rearms_nothing() {
    let menu = menu_with(&["workload/app/Pod/other"]); // the journaled node isn't here
    let r = restored(
        "fp-1",
        vec![journal::JournaledCut {
            node: "workload/app/Pod/web".into(),
            cut_signature: "workload/app/Pod/web -[quarantine-entry]-> workload/app/Pod/web".into(),
        }],
    );
    assert!(
        rearm_restored_decision(&r, "fp-1", &menu).is_none(),
        "a node no longer on the menu must re-arm nothing"
    );
}

/// A multi-cut decision re-arms only ALL-OR-NOTHING: one cut failing its lock drops the WHOLE
/// decision, never a partial re-arm of just the cuts that still resolve.
#[test]
fn one_failing_cut_drops_the_whole_multi_cut_decision() {
    let menu = menu_with(&["workload/app/Pod/web", "workload/app/Pod/store"]);
    let r = restored(
        "fp-1",
        vec![
            journal::JournaledCut {
                node: "workload/app/Pod/web".into(),
                cut_signature: "workload/app/Pod/web -[quarantine-entry]-> workload/app/Pod/web"
                    .into(),
            },
            journal::JournaledCut {
                node: "workload/app/Pod/store".into(),
                // Wrong signature for `store` — this cut alone would fail.
                cut_signature: "stale".into(),
            },
        ],
    );
    assert!(
        rearm_restored_decision(&r, "fp-1", &menu).is_none(),
        "one cut failing its lock must drop the entire decision, not just that cut"
    );
}

// --- ADR-0040: the escalated `ContainNode` cut needs NO special case in the replay lock ---

/// A hand-built menu line resolving to `ContainNode` (a self-reference on a `Host`, not a
/// workload) — mirrors [`quarantine_line`] but for the node-scoped mechanism.
fn contain_node_line(node: &str, host: &str) -> incident::MenuLine {
    let host_key = NodeKey(host.to_string());
    let cut = Link {
        from: host_key.clone(),
        to: host_key,
        relation: "contain-node".to_string(),
        technique: None,
        from_labels: BTreeMap::new(),
        to_labels: BTreeMap::new(),
    };
    incident::MenuLine {
        node: NodeKey(node.to_string()),
        action: ProposedAction::ContainNode,
        cut_signature: crate::engine::respond::cut_signature(&cut),
        cut,
        blast_note: "damage-limitation, not a clean sever: ...".to_string(),
    }
}

/// A `ContainNode` decision re-arms and re-resolves through the SAME lock as any other
/// mechanism — the lock only ever compares node/cut_signature strings, never the
/// `ProposedAction` itself, so the escalated action needs no special case.
#[test]
fn a_contain_node_decision_rearms_through_the_same_lock() {
    let line = contain_node_line("workload/app/Pod/store", "host/node-1");
    let sig = line.cut_signature.clone();
    let menu = incident::Menu {
        selectable: vec![line],
        uncontainable: Vec::new(),
    };
    let r = restored(
        "fp-1",
        vec![journal::JournaledCut {
            node: "workload/app/Pod/store".into(),
            cut_signature: sig.clone(),
        }],
    );
    let decision = rearm_restored_decision(&r, "fp-1", &menu).expect("both locks hold");
    assert_eq!(decision.cuts[0].action, ProposedAction::ContainNode);
    assert_eq!(decision.cuts[0].cut_signature, sig);
}

/// A `boundary_break` flip between passes changes a node's mechanism resolution
/// (`ContainNode` ⇄ its ordinary pod-scoped cut) — a DIFFERENT `cut_signature` for the SAME
/// node key — so lock 2 fails closed: cold re-judge, never a silent repoint from a node cut
/// to a pod cut or back.
#[test]
fn a_boundary_break_flip_fails_the_replay_lock_rather_than_repointing_the_cut() {
    let r = restored(
        "fp-1",
        vec![journal::JournaledCut {
            node: "workload/app/Pod/store".into(),
            cut_signature: "host/node-1 -[contain-node]-> host/node-1".into(),
        }],
    );
    // `boundary_break` flipped OFF since the decision was journaled: the current menu now
    // resolves `store` back to its ordinary pod-scoped quarantine cut.
    let menu = menu_with(&["workload/app/Pod/store"]);
    assert!(
        rearm_restored_decision(&r, "fp-1", &menu).is_none(),
        "a boundary_break flip must fail the replay-lock, never silently repoint the cut"
    );
}

// --- ADR-0040 §3(d): the LIVE cross-entry model-attack set ---

/// [`model_attack_set`] collects every `contain`-named node from a decisive `Attack`
/// decision, across every entry, and nothing from a `NoAttack`/`Uncertain` one.
#[test]
fn model_attack_set_collects_named_nodes_from_every_decisive_attack_entry() {
    use crate::engine::graph::NodeKey as GraphNodeKey;

    let mut decisions = BTreeMap::new();
    decisions.insert(
        "entry-a".to_string(),
        incident::IncidentDecision {
            assessment: incident::Assessment::Attack,
            reason: "x".into(),
            cuts: vec![incident::ChosenCut {
                node: GraphNodeKey("workload/app/Pod/a".into()),
                action: ProposedAction::QuarantineWorkload,
                cut: Link {
                    from: GraphNodeKey("workload/app/Pod/a".into()),
                    to: GraphNodeKey("workload/app/Pod/a".into()),
                    relation: "quarantine-workload".into(),
                    technique: None,
                    from_labels: BTreeMap::new(),
                    to_labels: BTreeMap::new(),
                },
                cut_signature: "sig-a".into(),
            }],
        },
    );
    decisions.insert(
        "entry-b".to_string(),
        incident::IncidentDecision::uncertain("model unavailable"),
    );
    let set = model_attack_set(&decisions);
    assert_eq!(set.len(), 1);
    assert!(set.contains(&GraphNodeKey("workload/app/Pod/a".into())));
}
