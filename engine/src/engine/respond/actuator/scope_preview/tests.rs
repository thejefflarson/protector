//! Unit tests for the pre-arm scope-simulation preview: the mutation-free proof, the
//! in-scope/out-of-scope partition, the collateral pass-through (including the
//! collateral-unknown flag), the honest-empty-scope reading, and the would-ever-act
//! eligibility filter.

use super::*;
use crate::engine::graph::NodeKey;
use crate::engine::graph::attack::CREDENTIAL_ACCESS;
use crate::engine::reason::proof::Link;
use crate::engine::respond::Justification;
use std::collections::HashSet;

fn mitigation(from: &str, to: &str, action: ProposedAction, justified: bool) -> Mitigation {
    Mitigation {
        cut: Link {
            from: NodeKey(from.to_string()),
            to: NodeKey(to.to_string()),
            relation: "reaches/Tcp/5432".to_string(),
            technique: None,
            from_labels: Default::default(),
            to_labels: Default::default(),
        },
        action,
        justifications: if justified {
            vec![Justification {
                entry: "workload/app/Pod/web".to_string(),
                objective: "secret/app/db-creds".to_string(),
                attack: CREDENTIAL_ACCESS,
                foothold: false,
                corroborated: true,
                adjudicated: true,
                promoted: false,
                breach_relevant: true,
            }]
        } else {
            vec![]
        },
    }
}

fn scope(namespaces: &[&str]) -> ActuationScope {
    ActuationScope::new(
        namespaces.iter().map(|s| s.to_string()).collect(),
        Vec::new(),
    )
}

#[test]
fn in_scope_cut_fires_with_its_precomputed_collateral() {
    let m = mitigation(
        "workload/app/Pod/web",
        "workload/app/Pod/db",
        ProposedAction::DenyNetworkPath,
        true,
    );
    let blast = BlastRadius {
        alive_collateral: vec!["workload/app/Pod/metrics".to_string()],
        reachability_incomplete: false,
    };
    let preview = preview_scope(&[(m, blast)], &scope(&["app"]));
    assert_eq!(preview.would_fire.len(), 1);
    assert!(preview.held_out_of_scope.is_empty());
    let fired = &preview.would_fire[0];
    assert_eq!(
        fired.cut,
        "workload/app/Pod/web -[reaches/Tcp/5432]-> workload/app/Pod/db"
    );
    assert_eq!(
        fired.alive_collateral,
        vec!["workload/app/Pod/metrics".to_string()]
    );
    assert!(!fired.collateral_unknown);
}

#[test]
fn out_of_scope_cut_is_held_never_shown_as_firing() {
    let m = mitigation(
        "workload/app/Pod/web",
        "workload/data/Pod/db",
        ProposedAction::DenyNetworkPath,
        true,
    );
    // Scope covers only the source's namespace, not the target's — held.
    let preview = preview_scope(&[(m, BlastRadius::default())], &scope(&["app"]));
    assert!(preview.would_fire.is_empty());
    assert_eq!(preview.held_out_of_scope.len(), 1);
}

#[test]
fn empty_candidate_scope_is_an_honest_zero_not_unscoped() {
    // A candidate scope with nothing in it must NOT be read as "matches everything" —
    // that reading is exactly the enforce-everywhere wildcard ADR-0021 refuses to start
    // with. Every eligible cut is held, none fire.
    let m = mitigation(
        "workload/app/Pod/web",
        "workload/app/Pod/db",
        ProposedAction::DenyNetworkPath,
        true,
    );
    let empty = ActuationScope::new(HashSet::new(), Vec::new());
    let preview = preview_scope(&[(m, BlastRadius::default())], &empty);
    assert!(
        preview.would_fire.is_empty(),
        "empty candidate scope must fire nothing"
    );
    assert_eq!(preview.held_out_of_scope.len(), 1);
}

#[test]
fn collateral_unknown_is_never_collapsed_into_an_empty_safe_reading() {
    let m = mitigation(
        "workload/app/Pod/web",
        "workload/app/Pod/db",
        ProposedAction::DenyNetworkPath,
        true,
    );
    let blind = BlastRadius {
        alive_collateral: vec![],
        reachability_incomplete: true,
    };
    let preview = preview_scope(&[(m, blind)], &scope(&["app"]));
    let fired = &preview.would_fire[0];
    assert!(fired.alive_collateral.is_empty());
    assert!(
        fired.collateral_unknown,
        "an unmodeled graph must flag collateral unknown, never imply safety"
    );
}

#[test]
fn ineligible_cuts_are_excluded_entirely_not_mislabeled_held() {
    // Irreversible, subtractive, and uncorroborated cuts would never act regardless of
    // scope — they must not show up in either bucket (mislabeling them "held (out of
    // scope)" would blame the wrong gate).
    let irreversible = mitigation(
        "workload/ci/Pod/runner",
        "host/node-1",
        ProposedAction::RemoveEscapePrimitive,
        true,
    );
    let subtractive = mitigation(
        "identity/ops/ops-sa",
        "capability/cluster/create/pods",
        ProposedAction::RevokeRbacGrant,
        true,
    );
    let uncorroborated = mitigation(
        "workload/app/Pod/web",
        "workload/app/Pod/db",
        ProposedAction::DenyNetworkPath,
        false,
    );
    let standing = vec![
        (irreversible, BlastRadius::default()),
        (subtractive, BlastRadius::default()),
        (uncorroborated, BlastRadius::default()),
    ];
    let preview = preview_scope(&standing, &scope(&["app", "ci", "ops"]));
    assert!(preview.would_fire.is_empty());
    assert!(preview.held_out_of_scope.is_empty());
}

#[test]
fn no_standing_cuts_is_an_empty_preview() {
    let preview = preview_scope(&[], &scope(&["app"]));
    assert_eq!(preview, ScopePreview::default());
}
