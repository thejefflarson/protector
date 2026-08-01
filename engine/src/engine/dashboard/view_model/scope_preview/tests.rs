//! View-model tests for the scope-preview panel: the candidate scope is echoed back, the
//! honest-empty-candidate reading, the collateral/collateral-unknown pass-through, and the
//! action mechanism rendered via `describe()`.

use super::*;
use crate::engine::graph::NodeKey;
use crate::engine::reason::proof::Link;
use crate::engine::respond::{Justification, ProposedAction};

fn strip() -> StatusStripProps {
    StatusStripProps {
        cluster: "prod-test".into(),
        armed: false,
        model_judging: true,
        warming_up: false,
        model_attached: true,
        coverage: vec![],
        coverage_alert: None,
        last_pass: None,
        breach_count: 0,
        awaiting_count: 0,
        uncertain_count: 0,
        cleared_count: 0,
        escalated_count: 0,
        signing_regression_breach: 0,
        signing_regression_uncertain: 0,
        auth_mode: crate::engine::dashboard::view_model::props::AuthMode::EdgeOnly,
    }
}

fn justified_mitigation(from: &str, to: &str) -> Mitigation {
    Mitigation {
        cut: Link {
            from: NodeKey(from.to_string()),
            to: NodeKey(to.to_string()),
            relation: "reaches/Tcp/5432".to_string(),
            technique: None,
            from_labels: Default::default(),
            to_labels: Default::default(),
        },
        action: ProposedAction::DenyNetworkPath,
        justifications: vec![Justification {
            entry: "workload/app/Pod/web".to_string(),
            objective: "secret/app/db-creds".to_string(),
            attack: crate::engine::graph::attack::CREDENTIAL_ACCESS,
            foothold: false,
            corroborated: true,
            adjudicated: true,
            promoted: false,
            breach_relevant: true,
        }],
    }
}

#[test]
fn empty_candidate_echoes_back_empty_and_flags_itself() {
    let standing = vec![(
        justified_mitigation("workload/app/Pod/web", "workload/app/Pod/db"),
        BlastRadius::default(),
    )];
    let view = build(strip(), &standing, &[], &[]);
    assert!(view.candidate_namespaces.is_empty());
    assert!(view.candidate_labels.is_empty());
    assert!(view.candidate_is_empty);
    assert!(
        view.would_fire.is_empty(),
        "an empty candidate scope must fire nothing"
    );
    assert_eq!(view.held_out_of_scope.len(), 1);
}

#[test]
fn in_scope_cut_carries_its_collateral_and_mechanism() {
    let blast = BlastRadius {
        alive_collateral: vec!["workload/app/Pod/metrics".to_string()],
        reachability_incomplete: false,
    };
    let standing = vec![(
        justified_mitigation("workload/app/Pod/web", "workload/app/Pod/db"),
        blast,
    )];
    let namespaces = vec!["app".to_string()];
    let view = build(strip(), &standing, &namespaces, &[]);
    assert!(!view.candidate_is_empty);
    assert_eq!(view.candidate_namespaces, vec!["app".to_string()]);
    assert_eq!(view.would_fire.len(), 1);
    let fired = &view.would_fire[0];
    assert_eq!(
        fired.alive_collateral,
        vec!["workload/app/Pod/metrics".to_string()]
    );
    assert!(!fired.collateral_unknown);
    assert_eq!(fired.action, ProposedAction::DenyNetworkPath.describe());
}

#[test]
fn candidate_labels_echo_back_as_key_equals_value() {
    let labels = vec![("tier".to_string(), "prod".to_string())];
    let view = build(strip(), &[], &[], &labels);
    assert_eq!(view.candidate_labels, vec!["tier=prod".to_string()]);
    assert!(!view.candidate_is_empty);
}

#[test]
fn collateral_unknown_flag_survives_into_the_props() {
    let blast = BlastRadius {
        alive_collateral: vec![],
        reachability_incomplete: true,
    };
    let standing = vec![(
        justified_mitigation("workload/app/Pod/web", "workload/app/Pod/db"),
        blast,
    )];
    let namespaces = vec!["app".to_string()];
    let view = build(strip(), &standing, &namespaces, &[]);
    assert!(view.would_fire[0].collateral_unknown);
    assert!(view.would_fire[0].alive_collateral.is_empty());
}
