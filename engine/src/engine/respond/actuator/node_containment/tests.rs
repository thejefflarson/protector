//! Unit tests for the ADR-0040 node-containment actuator: the cordon/uncordon renderers,
//! the co-resident default-deny sweep, each deterministic rail, the `enforceScope`
//! confinement check (`contain_node_in_scope`), and the PROPOSAL-side gate
//! (`evaluate_proposal`) — including that it stays `None` (never armed) unless the
//! mitigation is armed, in scope, AND live-corroborated; fails closed on a host absent
//! from the observed fleet; and NEVER returns anything an apply call could reach (there is
//! no `ApplyOutcome`/`evaluate_apply` — `ProposalOutcome::Proposed` is the only "eligible"
//! outcome, and it is surfaced, never applied, per ADR-0040 §5).

use super::*;
use crate::engine::graph::attack::CREDENTIAL_ACCESS;
use crate::engine::observe::Snapshot;
use crate::engine::observe::adapter::{build_graph, default_adapters};
use crate::engine::reason::proof::Link;
use crate::engine::respond::Justification;
use serde_json::json;

/// A `ContainNode` mitigation self-referencing `host/<name>` — the exact shape
/// [`crate::engine::respond::contain_node_link`] builds.
fn contain_node_mitigation(host_name: &str) -> Mitigation {
    let host = NodeKey(format!("host/{host_name}"));
    Mitigation {
        cut: Link {
            from: host.clone(),
            to: host,
            relation: "contain-node".to_string(),
            technique: None,
            from_labels: Default::default(),
            to_labels: Default::default(),
        },
        action: ProposedAction::ContainNode,
        justifications: vec![],
    }
}

/// A `ContainNode` mitigation that ALSO clears the live-corroboration bar
/// (`Mitigation::is_live_corroborated`) — a corroborated, adjudicated,
/// breach-relevant justification, mirroring `respond::tests`' own fixture shape.
fn corroborated_contain_node_mitigation(host_name: &str) -> Mitigation {
    let mut m = contain_node_mitigation(host_name);
    m.justifications.push(Justification {
        entry: "workload/app/Pod/entry".into(),
        objective: format!("host/{host_name}"),
        attack: CREDENTIAL_ACCESS,
        foothold: false,
        corroborated: true,
        adjudicated: true,
        promoted: false,
        breach_relevant: true,
    });
    m
}

fn scheduled_pod(
    name: &str,
    node_name: &str,
    labels: serde_json::Value,
) -> k8s_openapi::api::core::v1::Pod {
    serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": name, "namespace": "app", "labels": labels},
        "spec": {
            "nodeName": node_name,
            "containers": [{"name": name, "image": format!("{name}:1")}]
        }
    }))
    .expect("valid Pod fixture")
}

fn fact(name: &str, control_plane: bool, schedulable: bool, owned: bool) -> NodeFact {
    NodeFact {
        name: name.to_string(),
        control_plane,
        schedulable,
        owned_by_protector: owned,
    }
}

// --- render_cordon / render_uncordon ---

#[test]
fn render_cordon_sets_unschedulable_and_the_ownership_annotation() {
    let manifest = render_cordon(&contain_node_mitigation("node-1")).expect("ContainNode renders");
    assert_eq!(manifest["kind"], "Node");
    assert_eq!(manifest["metadata"]["name"], "node-1");
    assert_eq!(manifest["spec"]["unschedulable"], true);
    assert_eq!(
        manifest["metadata"]["annotations"][CORDON_OWNER_ANNOTATION],
        CORDON_OWNER_VALUE
    );
}

#[test]
fn render_uncordon_clears_unschedulable_and_omits_the_ownership_annotation() {
    let manifest =
        render_uncordon(&contain_node_mitigation("node-1")).expect("ContainNode renders");
    assert_eq!(manifest["spec"]["unschedulable"], false);
    // Omitted, not null: under server-side apply this is how the SAME field manager
    // that set the annotation RELEASES it on re-apply (see the module doc).
    assert!(manifest["metadata"].get("annotations").is_none());
}

#[test]
fn render_cordon_and_uncordon_are_none_for_a_non_contain_node_action() {
    let other = Mitigation {
        cut: Link {
            from: NodeKey("workload/app/Pod/web".into()),
            to: NodeKey("workload/app/Pod/web".into()),
            relation: "quarantine-workload".to_string(),
            technique: None,
            from_labels: [("app".to_string(), "web".to_string())].into(),
            to_labels: [("app".to_string(), "web".to_string())].into(),
        },
        action: ProposedAction::QuarantineWorkload,
        justifications: vec![],
    };
    assert!(render_cordon(&other).is_none());
    assert!(render_uncordon(&other).is_none());
}

// --- co_resident_denies ---

#[test]
fn co_resident_denies_covers_every_labelled_pod_on_the_host() {
    let snap = Snapshot {
        pods: vec![
            scheduled_pod("victim", "node-1", json!({"app": "victim"})),
            scheduled_pod("neighbor", "node-1", json!({"app": "neighbor"})),
            scheduled_pod("elsewhere", "node-2", json!({"app": "elsewhere"})),
        ],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let host = NodeKey("host/node-1".into());

    let denies = co_resident_denies(&graph, &host);
    assert_eq!(denies.len(), 2, "only node-1's two co-resident pods");
    for m in &denies {
        assert_eq!(m.action, ProposedAction::QuarantineWorkload);
        assert!(m.justifications.is_empty());
    }
    let targets: std::collections::BTreeSet<_> =
        denies.iter().map(|m| m.cut.from.0.clone()).collect();
    assert!(targets.contains("workload/app/Pod/victim"));
    assert!(targets.contains("workload/app/Pod/neighbor"));
}

#[test]
fn co_resident_denies_declines_an_unlabelled_pod() {
    let snap = Snapshot {
        pods: vec![scheduled_pod("bare", "node-1", json!({}))],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let host = NodeKey("host/node-1".into());

    assert!(
        co_resident_denies(&graph, &host).is_empty(),
        "an unlabelled co-resident pod is declined, never widened to a namespace"
    );
}

#[test]
fn co_resident_denies_is_empty_for_a_host_absent_from_the_graph() {
    let graph = crate::engine::graph::SecurityGraph::new();
    let host = NodeKey("host/nonexistent".into());
    assert!(co_resident_denies(&graph, &host).is_empty());
}

// --- RailRefusal metric labels (the fixed vocabulary the metric reason keys on) ---

#[test]
fn every_rail_refusal_has_its_specified_metric_reason() {
    assert_eq!(RailRefusal::ControlPlane.metric_reason(), "control-plane");
    assert_eq!(RailRefusal::OneNodeCap.metric_reason(), "one-node-cap");
    assert_eq!(RailRefusal::WorkerFloor.metric_reason(), "worker-floor");
    assert_eq!(RailRefusal::Unlabelled.metric_reason(), "unlabelled");
    assert_eq!(RailRefusal::NotOwned.metric_reason(), "not-owned");
    assert_eq!(RailRefusal::UnknownNode.metric_reason(), "unknown-node");
}

// --- cordon_decision rails ---

#[test]
fn cordon_decision_allows_a_worker_with_a_healthy_fleet() {
    let target = fact("node-1", false, true, false);
    let fleet = vec![
        target.clone(),
        fact("node-2", false, true, false),
        fact("node-3", false, true, false),
        fact("node-4", false, true, false),
        fact("cp-1", true, true, false),
    ];
    assert_eq!(cordon_decision(&target, &fleet), Ok(()));
}

#[test]
fn cordon_decision_never_cordons_a_control_plane_node() {
    let target = fact("cp-1", true, true, false);
    let fleet = vec![
        target.clone(),
        fact("node-1", false, true, false),
        fact("node-2", false, true, false),
        fact("node-3", false, true, false),
    ];
    assert_eq!(
        cordon_decision(&target, &fleet),
        Err(RailRefusal::ControlPlane)
    );
}

#[test]
fn cordon_decision_refuses_a_second_concurrent_cordon() {
    let target = fact("node-2", false, true, false);
    let fleet = vec![
        target.clone(),
        // node-1 is ALREADY cordoned by protector (unschedulable + owned).
        fact("node-1", false, false, true),
        fact("node-3", false, true, false),
        fact("node-4", false, true, false),
    ];
    assert_eq!(
        cordon_decision(&target, &fleet),
        Err(RailRefusal::OneNodeCap)
    );
}

#[test]
fn cordon_decision_ignores_a_node_cordoned_by_someone_other_than_protector() {
    // node-1 is unschedulable but NOT owned by protector (a human/autoscaler cordon) —
    // the one-node cap only tracks protector's OWN standing cordon.
    let target = fact("node-2", false, true, false);
    let fleet = vec![
        target.clone(),
        fact("node-1", false, false, false),
        fact("node-3", false, true, false),
        fact("node-4", false, true, false),
    ];
    assert_eq!(cordon_decision(&target, &fleet), Ok(()));
}

#[test]
fn cordon_decision_refuses_when_it_would_leave_fewer_than_two_schedulable_workers() {
    // Only two workers total (target + one other) — cordoning target leaves one.
    let target = fact("node-1", false, true, false);
    let fleet = vec![
        target.clone(),
        fact("node-2", false, true, false),
        fact("cp-1", true, true, false),
    ];
    assert_eq!(
        cordon_decision(&target, &fleet),
        Err(RailRefusal::WorkerFloor)
    );
}

#[test]
fn cordon_decision_worker_floor_excludes_already_unschedulable_and_control_plane_nodes() {
    // Three other entries, but only one is a schedulable, non-control-plane worker —
    // the floor must count REAL headroom, not raw fleet size.
    let target = fact("node-1", false, true, false);
    let fleet = vec![
        target.clone(),
        fact("node-2", false, true, false), // the one real worker left
        fact("node-3", false, false, false), // already unschedulable — doesn't count
        fact("cp-1", true, true, false),    // control-plane — doesn't count
    ];
    assert_eq!(
        cordon_decision(&target, &fleet),
        Err(RailRefusal::WorkerFloor)
    );
}

#[test]
fn cordon_decision_at_exactly_the_floor_is_allowed() {
    // Cordoning target leaves EXACTLY two schedulable workers — the floor is inclusive.
    let target = fact("node-1", false, true, false);
    let fleet = vec![
        target.clone(),
        fact("node-2", false, true, false),
        fact("node-3", false, true, false),
        fact("cp-1", true, true, false),
    ];
    assert_eq!(cordon_decision(&target, &fleet), Ok(()));
}

// --- revert_decision: ownership-gated ---

#[test]
fn revert_decision_allows_uncordoning_a_node_protector_owns() {
    let target = fact("node-1", false, false, true);
    assert_eq!(revert_decision(&target), Ok(()));
}

#[test]
fn revert_decision_refuses_a_node_protector_never_cordoned() {
    let target = fact("node-1", false, false, false);
    assert_eq!(revert_decision(&target), Err(RailRefusal::NotOwned));
}

// --- rails are pure over the fleet, independent of any arming/enabled state ---

#[test]
fn rail_decisions_take_no_arming_state_and_so_are_exactly_as_meaningful_in_shadow() {
    // `cordon_decision`/`revert_decision` accept only `NodeFact`/fleet data — no
    // `EnabledActions`, no `ActuationScope`, no mode. A refusal computed here is
    // identically valid whether or not anything is armed, which is what lets a
    // rail-refused event be counted "in shadow" (nothing armed) exactly as it would be
    // once a `node` rung exists.
    let control_plane = fact("cp-1", true, true, false);
    let fleet = vec![control_plane.clone()];
    assert_eq!(
        cordon_decision(&control_plane, &fleet),
        Err(RailRefusal::ControlPlane)
    );
    let unowned = fact("node-1", false, false, false);
    assert_eq!(revert_decision(&unowned), Err(RailRefusal::NotOwned));
}

// --- co_resident_denies_in_scope / ScopedDenies (ADR-0040 addendum, ADR-0021) ---

#[test]
fn co_resident_denies_in_scope_returns_the_full_set_when_unscoped() {
    let snap = Snapshot {
        pods: vec![
            scheduled_pod("victim", "node-1", json!({"app": "victim"})),
            scheduled_pod("neighbor", "node-1", json!({"app": "neighbor"})),
        ],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let host = NodeKey("host/node-1".into());

    let scoped = co_resident_denies_in_scope(&graph, &host, &ActuationScope::unscoped());
    assert_eq!(
        scoped.as_slice().len(),
        co_resident_denies(&graph, &host).len(),
        "unscoped returns the same full set co_resident_denies does"
    );
}

#[test]
fn co_resident_denies_in_scope_retains_only_the_in_scope_namespace() {
    let snap = Snapshot {
        pods: vec![
            scheduled_pod("victim", "node-1", json!({"app": "victim"})),
            scheduled_pod("neighbor", "node-1", json!({"app": "neighbor"})),
        ],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let host = NodeKey("host/node-1".into());
    // Both pods live in the "app" namespace (`scheduled_pod`'s own fixture), so scoping to
    // it must retain BOTH — this asserts the subset tracks the scope match, not an
    // arbitrary truncation.
    let scope = ActuationScope::enforce_namespaces(["app".to_string()]);

    let scoped = co_resident_denies_in_scope(&graph, &host, &scope);
    assert_eq!(scoped.as_slice().len(), 2);
}

#[test]
fn co_resident_denies_in_scope_is_empty_when_no_co_resident_pod_is_in_scope() {
    let snap = Snapshot {
        pods: vec![scheduled_pod("victim", "node-1", json!({"app": "victim"}))],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let host = NodeKey("host/node-1".into());
    let scope = ActuationScope::enforce_namespaces(["payments".to_string()]);

    let scoped = co_resident_denies_in_scope(&graph, &host, &scope);
    assert!(
        scoped.is_empty(),
        "the only co-resident pod is outside the configured scope"
    );
}

#[test]
fn co_resident_denies_in_scope_matches_on_the_label_axis() {
    let snap = Snapshot {
        pods: vec![
            scheduled_pod("victim", "node-1", json!({"app": "victim", "tier": "hot"})),
            scheduled_pod("neighbor", "node-1", json!({"app": "neighbor"})),
        ],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let host = NodeKey("host/node-1".into());
    // Namespace axis is empty; only the label axis is configured, and only "victim"
    // carries it — the subset must track the LABEL match, not the namespace (both pods
    // share the same "app" namespace).
    let scope = ActuationScope::new(
        Default::default(),
        vec![("tier".to_string(), "hot".to_string())],
    );

    let scoped = co_resident_denies_in_scope(&graph, &host, &scope);
    assert_eq!(scoped.as_slice().len(), 1);
    assert_eq!(scoped.as_slice()[0].cut.from.0, "workload/app/Pod/victim");
}

// The compile-time half of "constructible only by `co_resident_denies_in_scope`" lives as
// a `compile_fail` doctest on the [`ScopedDenies`] type itself (this `tests` module is
// `#[cfg(test)]`, which rustdoc never compiles, so a doctest here would silently never
// run). This is the runtime witness: the ONLY way this test (or anything outside the
// module) obtains a `ScopedDenies` is through the function — there is no
// `ScopedDenies::new`/`From`/public tuple constructor to call instead.
#[test]
fn scoped_denies_has_no_public_constructor_besides_co_resident_denies_in_scope() {
    let graph = crate::engine::graph::SecurityGraph::new();
    let host = NodeKey("host/nonexistent".into());
    let scoped = co_resident_denies_in_scope(&graph, &host, &ActuationScope::unscoped());
    assert!(scoped.is_empty());
}

// --- contain_node_in_scope: enforceScope confinement (ADR-0021) ---

#[test]
fn contain_node_in_scope_is_true_when_unscoped() {
    // No enforceScope configured at all (both axes empty) is the historical
    // "every namespace eligible" meaning, not "matches nothing" — even a host with NO
    // co-resident labelled pod at all must read as in scope here.
    let graph = crate::engine::graph::SecurityGraph::new();
    let host = NodeKey("host/node-1".into());
    assert!(contain_node_in_scope(
        &graph,
        &host,
        &crate::engine::respond::actuator::ActuationScope::unscoped()
    ));
}

#[test]
fn contain_node_in_scope_matches_a_co_resident_labelled_pods_namespace() {
    let snap = Snapshot {
        pods: vec![scheduled_pod("victim", "node-1", json!({"app": "victim"}))],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let host = NodeKey("host/node-1".into());
    let scope =
        crate::engine::respond::actuator::ActuationScope::enforce_namespaces(["app".to_string()]);
    assert!(contain_node_in_scope(&graph, &host, &scope));
}

#[test]
fn contain_node_in_scope_is_false_when_no_co_resident_pod_is_in_a_configured_scope() {
    // A real, non-empty enforceScope is configured, but the host's only co-resident
    // labelled pod lives in a DIFFERENT namespace — checking the host's OWN cut
    // directly (the bug this function fixes) would read as vacuously in scope; this
    // must not.
    let snap = Snapshot {
        pods: vec![scheduled_pod("victim", "node-1", json!({"app": "victim"}))],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let host = NodeKey("host/node-1".into());
    let scope = crate::engine::respond::actuator::ActuationScope::enforce_namespaces([
        "payments".to_string()
    ]);
    assert!(!contain_node_in_scope(&graph, &host, &scope));
}

#[test]
fn contain_node_in_scope_is_false_for_a_scoped_host_with_no_labelled_co_resident_pod() {
    // A scope IS configured, but the host's only co-resident pod carries no labels at
    // all (so `co_resident_denies` declines it, same as everywhere else) — never
    // presumed in scope just because there was nothing to check.
    let snap = Snapshot {
        pods: vec![scheduled_pod("bare", "node-1", json!({}))],
        ..Default::default()
    };
    let graph = build_graph(&snap, &default_adapters());
    let host = NodeKey("host/node-1".into());
    let scope =
        crate::engine::respond::actuator::ActuationScope::enforce_namespaces(["app".to_string()]);
    assert!(!contain_node_in_scope(&graph, &host, &scope));
}

// --- evaluate_proposal: the PROPOSAL-side gate Engine::process calls (ADR-0040 §5/§6) ---
// NEVER an apply gate — there is no `ApplyOutcome`/apply call path for `ContainNode` at
// all; `ProposalOutcome::Proposed` is surfaced, never acted on.

#[test]
fn evaluate_proposal_is_none_for_a_non_contain_node_action() {
    let other = Mitigation {
        cut: Link {
            from: NodeKey("workload/app/Pod/web".into()),
            to: NodeKey("workload/app/Pod/web".into()),
            relation: "quarantine-workload".to_string(),
            technique: None,
            from_labels: [("app".to_string(), "web".to_string())].into(),
            to_labels: [("app".to_string(), "web".to_string())].into(),
        },
        action: ProposedAction::QuarantineWorkload,
        justifications: vec![],
    };
    assert_eq!(evaluate_proposal(&other, true, true, &[]), None);
}

#[test]
fn evaluate_proposal_is_none_when_not_armed() {
    let m = corroborated_contain_node_mitigation("node-1");
    let fleet = vec![
        fact("node-1", false, true, false),
        fact("node-2", false, true, false),
    ];
    assert_eq!(evaluate_proposal(&m, false, true, &fleet), None);
}

#[test]
fn evaluate_proposal_is_none_when_out_of_scope() {
    let m = corroborated_contain_node_mitigation("node-1");
    let fleet = vec![
        fact("node-1", false, true, false),
        fact("node-2", false, true, false),
    ];
    assert_eq!(evaluate_proposal(&m, true, false, &fleet), None);
}

#[test]
fn evaluate_proposal_is_none_when_not_live_corroborated() {
    // `contain_node_mitigation` carries no justifications at all — never corroborated.
    let m = contain_node_mitigation("node-1");
    let fleet = vec![
        fact("node-1", false, true, false),
        fact("node-2", false, true, false),
    ];
    assert_eq!(evaluate_proposal(&m, true, true, &fleet), None);
}

#[test]
fn evaluate_proposal_fails_closed_on_a_host_absent_from_the_fleet() {
    // Armed + in-scope + corroborated, but the fleet has no entry for the target host at
    // all (the watch hasn't synced, or the host no longer exists) — must refuse, never
    // fabricate a passing rail.
    let m = corroborated_contain_node_mitigation("node-1");
    let fleet = vec![
        fact("node-2", false, true, false),
        fact("node-3", false, true, false),
    ];
    assert_eq!(
        evaluate_proposal(&m, true, true, &fleet),
        Some(ProposalOutcome::Refuse(RailRefusal::UnknownNode))
    );
}

#[test]
fn evaluate_proposal_proposes_when_eligible_and_the_rails_pass() {
    let m = corroborated_contain_node_mitigation("node-1");
    let fleet = vec![
        fact("node-1", false, true, false),
        fact("node-2", false, true, false),
        fact("node-3", false, true, false),
        fact("cp-1", true, true, false),
    ];
    assert_eq!(
        evaluate_proposal(&m, true, true, &fleet),
        Some(ProposalOutcome::Proposed)
    );
}

#[test]
fn evaluate_proposal_still_proposes_a_standing_protector_cordon() {
    // The target is ALREADY cordoned by protector (unschedulable + owned) — the rails
    // still pass (cordon_decision doesn't gate on the target's own state, only on the
    // REST of the fleet). There is no "already applied, skip" branch to test here:
    // `ProposalOutcome` carries no such field — proposing is idempotent by nature (it
    // never writes anything), unlike the apply path this ticket deliberately does not
    // have.
    let m = corroborated_contain_node_mitigation("node-1");
    let fleet = vec![
        fact("node-1", false, false, true),
        fact("node-2", false, true, false),
        fact("node-3", false, true, false),
    ];
    assert_eq!(
        evaluate_proposal(&m, true, true, &fleet),
        Some(ProposalOutcome::Proposed)
    );
}

#[test]
fn evaluate_proposal_surfaces_the_cordon_rail_refusal() {
    // Eligible on every upstream gate, but the target is control-plane — the rail (not
    // the arming/scope/corroboration gate) is what refuses here.
    let m = corroborated_contain_node_mitigation("cp-1");
    let fleet = vec![
        fact("cp-1", true, true, false),
        fact("node-1", false, true, false),
    ];
    assert_eq!(
        evaluate_proposal(&m, true, true, &fleet),
        Some(ProposalOutcome::Refuse(RailRefusal::ControlPlane))
    );
}
