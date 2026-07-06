//! Unit tests for the actuator: the action allowlist + decide gate, the blast-radius
//! prediction, the closed-loop verify, and the pure manifest rendering. Split out of
//! the actuator module root purely to keep every file under the 1,000-line cap (repo
//! CLAUDE.md). `use super::*` resolves to the actuator module, so the tests see what the
//! inline `mod tests` block saw; the renderers live in `super::render`.
#![allow(unused_imports)]

use super::*;
use crate::engine::graph::attack::CREDENTIAL_ACCESS;
use crate::engine::graph::{Edge, Exposure, Node, NodeKey, Protocol, Provenance, Workload};
use crate::engine::reason::proof::Link;
use crate::engine::respond::{Justification, ProposedAction};
use std::time::SystemTime;

fn mitigation(from: &str, relation: &str, to: &str, action: ProposedAction) -> Mitigation {
    Mitigation {
        cut: Link {
            from: NodeKey(from.to_string()),
            to: NodeKey(to.to_string()),
            relation: relation.to_string(),
            technique: None,
            from_labels: Default::default(),
            to_labels: Default::default(),
        },
        action,
        justifications: vec![],
    }
}

fn justification(foothold: bool, corroborated: bool, adjudicated: bool) -> Justification {
    Justification {
        entry: "workload/app/Pod/web".to_string(),
        objective: "secret/app/db-creds".to_string(),
        attack: CREDENTIAL_ACCESS,
        foothold,
        corroborated,
        adjudicated,
        promoted: false,
        // These tests exercise the corroboration/foothold/reversibility axes;
        // breach-relevance (internet-facing entry) is held true so it isn't the
        // gating factor here. The breach-relevance gate is tested in response.rs.
        breach_relevant: true,
    }
}

/// A justification that is live-actionable (corroborated + adjudicated).
fn corroborated() -> Justification {
    justification(true, true, true)
}

/// A justification auto-actionable via model promotion, not runtime corroboration.
fn promoted() -> Justification {
    Justification {
        promoted: true,
        ..justification(false, false, true)
    }
}

fn health(entries: &[(&str, Health)]) -> HealthReport {
    let mut r = HealthReport::default();
    for (k, h) in entries {
        r.insert(NodeKey(k.to_string()), *h);
    }
    r
}

/// An app-namespace Pod workload node (keyed `workload/app/Pod/<name>`).
fn pod(name: &str) -> Node {
    Node::Workload(Workload {
        namespace: "app".to_string(),
        name: name.to_string(),
        kind: "Pod".to_string(),
        labels: Default::default(),
        meshed: false,
        exposure: Exposure::Internal,
        runtime: vec![],
        persistent: false,
        misconfigs: vec![],
        rbac_findings: vec![],
    })
}

fn reaches() -> Edge {
    Edge {
        relation: Relation::Reaches {
            port: None,
            protocol: Protocol::Tcp,
        },
        provenance: Provenance::new("test", SystemTime::UNIX_EPOCH),
    }
}

#[test]
fn blast_radius_excludes_cut_endpoints_counts_other_reaches() {
    // Isolating `web` (default-deny on the source) cuts web's ENTIRE egress, so
    // the blast radius is every alive workload web reaches *except* the target
    // we deliberately sever. web reaches db (the cut target), metrics (a live
    // bystander), and ghost (down). Cut = web→db.
    let mut g = SecurityGraph::new();
    let web = g.upsert_node(pod("web"));
    let db = g.upsert_node(pod("db"));
    let metrics = g.upsert_node(pod("metrics"));
    let ghost = g.upsert_node(pod("ghost"));
    g.add_edge(web, db, reaches());
    g.add_edge(web, metrics, reaches());
    g.add_edge(web, ghost, reaches());

    let m = mitigation(
        "workload/app/Pod/web",
        "reaches/Tcp/5432",
        "workload/app/Pod/db",
        ProposedAction::DenyNetworkPath,
    );
    let h = health(&[
        ("workload/app/Pod/web", Health::Alive),
        ("workload/app/Pod/db", Health::Alive),
        ("workload/app/Pod/metrics", Health::Alive),
        ("workload/app/Pod/ghost", Health::Halted),
    ]);
    // db excluded (intended severance), web excluded (the subject), ghost
    // excluded (not alive) ⇒ only the live bystander `metrics` is collateral.
    assert_eq!(
        predict_blast_radius(&m, &g, &h).alive_collateral,
        vec!["workload/app/Pod/metrics".to_string()]
    );

    // A cut whose source reaches nothing else has no collateral ⇒ auto-eligible.
    let mut g2 = SecurityGraph::new();
    let only_web = g2.upsert_node(pod("web"));
    let only_db = g2.upsert_node(pod("db"));
    g2.add_edge(only_web, only_db, reaches());
    assert!(
        predict_blast_radius(&m, &g2, &h)
            .alive_collateral
            .is_empty()
    );

    // can-do from an Identity to a Capability ⇒ source has no reaches edges, no
    // collateral (the workload-key guard prevents the false positive).
    let rbac = mitigation(
        "identity/ops/ops-sa",
        "can-do/create/pods",
        "capability/cluster/create/pods",
        ProposedAction::RevokeRbacGrant,
    );
    assert!(
        predict_blast_radius(&rbac, &g, &health(&[]))
            .alive_collateral
            .is_empty()
    );
}

#[test]
fn decide_forbids_irreversible() {
    let m = mitigation(
        "workload/ci/Pod/runner",
        "escapes-to/privileged",
        "host/node-1",
        ProposedAction::RemoveEscapePrimitive,
    );
    let d = decide(
        &m,
        &EnabledActions::none(),
        &ActuationScope::unscoped(),
        &BlastRadius::default(),
    );
    assert!(matches!(d, Decision::Forbidden(_)));
}

#[test]
fn decide_proposes_on_live_collateral_even_when_enabled() {
    let m = mitigation(
        "workload/app/Pod/web",
        "reaches/Tcp/5432",
        "workload/app/Pod/db",
        ProposedAction::DenyNetworkPath,
    );
    let active = EnabledActions::none().enable(ProposedAction::DenyNetworkPath);
    let blast = BlastRadius {
        alive_collateral: vec!["workload/app/Pod/web".to_string()],
        ..Default::default()
    };
    assert!(matches!(
        decide(&m, &active, &ActuationScope::unscoped(), &blast),
        Decision::Propose(_)
    ));

    // Even with no collateral, an incompletely-modeled graph fails safe.
    let unknown = BlastRadius {
        alive_collateral: vec![],
        reachability_incomplete: true,
    };
    let live = Mitigation {
        justifications: vec![corroborated()],
        ..m
    };
    assert!(matches!(
        decide(
            &live,
            &EnabledActions::none().enable(ProposedAction::DenyNetworkPath),
            &ActuationScope::unscoped(),
            &unknown
        ),
        Decision::Propose(_)
    ));
}

#[test]
fn action_bar_is_asymmetric_live_acts_latent_proposes() {
    let armed = EnabledActions::none().enable(ProposedAction::DenyNetworkPath);
    let net = |justifications: Vec<Justification>| Mitigation {
        justifications,
        ..mitigation(
            "workload/app/Pod/web",
            "reaches/Tcp/5432",
            "workload/ext/Pod/attacker",
            ProposedAction::DenyNetworkPath,
        )
    };

    // Live evidence (corroborated + adjudicated), no KEV foothold ⇒ auto-apply.
    assert_eq!(
        decide(
            &net(vec![justification(false, true, true)]),
            &armed,
            &ActuationScope::unscoped(),
            &BlastRadius::default()
        ),
        Decision::AutoApply
    );
    // Latent foothold (KEV, exposed) but no live activity ⇒ propose, not act.
    assert!(matches!(
        decide(
            &net(vec![justification(true, false, true)]),
            &armed,
            &ActuationScope::unscoped(),
            &BlastRadius::default()
        ),
        Decision::Propose(_)
    ));
    // Live but adjudicator-vetoed ⇒ propose.
    assert!(matches!(
        decide(
            &net(vec![justification(false, true, false)]),
            &armed,
            &ActuationScope::unscoped(),
            &BlastRadius::default()
        ),
        Decision::Propose(_)
    ));
}

#[test]
fn decide_forbids_subtractive_rbac() {
    // RBAC revocation is subtractive — never live-actuatable, even enabled.
    let m = mitigation(
        "identity/ops/ops-sa",
        "can-do/create/pods",
        "capability/cluster/create/pods",
        ProposedAction::RevokeRbacGrant,
    );
    let enabled = EnabledActions::none().enable(ProposedAction::RevokeRbacGrant);
    assert!(matches!(
        decide(
            &m,
            &enabled,
            &ActuationScope::unscoped(),
            &BlastRadius::default()
        ),
        Decision::Forbidden(_)
    ));
}

#[test]
fn decide_network_needs_corroboration_and_active_to_auto_apply() {
    let net = || Mitigation {
        justifications: vec![corroborated()],
        ..mitigation(
            "workload/app/Pod/web",
            "reaches/Tcp/5432",
            "workload/ext/Pod/attacker",
            ProposedAction::DenyNetworkPath,
        )
    };
    let enabled = EnabledActions::none().enable(ProposedAction::DenyNetworkPath);

    // Corroborated + enabled + no live collateral ⇒ auto-apply.
    assert_eq!(
        decide(
            &net(),
            &enabled,
            &ActuationScope::unscoped(),
            &BlastRadius::default()
        ),
        Decision::AutoApply
    );
    // Enabled but the justifying chain isn't corroborated ⇒ propose.
    let uncorroborated = mitigation(
        "workload/app/Pod/web",
        "reaches/Tcp/5432",
        "workload/ext/Pod/attacker",
        ProposedAction::DenyNetworkPath,
    );
    assert!(matches!(
        decide(
            &uncorroborated,
            &enabled,
            &ActuationScope::unscoped(),
            &BlastRadius::default()
        ),
        Decision::Propose(_)
    ));
    // Corroborated but not enabled ⇒ propose.
    assert!(matches!(
        decide(
            &net(),
            &EnabledActions::none(),
            &ActuationScope::unscoped(),
            &BlastRadius::default()
        ),
        Decision::Propose(_)
    ));
}

#[test]
fn decide_scopes_auto_apply_to_the_namespace_allowlist() {
    // JEF-104: an enabled + corroborated + collateral-free network cut auto-applies
    // only when its namespaces are in PROTECTOR_ENGINE_ENFORCE_NAMESPACES. Cut runs
    // app -> data (both workload endpoints carry a namespace).
    let net = || Mitigation {
        justifications: vec![corroborated()],
        ..mitigation(
            "workload/app/Pod/web",
            "reaches/Tcp/5432",
            "workload/data/Pod/db",
            ProposedAction::DenyNetworkPath,
        )
    };
    let enabled = EnabledActions::none().enable(ProposedAction::DenyNetworkPath);

    // Empty allowlist (the default) ⇒ unscoped, every namespace eligible ⇒ apply.
    assert_eq!(
        decide(
            &net(),
            &enabled,
            &ActuationScope::unscoped(),
            &BlastRadius::default()
        ),
        Decision::AutoApply
    );

    // Both endpoints' namespaces listed ⇒ in scope ⇒ apply.
    let in_scope = ActuationScope::enforce_namespaces(["app".to_string(), "data".to_string()]);
    assert_eq!(
        decide(&net(), &enabled, &in_scope, &BlastRadius::default()),
        Decision::AutoApply
    );

    // Allowlist covers only the source, not the target ⇒ out of scope ⇒ propose
    // (the deny would write an ANP selecting the unlisted `data` namespace).
    let partial = ActuationScope::enforce_namespaces(["app".to_string()]);
    assert!(matches!(
        decide(&net(), &enabled, &partial, &BlastRadius::default()),
        Decision::Propose(_)
    ));

    // A disjoint allowlist ⇒ out of scope ⇒ propose.
    let other = ActuationScope::enforce_namespaces(["other".to_string()]);
    assert!(matches!(
        decide(&net(), &enabled, &other, &BlastRadius::default()),
        Decision::Propose(_)
    ));
}

#[test]
fn actuation_scope_is_unscoped_when_allowlist_empty() {
    // The gate is purely additive: with no allowlist, every cut is in scope.
    let m = mitigation(
        "workload/app/Pod/web",
        "reaches/Tcp/5432",
        "workload/data/Pod/db",
        ProposedAction::DenyNetworkPath,
    );
    assert!(ActuationScope::unscoped().in_scope(&m));
    assert!(
        ActuationScope::enforce_namespaces(["app".to_string(), "data".to_string()]).in_scope(&m)
    );
    assert!(!ActuationScope::enforce_namespaces(["app".to_string()]).in_scope(&m));
}

#[test]
fn actuation_scope_confines_by_pod_label_like_the_webhook() {
    // ADR-0021: labels behave like namespaces. A label-only scope confines the cut to
    // endpoints carrying the label — both endpoints must match, so a scope leak can never
    // widen actuation beyond enforceScope.
    let mut m = mitigation(
        "workload/app/Pod/web",
        "reaches/Tcp/5432",
        "workload/data/Pod/db",
        ProposedAction::DenyNetworkPath,
    );
    m.cut.from_labels =
        std::collections::BTreeMap::from([("tier".to_string(), "prod".to_string())]);
    m.cut.to_labels = std::collections::BTreeMap::from([("tier".to_string(), "prod".to_string())]);

    // Both endpoints carry tier=prod ⇒ in scope.
    let prod = ActuationScope::new(
        std::collections::HashSet::new(),
        vec![("tier".to_string(), "prod".to_string())],
    );
    assert!(prod.in_scope(&m), "both endpoints labelled ⇒ in scope");

    // A different label value ⇒ neither endpoint matches ⇒ out of scope.
    let staging = ActuationScope::new(
        std::collections::HashSet::new(),
        vec![("tier".to_string(), "staging".to_string())],
    );
    assert!(
        !staging.in_scope(&m),
        "no endpoint matches ⇒ held as a proposal"
    );

    // Only the source carries the label (target does not) ⇒ out of scope: the cut would
    // write an object selecting the unlabelled target's namespace.
    m.cut.to_labels.clear();
    assert!(
        !prod.in_scope(&m),
        "every workload endpoint must be in scope, source-only match is not enough"
    );

    // A namespace-OR-label scope: the target is reachable via its namespace even without
    // the label.
    let mixed = ActuationScope::new(
        ["data".to_string()].into_iter().collect(),
        vec![("tier".to_string(), "prod".to_string())],
    );
    assert!(
        mixed.in_scope(&m),
        "source matches by label, target matches by namespace ⇒ in scope"
    );
}

#[test]
fn decide_auto_applies_a_model_promoted_chain() {
    // ADR-0011: a model-promoted justification (no runtime corroboration) is
    // auto-actionable just like a live one, gated by the same bounded action.
    let promoted_net = Mitigation {
        justifications: vec![promoted()],
        ..mitigation(
            "workload/app/Pod/web",
            "reaches/Tcp/5432",
            "workload/ext/Pod/attacker",
            ProposedAction::DenyNetworkPath,
        )
    };
    let enabled = EnabledActions::none().enable(ProposedAction::DenyNetworkPath);
    assert_eq!(
        decide(
            &promoted_net,
            &enabled,
            &ActuationScope::unscoped(),
            &BlastRadius::default()
        ),
        Decision::AutoApply
    );
    // The `judgement` opt-in toggles promotion (consumed in the engine loop), not
    // the cut's action class.
    assert!(EnabledActions::from_names(["judgement"]).judgement_enabled());
    assert!(!EnabledActions::from_names(["network"]).judgement_enabled());
}

#[test]
fn verify_holds_when_prediction_holds_and_reverts_otherwise() {
    let predicted = vec!["workload/app/Pod/api".to_string()];
    assert_eq!(
        verify(
            &predicted,
            &health(&[("workload/app/Pod/api", Health::Alive)])
        ),
        Verdict::Hold
    );
    assert!(matches!(
        verify(
            &predicted,
            &health(&[("workload/app/Pod/api", Health::Halted)])
        ),
        Verdict::Revert(_)
    ));
}

#[test]
fn render_deny_builds_namespace_scoped_anp_for_network_cuts_only() {
    let net = mitigation(
        "workload/app/Pod/web",
        "reaches/Tcp/5432",
        "workload/data/Pod/db",
        ProposedAction::DenyNetworkPath,
    );
    let anp = render_deny(&net).expect("network cut renders an ANP");
    assert_eq!(anp["kind"], "AdminNetworkPolicy");
    assert_eq!(
        anp["metadata"]["labels"]["app.kubernetes.io/managed-by"],
        "protector"
    );
    assert_eq!(anp["spec"]["ingress"][0]["action"], "Deny");
    // Subject = target namespace; deny from = source namespace.
    assert_eq!(
        anp["spec"]["subject"]["namespaces"]["matchLabels"]["kubernetes.io/metadata.name"],
        "data"
    );
    assert_eq!(
        anp["spec"]["ingress"][0]["from"][0]["namespaces"]["matchLabels"]["kubernetes.io/metadata.name"],
        "app"
    );

    // A non-network (RBAC) cut isn't additive-live — renders nothing.
    let rbac = mitigation(
        "identity/ops/ops-sa",
        "can-do/create/pods",
        "capability/cluster/create/pods",
        ProposedAction::RevokeRbacGrant,
    );
    assert!(render_deny(&rbac).is_none());
}

#[test]
fn render_deny_uses_pod_selector_when_labels_are_known() {
    let mut net = mitigation(
        "workload/app/Pod/web",
        "reaches/Tcp/5432",
        "workload/data/Pod/db",
        ProposedAction::DenyNetworkPath,
    );
    net.cut.from_labels =
        std::collections::BTreeMap::from([("role".to_string(), "web".to_string())]);
    net.cut.to_labels = std::collections::BTreeMap::from([("role".to_string(), "db".to_string())]);

    let anp = render_deny(&net).expect("renders");
    // Subject narrows to the target pod by label, within its namespace.
    let subject = &anp["spec"]["subject"]["pods"];
    assert_eq!(
        subject["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
        "data"
    );
    assert_eq!(subject["podSelector"]["matchLabels"]["role"], "db");
    // Deny-from narrows to the source pod by label.
    let from = &anp["spec"]["ingress"][0]["from"][0]["pods"];
    assert_eq!(from["podSelector"]["matchLabels"]["role"], "web");
}

#[test]
fn render_isolation_builds_deny_all_networkpolicy_on_the_source() {
    let mut net = mitigation(
        "workload/app/Pod/web",
        "reaches/Tcp/5432",
        "workload/data/Pod/db",
        ProposedAction::DenyNetworkPath,
    );
    net.cut.from_labels =
        std::collections::BTreeMap::from([("role".to_string(), "web".to_string())]);

    let np = render_isolation(&net).expect("renders");
    assert_eq!(np["kind"], "NetworkPolicy");
    // In the *source's* namespace, selecting the source pod.
    assert_eq!(np["metadata"]["namespace"], "app");
    assert_eq!(np["spec"]["podSelector"]["matchLabels"]["role"], "web");
    // Deny-all: both policy types, no rules.
    assert_eq!(np["spec"]["policyTypes"][0], "Ingress");
    assert_eq!(np["spec"]["policyTypes"][1], "Egress");
    assert!(np["spec"]["ingress"].is_null());
    assert!(np["spec"]["egress"].is_null());

    // Without source labels we decline rather than isolate the whole namespace.
    let mut no_labels = net.clone();
    no_labels.cut.from_labels.clear();
    assert!(render_isolation(&no_labels).is_none());
}

#[test]
fn render_isolation_quarantines_the_entry_for_quarantine_entry_action() {
    // A QuarantineEntry mitigation's cut is a self-reference on the entry, carrying the
    // entry's labels — so the isolation renderer selects ONLY the entry pod, full
    // default-deny, and nothing deeper (ADR-0010). It is not gated on DenyNetworkPath.
    let mut quarantine = mitigation(
        "workload/edge/Pod/argocd-server",
        "quarantine-entry",
        "workload/edge/Pod/argocd-server",
        ProposedAction::QuarantineEntry,
    );
    quarantine.cut.from_labels =
        std::collections::BTreeMap::from([("app".to_string(), "argocd-server".to_string())]);

    let np = render_isolation(&quarantine).expect("quarantine renders an isolation NetworkPolicy");
    assert_eq!(np["kind"], "NetworkPolicy");
    // In the entry's namespace, selecting ONLY the entry pod by label.
    assert_eq!(np["metadata"]["namespace"], "edge");
    assert_eq!(
        np["spec"]["podSelector"]["matchLabels"]["app"],
        "argocd-server"
    );
    // Full default-deny: both policy types, no ingress/egress rules.
    assert_eq!(np["spec"]["policyTypes"][0], "Ingress");
    assert_eq!(np["spec"]["policyTypes"][1], "Egress");
    assert!(np["spec"]["ingress"].is_null());
    assert!(np["spec"]["egress"].is_null());

    // QuarantineEntry is an additive, reversible network deny — auto-actuatable.
    assert!(ProposedAction::QuarantineEntry.is_additive_live());
    assert!(ProposedAction::QuarantineEntry.is_reversible());
}

#[test]
fn from_names_arms_only_network_and_ignores_non_actuatable_classes() {
    // Only `network` is live-actuatable, so only it arms. The subtractive classes
    // (rbac/mount/identity), irreversible `escape`, and unknown names are ignored —
    // the engine still proposes those cuts, they just can't be enabled for actuation.
    let policy = EnabledActions::from_names(["network", "rbac", "mount", "escape", "bogus"]);
    assert!(policy.is_enabled(ProposedAction::DenyNetworkPath));
    // The `network` class arms both network denies — the surgical edge-cut and the
    // default-deny entry quarantine (ADR-0010), the same additive/reversible mechanism.
    assert!(policy.is_enabled(ProposedAction::QuarantineEntry));
    assert!(!policy.is_enabled(ProposedAction::RevokeRbacGrant));
    assert!(!policy.is_enabled(ProposedAction::RemoveSecretMount));
    assert!(!policy.is_enabled(ProposedAction::RebindIdentity));
    assert!(!policy.is_enabled(ProposedAction::RemoveEscapePrimitive));
}

#[test]
fn lifecycle_reverts_on_health_divergence_and_retirement_else_holds() {
    let rbac = mitigation(
        "identity/ops/ops-sa",
        "can-do/create/pods",
        "capability/cluster/create/pods",
        ProposedAction::RevokeRbacGrant,
    );
    let net = mitigation(
        "workload/app/Pod/web",
        "reaches/Tcp/5432",
        "workload/app/Pod/db",
        ProposedAction::DenyNetworkPath,
    );

    // rbac promised api stays alive; net promised nothing live was affected.
    let mut log = ActionLog::new();
    log.record(rbac.clone(), vec!["workload/app/Pod/api".to_string()]);
    log.record(net.clone(), vec![]);
    assert_eq!(log.active_count(), 2);
    assert!(log.is_active(&rbac));

    // api went down (divergence) ⇒ rbac reverts; net's chain is unjustified
    // (empty set) ⇒ net reverts.
    let reversions = log.reconcile(
        &health(&[("workload/app/Pod/api", Health::Halted)]),
        &HashSet::new(),
    );
    assert_eq!(reversions.len(), 2);
    assert_eq!(log.active_count(), 0);

    // A still-justified action whose baseline stayed alive is held.
    let mut log = ActionLog::new();
    log.record(rbac.clone(), vec!["workload/app/Pod/api".to_string()]);
    let justified = HashSet::from([rbac.cut_signature()]);
    assert!(
        log.reconcile(
            &health(&[("workload/app/Pod/api", Health::Alive)]),
            &justified
        )
        .is_empty()
    );
    assert_eq!(log.active_count(), 1);
}
