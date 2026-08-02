use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use super::*;
use crate::engine::graph::NodeKey;
use crate::engine::observe::adapter::{build_graph, default_adapters};
use crate::engine::observe::health::HealthReport;
use crate::engine::observe::{ImageVulnerabilities, Snapshot};
use crate::engine::reason::adjudicate::incident::{ChosenCut, build_menu};
use crate::engine::reason::proof::{Link, prove};
use crate::engine::respond::ProposedAction;

/// A multi-hop incident: an internet-exposed `web` entry reaches a `payments` pivot pod
/// (critical CVE, no evidence of its own besides reachability + the CVE) which in turn reaches
/// `ledger` (a KEV CVE, mounts the objective secret) — the same shape a real internet-facing
/// pivot-then-objective compromise takes: the front door is popped, then the attacker walks one
/// hop laterally to the workload actually holding the crown-jewel credential. Both `payments` and
/// `ledger` are independently compromisable and network-reachable from the internet foothold, so
/// BOTH qualify as `RemotelyExploitable` quarantine candidates on top of the
/// entry's own surgical edge-cut — the downstream (not just entry) divergence surface this
/// fixture exists to exercise.
fn multi_hop_incident_snapshot() -> Snapshot {
    let pod = |name: &str, role: &str, image: &str, secret: Option<&str>| {
        let env = secret
            .map(|s| json!([{"secretRef": {"name": s}}]))
            .unwrap_or(json!([]));
        serde_json::from_value(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": "shop", "labels": {"role": role}},
            "spec": {"containers": [{"name": "c", "image": image, "envFrom": env}]}
        }))
        .unwrap()
    };
    let ingress = |name: &str, to_role: &str, from_role: &str| {
        serde_json::from_value(json!({
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": "shop"},
            "spec": {
                "podSelector": {"matchLabels": {"role": to_role}},
                "policyTypes": ["Ingress"],
                "ingress": [{"from": [{"podSelector": {"matchLabels": {"role": from_role}}}]}]
            }
        }))
        .unwrap()
    };
    let lb = serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "web-lb", "namespace": "shop"},
        "spec": {"type": "LoadBalancer", "selector": {"role": "web"}}
    }))
    .unwrap();
    let crit = |id: &str, kev: bool| crate::engine::graph::Vulnerability {
        id: id.into(),
        severity: crate::engine::graph::Severity::Critical,
        exploited_in_wild: kev,
        epss: None,
        sources: vec![crate::engine::graph::Provenance::new(
            "trivy",
            std::time::SystemTime::UNIX_EPOCH,
        )],
        ..Default::default()
    };
    Snapshot {
        pods: vec![
            pod("web", "web", "web:1", None),
            pod("payments", "payments", "payments:1", None),
            pod("ledger", "ledger", "ledger:1", Some("ledger-creds")),
        ],
        network_policies: vec![
            ingress("payments-ingress", "payments", "web"),
            ingress("ledger-ingress", "ledger", "payments"),
        ],
        services: vec![lb],
        image_vulns: vec![
            ImageVulnerabilities {
                image: "payments:1".into(),
                vulnerabilities: vec![crit("CVE-2026-2001", false)],
            },
            ImageVulnerabilities {
                image: "ledger:1".into(),
                vulnerabilities: vec![crit("CVE-2026-2002", true)],
            },
        ],
        ..Default::default()
    }
}

/// The single (entry, objective) chain the fixture proves: `web` → `ledger-creds`.
fn multi_hop_chain(chains: &[ProvenChain]) -> &ProvenChain {
    chains
        .iter()
        .find(|c| c.entry.0 == "workload/shop/Pod/web")
        .expect("web → ledger multi-hop chain")
}

/// A decisive `Attack` decision naming `nodes`, resolved through the REAL menu builder — the
/// same resolver [`compute`]'s deterministic-target computation reuses — so a test's "model
/// chose X" is exactly what the model *could* have chosen, not a hand-rolled shortcut.
fn decisive_attack(
    chain: &ProvenChain,
    graph: &crate::engine::graph::SecurityGraph,
    nodes: &[&str],
) -> BTreeMap<String, IncidentDecision> {
    let menu = build_menu(chain, graph, &HealthReport::default(), &BTreeSet::new());
    let cuts = nodes
        .iter()
        .map(|n| {
            let key = NodeKey((*n).to_string());
            menu.resolve(&key)
                .unwrap_or_else(|| panic!("{n} is selectable on the menu"))
        })
        .collect();
    let mut decisions = BTreeMap::new();
    decisions.insert(
        chain.entry.0.clone(),
        IncidentDecision {
            assessment: Assessment::Attack,
            reason: "test-supplied decision".to_string(),
            cuts,
        },
    );
    decisions
}

fn decisive_no_attack(chain: &ProvenChain) -> BTreeMap<String, IncidentDecision> {
    let mut decisions = BTreeMap::new();
    decisions.insert(
        chain.entry.0.clone(),
        IncidentDecision {
            assessment: Assessment::NoAttack,
            reason: "test-supplied clear".to_string(),
            cuts: Vec::new(),
        },
    );
    decisions
}

fn fresh_uncertain(chain: &ProvenChain) -> BTreeMap<String, IncidentDecision> {
    let mut decisions = BTreeMap::new();
    decisions.insert(
        chain.entry.0.clone(),
        IncidentDecision::uncertain("timeout"),
    );
    decisions
}

/// A synthetic [`ChosenCut`] naming an arbitrary node key — used ONLY to exercise the
/// over-cut/mixed branches of [`classify`] in isolation. `compute` itself never grounds a cut
/// against the menu (that guarding is the parser/guards' job upstream, ADR-0034 D3/D5); the
/// comparator's contract is purely "compare the sets it is given."
fn synthetic_cut(node: &str) -> ChosenCut {
    let key = NodeKey(node.to_string());
    ChosenCut {
        node: key.clone(),
        action: ProposedAction::QuarantineWorkload,
        cut: Link {
            from: key.clone(),
            to: key,
            relation: "quarantine-workload".to_string(),
            technique: None,
            from_labels: Default::default(),
            to_labels: Default::default(),
        },
        cut_signature: format!("synthetic -[quarantine-workload]-> {node}"),
    }
}

#[test]
fn deterministic_target_set_covers_entry_and_every_downstream_node() {
    let graph = build_graph(&multi_hop_incident_snapshot(), &default_adapters());
    let chains = prove(&graph);
    let chain = multi_hop_chain(&chains);

    let targets = deterministic_targets(&[chain]);
    assert_eq!(
        targets,
        BTreeSet::from([
            "workload/shop/Pod/web".to_string(),
            "workload/shop/Pod/payments".to_string(),
            "workload/shop/Pod/ledger".to_string(),
        ]),
        "determinism proposes the entry's own ladder cut PLUS every remotely-exploitable \
         downstream node on the path — not just the entry"
    );
}

#[test]
fn model_matching_the_deterministic_set_agrees() {
    let graph = build_graph(&multi_hop_incident_snapshot(), &default_adapters());
    let chains = prove(&graph);
    let chain = multi_hop_chain(&chains);
    let decisions = decisive_attack(
        chain,
        &graph,
        &[
            "workload/shop/Pod/web",
            "workload/shop/Pod/payments",
            "workload/shop/Pod/ledger",
        ],
    );

    let records = compute(&chains, &decisions);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].class, DivergenceClass::Agree);
    assert_eq!(records[0].deterministic_cuts.len(), 3);
    assert_eq!(records[0].model_cuts.len(), 3);
}

#[test]
fn model_naming_only_the_entry_under_cuts_the_downstream_nodes() {
    let graph = build_graph(&multi_hop_incident_snapshot(), &default_adapters());
    let chains = prove(&graph);
    let chain = multi_hop_chain(&chains);
    let decisions = decisive_attack(chain, &graph, &["workload/shop/Pod/web"]);

    let records = compute(&chains, &decisions);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].class,
        DivergenceClass::ModelUnderCut,
        "the model's {{web}} is a strict subset of determinism's {{web, payments, ledger}}"
    );
}

#[test]
fn a_decisive_no_attack_under_cuts_a_containable_chain() {
    let graph = build_graph(&multi_hop_incident_snapshot(), &default_adapters());
    let chains = prove(&graph);
    let chain = multi_hop_chain(&chains);
    let decisions = decisive_no_attack(chain);

    let records = compute(&chains, &decisions);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].class, DivergenceClass::ModelUnderCut);
    assert!(records[0].model_cuts.is_empty());
}

#[test]
fn model_naming_an_extra_node_over_cuts() {
    let graph = build_graph(&multi_hop_incident_snapshot(), &default_adapters());
    let chains = prove(&graph);
    let chain = multi_hop_chain(&chains);
    let mut decisions = decisive_attack(
        chain,
        &graph,
        &[
            "workload/shop/Pod/web",
            "workload/shop/Pod/payments",
            "workload/shop/Pod/ledger",
        ],
    );
    decisions
        .get_mut(&chain.entry.0)
        .unwrap()
        .cuts
        .push(synthetic_cut("workload/shop/Pod/checkout"));

    let records = compute(&chains, &decisions);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].class, DivergenceClass::ModelOverCut);
}

#[test]
fn model_naming_a_disjoint_node_while_missing_others_is_mixed() {
    let graph = build_graph(&multi_hop_incident_snapshot(), &default_adapters());
    let chains = prove(&graph);
    let chain = multi_hop_chain(&chains);
    let mut decisions = decisive_attack(chain, &graph, &["workload/shop/Pod/web"]);
    decisions
        .get_mut(&chain.entry.0)
        .unwrap()
        .cuts
        .push(synthetic_cut("workload/shop/Pod/checkout"));

    let records = compute(&chains, &decisions);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].class,
        DivergenceClass::Mixed,
        "model named `checkout` (not in determinism's set) but omitted `payments`/`ledger` \
         (which are) — neither set contains the other"
    );
}

#[test]
fn a_fresh_uncertain_produces_no_divergence_record() {
    let graph = build_graph(&multi_hop_incident_snapshot(), &default_adapters());
    let chains = prove(&graph);
    let chain = multi_hop_chain(&chains);
    let decisions = fresh_uncertain(chain);

    assert!(
        compute(&chains, &decisions).is_empty(),
        "a fresh Uncertain carries no new information — never a divergence claim"
    );
}

#[test]
fn an_entry_with_no_decision_at_all_produces_no_divergence_record() {
    let graph = build_graph(&multi_hop_incident_snapshot(), &default_adapters());
    let chains = prove(&graph);

    assert!(compute(&chains, &BTreeMap::new()).is_empty());
}

#[test]
fn compute_is_pure_and_never_mutates_its_inputs() {
    // `compute` takes `&[ProvenChain]` and `&BTreeMap<..>` — the type system alone guarantees it
    // cannot mutate either. This test is the behavioral half: calling it twice on the same
    // inputs is idempotent (a view, never a gate — ADR-0016), and the inputs are usable
    // afterward exactly as before.
    let graph = build_graph(&multi_hop_incident_snapshot(), &default_adapters());
    let chains = prove(&graph);
    let chain = multi_hop_chain(&chains);
    let decisions = decisive_attack(chain, &graph, &["workload/shop/Pod/web"]);

    let first = compute(&chains, &decisions);
    let second = compute(&chains, &decisions);
    assert_eq!(first, second);
    // The inputs are unchanged — chains still proves the same entry/objective pair.
    assert_eq!(multi_hop_chain(&chains).entry.0, "workload/shop/Pod/web");
}
