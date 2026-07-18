//! Tests for the readiness aggregation (JEF-160) and the collapsed runtime-corroboration row
//! (JEF-308). Extracted to keep `readiness.rs` under the 1,000-line cap (CLAUDE.md).

use super::super::agent_liveness::{
    BlindReason, CoverageAlert, CoverageState, NodeCoverage, NodeState, RuntimeCoverage,
};
use super::*;

fn covered_config() -> ReadinessConfig {
    ReadinessConfig {
        model_attached: true,
        kev_count: 5,
        epss_count: 5,
        journal_durable: true,
        armed: false,
        // A fresh trust root, no fleet-wide unverifiable spike ⇒ the TUF row is Present.
        tuf_cache_age_secs: Some(60),
        unverifiable_spike: false,
        // No images stuck checking ⇒ the signature-verification row is Present.
        checking_images: 0,
    }
}

/// An empty runtime-coverage snapshot (no expected agent nodes) — the default for tests that
/// aren't exercising the per-node liveness path.
fn no_runtime() -> RuntimeCoverage {
    RuntimeCoverage::default()
}

/// A coverage snapshot from `(node, state)` pairs.
fn coverage(nodes: &[(&str, NodeState)]) -> RuntimeCoverage {
    RuntimeCoverage {
        nodes: nodes
            .iter()
            .map(|(n, s)| NodeCoverage {
                node: (*n).to_string(),
                state: *s,
            })
            .collect(),
    }
}

/// The runtime-corroboration row from a readiness snapshot.
fn runtime_row(readiness: &Readiness) -> &ReadinessRow {
    readiness
        .inputs
        .iter()
        .find(|r| r.id == "runtime-corroboration")
        .expect("a runtime-corroboration row is present")
}

#[test]
fn fully_covered_model_judging_has_no_unmet_inputs() {
    // One healthy expected node → runtime corroboration is Present.
    let cov = coverage(&[("node-a", NodeState::Healthy { signals: 2 })]);
    let readiness = derive_readiness(
        &covered_config(),
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &cov,
    );
    assert!(readiness.model_judging);
    assert!(readiness.model_attached());
    assert!(!readiness.has_unmet());
    assert_eq!(readiness.unmet_count(), 0);
    assert!(!readiness.warming_up);
}

#[test]
fn coverage_stall_escalates_the_runtime_row_to_stalled() {
    // JEF-421: a covering fleet whose stall edge fired escalates the runtime row to `Stalled`
    // (distinct from the per-pass Absent/Degraded), and the detail names the last-observed time.
    let cov = coverage(&[("node-a", NodeState::Healthy { signals: 2 })]);
    let stalled = CoverageState::Stalled(CoverageAlert {
        feed_label: "Runtime".into(),
        last_observation: Some("2m ago".into()),
        message: "runtime corroboration stalled — all 1 sensor node went dark".into(),
    });
    let readiness = derive_readiness(
        &covered_config(),
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &cov,
    )
    .with_coverage_stall(&stalled);
    let row = runtime_row(&readiness);
    assert_eq!(
        row.state,
        InputState::Stalled,
        "the row escalates to stalled"
    );
    assert!(row.detail.contains("STALLED"));
    assert!(
        row.detail.contains("2m ago"),
        "the escalated detail names the last-observed time"
    );
    // A stalled input is unmet (never reads as covered/present).
    assert!(readiness.has_unmet());
}

#[test]
fn coverage_absent_does_not_escalate_the_runtime_row() {
    // JEF-421: the honest known-absence (Absent) never manufactures a stall — the row keeps its
    // per-pass state, unchanged by the overlay.
    let cov = coverage(&[("node-a", NodeState::Healthy { signals: 2 })]);
    let before = derive_readiness(
        &covered_config(),
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &cov,
    );
    let before_state = runtime_row(&before).state;
    let after = derive_readiness(
        &covered_config(),
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &cov,
    )
    .with_coverage_stall(&CoverageState::Absent);
    assert_eq!(
        runtime_row(&after).state,
        before_state,
        "an Absent register leaves the row untouched"
    );
    assert_ne!(runtime_row(&after).state, InputState::Stalled);
}

#[test]
fn a_timed_out_model_is_degraded_not_judging() {
    let readiness = derive_readiness(
        &covered_config(),
        ModelHealth::Timeout,
        Some(SystemTime::now()),
        &no_runtime(),
    );
    assert!(!readiness.model_judging);
    // The model is still CONFIGURED — attached, just not answering.
    assert!(readiness.model_attached());
    // The model row is degraded and the (quiet) behavioral feeds are absent ⇒ unmet.
    assert!(readiness.has_unmet());
}

/// The TUF-root row from a readiness snapshot.
fn tuf(readiness: &Readiness) -> &ReadinessRow {
    readiness
        .inputs
        .iter()
        .find(|r| r.id == "tuf-root")
        .expect("a TUF-root row is present")
}

#[test]
fn a_fresh_trust_root_reads_present() {
    let readiness = derive_readiness(
        &covered_config(),
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &no_runtime(),
    );
    assert_eq!(tuf(&readiness).state, InputState::Present);
    assert!(tuf(&readiness).detail.contains("fresh"));
}

#[test]
fn a_stale_trust_root_is_degraded_and_surfaced_non_green() {
    let mut config = covered_config();
    config.tuf_cache_age_secs = Some(TUF_STALE_AFTER_SECS + 1);
    let readiness = derive_readiness(
        &config,
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &no_runtime(),
    );
    assert_eq!(tuf(&readiness).state, InputState::Degraded);
    assert!(tuf(&readiness).detail.contains("stale"));
    // Non-green: a stale trust root counts as an unmet input.
    assert!(readiness.has_unmet());
}

#[test]
fn a_never_fetched_trust_root_reads_absent() {
    let mut config = covered_config();
    config.tuf_cache_age_secs = None;
    let readiness = derive_readiness(
        &config,
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &no_runtime(),
    );
    assert_eq!(tuf(&readiness).state, InputState::Absent);
}

#[test]
fn a_fleet_wide_unverifiable_spike_is_surfaced_even_on_a_fresh_root() {
    let mut config = covered_config();
    config.tuf_cache_age_secs = Some(60); // fresh mtime …
    config.unverifiable_spike = true; // … but a mass unverifiable spike this pass
    let readiness = derive_readiness(
        &config,
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &no_runtime(),
    );
    assert_eq!(tuf(&readiness).state, InputState::Degraded);
    assert!(tuf(&readiness).detail.contains("spike"));
    assert!(readiness.has_unmet());
}

// --- JEF-326: the signature-verification reachability row (perpetual "checking") ---

/// The signature-verification row from a readiness snapshot.
fn verify(readiness: &Readiness) -> &ReadinessRow {
    readiness
        .inputs
        .iter()
        .find(|r| r.id == "signature-verification")
        .expect("a signature-verification row is present")
}

#[test]
fn no_images_checking_reads_present() {
    let readiness = derive_readiness(
        &covered_config(),
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &no_runtime(),
    );
    assert_eq!(verify(&readiness).state, InputState::Present);
    assert!(verify(&readiness).detail.contains("no images stuck"));
}

#[test]
fn images_stuck_checking_are_degraded_and_surfaced_non_green() {
    // The JEF-326 bug made visible: a perpetual-checking backlog reads Degraded (non-green),
    // names the count, and points at the timeout knob — never a silent green.
    let mut config = covered_config();
    config.checking_images = 5;
    let readiness = derive_readiness(
        &config,
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &no_runtime(),
    );
    assert_eq!(verify(&readiness).state, InputState::Degraded);
    assert!(verify(&readiness).detail.contains("5 images stuck"));
    assert!(
        verify(&readiness)
            .detail
            .contains("PROTECTOR_VERIFY_TIMEOUT")
    );
    // Non-green: a stuck signing-verification backlog counts as an unmet input.
    assert!(readiness.has_unmet());
}

#[test]
fn an_unconfigured_model_reads_absent_and_warming_before_first_pass() {
    let readiness = derive_readiness(
        &ReadinessConfig::default(),
        ModelHealth::Unknown,
        None,
        &no_runtime(),
    );
    assert!(!readiness.model_attached());
    assert!(!readiness.model_judging);
    assert!(readiness.warming_up);
}

// --- JEF-308: the collapsed runtime-corroboration row + honesty ladder ---

/// There is exactly ONE runtime row — the collapsed agent-sourced runtime-corroboration row.
#[test]
fn runtime_corroboration_is_a_single_agent_sourced_row() {
    let readiness = derive_readiness(
        &covered_config(),
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &no_runtime(),
    );
    assert!(readiness.inputs.iter().all(|r| r.id != "ebpf-agent"));
    assert_eq!(
        readiness
            .inputs
            .iter()
            .filter(|r| r.id == "runtime-corroboration")
            .count(),
        1
    );
}

#[test]
fn all_nodes_healthy_reads_present() {
    let cov = coverage(&[
        ("node-a", NodeState::Healthy { signals: 3 }),
        ("node-b", NodeState::Healthy { signals: 0 }), // quiet — still healthy
    ]);
    let readiness = derive_readiness(
        &covered_config(),
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &cov,
    );
    let row = runtime_row(&readiness);
    assert_eq!(row.state, InputState::Present);
    assert!(row.detail.starts_with("healthy"));
    assert_eq!(row.nodes.len(), 2);
    // The quiet node is spelled out as quiet, not absent.
    let quiet = row.nodes.iter().find(|n| n.node == "node-b").unwrap();
    assert_eq!(quiet.state, NodeCoverageState::Healthy);
    assert!(quiet.detail.contains("quiet"));
}

#[test]
fn a_blind_node_degrades_the_row_and_is_named() {
    let cov = coverage(&[
        ("node-a", NodeState::Healthy { signals: 1 }),
        (
            "node-b",
            NodeState::Blind {
                reason: BlindReason::NotReporting,
            },
        ),
    ]);
    let readiness = derive_readiness(
        &covered_config(),
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &cov,
    );
    let row = runtime_row(&readiness);
    assert_eq!(row.state, InputState::Degraded);
    assert!(row.detail.contains("node-b"), "the blind node is named");
    assert!(readiness.has_unmet());
    let b = row.nodes.iter().find(|n| n.node == "node-b").unwrap();
    assert_eq!(b.state, NodeCoverageState::Blind);
}

#[test]
fn probes_failed_node_reads_blind_despite_reporting() {
    let cov = coverage(&[(
        "node-a",
        NodeState::Blind {
            reason: BlindReason::ProbesFailed,
        },
    )]);
    let readiness = derive_readiness(
        &covered_config(),
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &cov,
    );
    let row = runtime_row(&readiness);
    // The single EXPECTED node is dark ⇒ wholly BLIND (distinct from Absent/never-enabled — it
    // forbids the green all-clear).
    assert_eq!(row.state, InputState::Blind);
    assert!(row.detail.contains("BLIND"));
    let a = row.nodes.iter().find(|n| n.node == "node-a").unwrap();
    assert!(a.detail.contains("probes failed"));
}

#[test]
fn no_sensor_at_all_reads_blind_never_reassuring() {
    // No expected agent nodes → the row is BLIND, and its detail says absence of a signal is not
    // evidence of safety (the honesty invariant).
    let readiness = derive_readiness(
        &covered_config(),
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &no_runtime(),
    );
    let row = runtime_row(&readiness);
    assert_eq!(row.state, InputState::Absent);
    assert!(row.detail.contains("not evidence of safety"));
    assert!(readiness.has_unmet());
}

#[test]
fn a_partial_probe_node_is_degraded_not_blind() {
    let cov = coverage(&[(
        "node-a",
        NodeState::DegradedProbes {
            loaded: 4,
            total: 6,
        },
    )]);
    let readiness = derive_readiness(
        &covered_config(),
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &cov,
    );
    let row = runtime_row(&readiness);
    assert_eq!(row.state, InputState::Degraded);
    assert!(row.detail.contains("partial"));
    let a = &row.nodes[0];
    assert_eq!(a.state, NodeCoverageState::Degraded);
    assert!(a.detail.contains("4/6"));
}

#[test]
fn an_out_of_scope_reporter_does_not_push_the_row_off_green() {
    // An out-of-scope reporter (agent seen where it isn't scheduled) is not blind and doesn't
    // count as an expected node — one healthy expected node keeps the row Present.
    let cov = coverage(&[
        ("node-a", NodeState::Healthy { signals: 1 }),
        ("node-x", NodeState::OutOfScope),
    ]);
    let readiness = derive_readiness(
        &covered_config(),
        ModelHealth::Ok,
        Some(SystemTime::now()),
        &cov,
    );
    let row = runtime_row(&readiness);
    assert_eq!(row.state, InputState::Present);
    let x = row.nodes.iter().find(|n| n.node == "node-x").unwrap();
    assert_eq!(x.state, NodeCoverageState::OutOfScope);
}
