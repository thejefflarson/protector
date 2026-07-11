//! Render-level tests for the Alerts view (JEF-323): the live "alarming-now" corroboration surface
//! and the findings-view "corroborated-now by …" annotation. These assert the honesty invariants
//! against the actual emitted HTML (ADR-0016) — an alert is EVIDENCE not a verdict, the empty state
//! is calm (not an alarm), a blind node forbids an "all clear", and untrusted signal text is
//! escaped. They drive the view_model + components directly (no HTTP, no engine), so they are fast
//! and pure. Kept in their own file so `tests.rs` stays under the 1,000-line cap (CLAUDE.md).

use std::time::SystemTime;

use crate::engine::graph::Behavior;
use crate::engine::reason::adjudicate::Verdict;
use crate::engine::state::{
    BlindReason, Delta, EntryEvidence, Finding, ModelHealth, NodeCoverage, NodeState,
    ReadinessConfig, RecencyInfo, RuntimeCoverage, derive_readiness,
};

use super::page;
use super::tests::{breach_finding, judging_readiness};
use super::view_model::{build_alerts_view, build_status_strip};

/// A readiness snapshot for a fully-covered, judging model with one BLIND node (JEF-308) — so the
/// quiet Alerts state must caveat "absence is not safety" rather than read all-clear.
fn blind_node_readiness() -> crate::engine::state::Readiness {
    let config = ReadinessConfig {
        model_attached: true,
        kev_count: 5,
        epss_count: 5,
        journal_durable: true,
        armed: false,
        tuf_cache_age_secs: Some(60),
        unverifiable_spike: false,
        checking_images: 0,
    };
    let coverage = RuntimeCoverage {
        nodes: vec![NodeCoverage {
            node: "node-blind".into(),
            state: NodeState::Blind {
                reason: BlindReason::NotReporting,
            },
        }],
    };
    derive_readiness(&config, ModelHealth::Ok, Some(SystemTime::now()), &coverage)
}

/// Attach a set of runtime behaviors + an age to a breach finding, so its entry carries live
/// signals the Alerts view projects from.
fn finding_with_signals(entry: &str, age_secs: u64, behaviors: Vec<Behavior>) -> Finding {
    let mut f = breach_finding(entry, Verdict::Confirmed);
    f.evidence = EntryEvidence {
        runtime: behaviors,
        ..EntryEvidence::default()
    };
    f.recency = Some(RecencyInfo {
        delta: Delta::Unchanged,
        age_secs: Some(age_secs),
    });
    f
}

fn strip_for(
    findings: &[Finding],
    readiness: &crate::engine::state::Readiness,
) -> super::view_model::props::StatusStripProps {
    build_status_strip(
        "prod".into(),
        findings,
        &[],
        readiness,
        Some(SystemTime::now()),
    )
}

// ---------------------------------------------------------------------------
// The Alerts tab renders alarming-now cards: signal + workload + recency + chain.
// ---------------------------------------------------------------------------

#[test]
fn alerts_tab_renders_signal_workload_recency_and_corroborated_chain() {
    // A drop-and-execute write (alarming) + a notable exec (bash) + a cloud-metadata contact —
    // the three example shapes the ticket names. All three should surface as alarming-now.
    let f = finding_with_signals(
        "workload/prod/web",
        120, // 2m
        vec![
            Behavior::FileWrite {
                path: "/usr/bin/dropper".into(),
            },
            Behavior::ProcessExec {
                path: "/bin/bash".into(),
            },
            Behavior::NetworkConnection {
                peer: "169.254.169.254:80".into(),
                internet: false,
            },
        ],
    );
    let readiness = judging_readiness();
    let findings = [f];
    let view = build_alerts_view(strip_for(&findings, &readiness), &findings, &readiness);
    let html = page::alerts_page(&view).into_string();

    // Each alarming-now signal shows, phrased as evidence.
    assert!(
        html.contains("drop-and-execute") || html.contains("/usr/bin/dropper"),
        "the alarming write surfaces"
    );
    assert!(html.contains("notable exec"), "the notable exec surfaces");
    assert!(
        html.contains("cloud instance-metadata") || html.contains("169.254.169.254"),
        "the cloud-metadata contact surfaces"
    );
    // The workload it was attributed to, its recency, and the chain it corroborates.
    assert!(html.contains("prod/web"), "the workload is named");
    assert!(html.contains("2m ago"), "the recency is shown");
    assert!(
        html.contains("corroborates"),
        "the corroborated objective/chain is named"
    );
    // It is EVIDENCE, not a verdict — never a loud breach conclusion.
    assert!(
        !html.contains("BREACH"),
        "an alert is corroboration, never a breach verdict (ADR-0016)"
    );
    assert!(
        html.contains("not a verdict"),
        "the surface labels itself as corroboration, not a verdict"
    );
}

// ---------------------------------------------------------------------------
// Untrusted signal text (a <script>/path/rule name) is ESCAPED (invariant #6).
// ---------------------------------------------------------------------------

#[test]
fn untrusted_signal_text_is_escaped_in_the_alerts_view() {
    let evil = "<script>alert('x')</script>";
    // An untrusted sensor RULE name and an untrusted WRITE path — both flow into the signal line.
    let f = finding_with_signals(
        "workload/prod/web",
        30,
        vec![
            Behavior::Alert {
                rule: evil.to_string(),
            },
            Behavior::FileWrite {
                path: format!("/etc/{evil}"),
            },
        ],
    );
    let readiness = judging_readiness();
    let view = build_alerts_view(strip_for(&[], &readiness), &[f], &readiness);
    let html = page::alerts_page(&view).into_string();

    assert!(
        !html.contains("<script>alert"),
        "a raw <script> in a rule/path must never reach the output"
    );
    assert!(
        html.contains("&lt;script&gt;"),
        "it is HTML-escaped instead"
    );
}

// ---------------------------------------------------------------------------
// Calm empty state — no alerts ⇒ reassuring copy, not an alarm/error.
// ---------------------------------------------------------------------------

#[test]
fn empty_alerts_is_a_calm_state_not_an_alarm() {
    let readiness = judging_readiness();
    let view = build_alerts_view(strip_for(&[], &readiness), &[], &readiness);
    let html = page::alerts_page(&view).into_string();

    assert!(
        html.contains("no alarming activity right now"),
        "the empty state is calm and reassuring"
    );
    // Not an alarm, not a breach frame.
    assert!(
        !html.contains("BREACH"),
        "a calm empty state never renders a breach frame"
    );
    // And it does not claim a false all-clear caveat when nothing is blind.
    assert!(
        !html.contains("not evidence of safety"),
        "with no blind node there is no blind caveat"
    );
}

// ---------------------------------------------------------------------------
// Blind-node honesty — a blind node ⇒ the "absence ≠ safety" caveat, not "all clear".
// ---------------------------------------------------------------------------

#[test]
fn quiet_alerts_with_a_blind_node_caveats_absence_is_not_safety() {
    let readiness = blind_node_readiness();
    let view = build_alerts_view(strip_for(&[], &readiness), &[], &readiness);
    let html = page::alerts_page(&view).into_string();

    // The honesty caveat replaces the reassuring all-quiet copy.
    assert!(
        html.contains("absence of a signal is not evidence of safety"),
        "a blind node forbids an all-quiet reading (F5/JEF-308)"
    );
    assert!(
        html.contains("node-blind"),
        "the blind node is named in the caveat"
    );
    assert!(
        !html.contains("no alarming activity right now"),
        "the calm all-quiet copy must NOT render while we are blind"
    );
}

// ---------------------------------------------------------------------------
// The findings/path view annotates a live-corroborated chain with its alert.
// ---------------------------------------------------------------------------

#[test]
fn findings_detail_annotates_the_chain_with_its_corroborating_alert() {
    let f = finding_with_signals(
        "workload/prod/web",
        120,
        vec![Behavior::FileWrite {
            path: "/usr/bin/dropper".into(),
        }],
    );
    let readiness = judging_readiness();
    let view = super::view_model::build_findings_view(
        "prod".into(),
        &[f],
        &[],
        &readiness,
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view).into_string();

    // The critical-path detail carries the "corroborated-now" annotation naming the live signal,
    // the workload, and its recency.
    assert!(
        html.contains("corroborated-now"),
        "the chain is annotated with its corroborating alert (JEF-323)"
    );
    assert!(
        html.contains("prod/web"),
        "the annotation names the workload"
    );
    assert!(html.contains("2m ago"), "the annotation carries recency");
}
