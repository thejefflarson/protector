//! Render-level tests for the JEF-308 runtime-corroboration row: the per-node breakdown is a
//! server-rendered `<table>` inside `<details>` (no JS), a blind node is surfaced loudly, and an
//! untrusted node name is ESCAPED (maud auto-escape — never `PreEscaped`).

use std::time::SystemTime;

use crate::engine::dashboard::page;
use crate::engine::dashboard::view_model::{build_readiness_view, build_status_strip};
use crate::engine::state::{
    BakeStats, BlindReason, CorroborationParity, ModelHealth, NodeCoverage, NodeState,
    ReadinessConfig, RuntimeCoverage, derive_readiness,
};

fn covered() -> ReadinessConfig {
    ReadinessConfig {
        model_attached: true,
        kev_count: 5,
        epss_count: 5,
        journal_durable: true,
        armed: false,
        tuf_cache_age_secs: Some(60),
        unverifiable_spike: false,
    }
}

#[test]
fn per_node_breakdown_is_a_server_table_and_escapes_node_names() {
    // A malicious node name plus a healthy one — the row is degraded (one blind), named.
    let coverage = RuntimeCoverage {
        nodes: vec![
            NodeCoverage {
                node: "node-a".into(),
                state: NodeState::Healthy { signals: 2 },
            },
            NodeCoverage {
                node: "<script>alert(1)</script>".into(),
                state: NodeState::Blind {
                    reason: BlindReason::NotReporting,
                },
            },
        ],
    };
    let readiness = derive_readiness(
        &covered(),
        ModelHealth::Ok,
        &BakeStats::default(),
        Some(SystemTime::now()),
        &coverage,
    );
    let strip = build_status_strip("prod".into(), &[], &[], &readiness, Some(SystemTime::now()));
    let v = build_readiness_view(strip, &readiness);
    let html = page::readiness_page(&v).into_string();

    assert!(
        html.contains("Runtime monitoring"),
        "the collapsed row label"
    );
    assert!(
        html.contains("<table"),
        "the per-node breakdown is a server-rendered table (no JS)"
    );
    assert!(html.contains("<details"), "wrapped in a details disclosure");
    assert!(html.contains("node-a"));
    // The untrusted node name is ESCAPED — the raw <script> tag never reaches the HTML.
    assert!(
        !html.contains("<script>alert(1)</script>"),
        "an untrusted node name must be escaped, not injected"
    );
    assert!(
        html.contains("&lt;script&gt;"),
        "it appears in escaped form"
    );
    // A blind node is surfaced loudly, never quietly reassuring.
    assert!(html.contains("BLIND"));
}

/// Render the corroboration-parity panel (JEF-310) and render `page` once, returning the HTML.
fn render_with_parity(parity: CorroborationParity) -> String {
    let readiness = derive_readiness(
        &covered(),
        ModelHealth::Ok,
        &BakeStats::default(),
        Some(SystemTime::now()),
        &RuntimeCoverage::default(),
    )
    .with_parity(&parity);
    let strip = build_status_strip("prod".into(), &[], &[], &readiness, Some(SystemTime::now()));
    let v = build_readiness_view(strip, &readiness);
    page::readiness_page(&v).into_string()
}

#[test]
fn parity_panel_reads_nothing_to_compare_not_a_go_signal_when_falco_is_silent() {
    // An empty fold: no Falco corroboration this pass. The panel must read "nothing to compare",
    // NOT a reassuring "0 uncovered = safe to retire" (ADR-0016 honesty).
    let html = render_with_parity(CorroborationParity::default());
    assert!(
        html.contains("Falco-retirement corroboration parity"),
        "the parity panel is present"
    );
    assert!(
        html.contains("nothing to compare"),
        "a Falco-silent window reads 'nothing to compare'"
    );
    // It must NOT read as a cleared/parity go-signal.
    assert!(
        !html.contains("parity this pass"),
        "no Falco corroboration is not parity"
    );
}

#[test]
fn parity_panel_surfaces_agent_uncovered_count_and_escapes_workload_names() {
    // Falco corroborated two chains, the agent matched one → one agent-uncovered, on a workload
    // whose (untrusted-adjacent) name must be ESCAPED at render, never injected.
    let parity = CorroborationParity {
        falco_corroborated: 2,
        agent_corroborated: 1,
        both: 1,
        agent_uncovered: 1,
        agent_only: 0,
        uncovered_entries: vec!["workload/app/Pod/<script>alert(1)</script>".into()],
    };
    let html = render_with_parity(parity);
    assert!(
        html.contains("AGENT-UNCOVERED"),
        "the agent-uncovered state is surfaced loudly"
    );
    assert!(
        html.contains("NOT yet safe to retire Falco"),
        "the honest retirement caveat is shown"
    );
    // The untrusted workload name is ESCAPED — the raw <script> tag never reaches the HTML.
    assert!(
        !html.contains("<script>alert(1)</script>"),
        "an untrusted workload name must be escaped, not injected"
    );
    assert!(html.contains("&lt;script&gt;"), "it appears escaped");
}
