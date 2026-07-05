//! Render-level tests for the JEF-308 runtime-corroboration row: the per-node breakdown is a
//! server-rendered `<table>` inside `<details>` (no JS), a blind node is surfaced loudly, and an
//! untrusted node name is ESCAPED (maud auto-escape — never `PreEscaped`).

use std::time::SystemTime;

use crate::engine::dashboard::page;
use crate::engine::dashboard::view_model::{build_readiness_view, build_status_strip};
use crate::engine::state::{
    BakeStats, BlindReason, ModelHealth, NodeCoverage, NodeState, ReadinessConfig, RuntimeCoverage,
    derive_readiness,
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
        html.contains("Runtime corroboration"),
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
