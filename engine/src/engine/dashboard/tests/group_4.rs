#![allow(unused_imports)]
//! Render-level findings + evidence tests (JEF-202 / JEF-133) and the cross-surface no-leak
//! guard (JEF-176). The findings core renders through the migrated maud components (JEF-205);
//! the pure verdict-gist / evidence-glyph / next-lever logic is tested in
//! `view_model::findings`, and the standalone CVE/runtime block HTML in
//! `components::findings::evidence`.
use super::*;
use crate::engine::dashboard::model::*;
use crate::engine::dashboard::page::FINDINGS_COLS;
use crate::engine::dashboard::page::{render_fragment, render_html};
use crate::engine::dashboard::view_model::readiness_data::*;
use crate::engine::dashboard::view_model::report_data::*;
use crate::engine::dashboard::{DASHBOARD_CSS, DASHBOARD_JS, default_window_report};
use crate::engine::graph::attack::{CREDENTIAL_ACCESS, EXPLOIT_PUBLIC_FACING};
use crate::engine::graph::{
    Behavior, NodeKey, Reachability, SecurityGraph, Severity, Vulnerability,
};
use crate::engine::reason::proof::{Link, ProvenChain};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[test]
fn table_is_primary_no_full_card_until_a_row_is_expanded() {
    // JEF-202: the dense table leads; the verbose card body is ONLY in the hidden detail row.
    let f = ranked_finding(
        "workload/app/Pod/web",
        "latent foothold — propose",
        false,
        Some("exploitable — boom"),
    );
    let html = render_html(
        &[f],
        false,
        &BakeStats::default(),
        &[],
        Some(SystemTime::now()),
        &ready_all_met(),
    );
    let body_at = html
        .find("what to do:")
        .expect("body present (in detail row)");
    let detail_at = html
        .find("class=\"f-detail\" hidden")
        .expect("hidden detail row");
    assert!(
        detail_at < body_at,
        "the card body lives inside the hidden detail row"
    );
    assert!(!html.contains("card-context"), "no old card wrapper");
}

#[test]
fn verdict_cell_is_a_tag_plus_clause_not_a_paragraph() {
    // JEF-199: the row's verdict cell shows the tag + one clause; the model's PARAGRAPH is
    // only in the expanded body (verbatim).
    let f = finding_with_cves(
        Some(
            "exploitable — a long verbatim model paragraph that explains the whole chain in detail",
        ),
        vec![cve("CVE-2021-44228", Severity::Critical, true)],
    );
    let row = row_html("workload/app/Pod/web", &[&f]);
    assert!(row.contains("c-verdict"), "verdict cell present");
    assert!(row.contains("[BREACH]"));
    assert!(row.contains("CVE-2021-44228"));
    let cell_start = row.find("c-verdict").unwrap();
    let detail_start = row.find("class=\"f-detail\"").unwrap();
    let para = "long verbatim model paragraph";
    let para_at = row.find(para).expect("paragraph present in body");
    assert!(para_at > detail_start, "paragraph lives in the detail body");
    assert!(
        !row[cell_start..detail_start].contains(para),
        "the summary verdict cell is not the paragraph"
    );
}

#[test]
fn row_open_state_persistence_hooks_are_present() {
    // JEF-202: the row-expand button state AND the lazy graph survive the /fragment swap —
    // asserted against the served dashboard module asset (DASHBOARD_JS).
    let js = DASHBOARD_JS;
    assert!(js.contains("function rowKey(btn)"), "stable row key");
    assert!(
        js.contains("function restoreRows(root)"),
        "restore row state"
    );
    assert!(
        js.contains("restoreRows(region)"),
        "re-applied after the swap"
    );
    assert!(js.contains("localStorage"), "persisted to localStorage");
    assert!(
        js.contains("closest('[hidden]')"),
        "graphs in a hidden row are deferred to first reveal"
    );
    assert!(js.contains("function hydrate(root)") && js.contains("detailsKey"));
}

// The `/judgements` HTML render (the three meta-states, prose-first, raw behind the
// expander, and the honest-empty state) is byte-pinned in `components::judgements`'s own
// tests (JEF-207).

#[test]
fn render_html_card_has_aria_label_on_the_graph() {
    // AC #4: every rendered attack-path graph carries the words summary.
    let findings = vec![finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "durable-fix PR",
        "can-do/get/secrets",
        true,
        Some("not exploitable — authorized RBAC"),
    )];
    let html = render_html(&findings, false, &BakeStats::default(), &[], None, &ready());
    assert!(html.contains("data-aria=\""));
    assert!(html.contains("Attack-path graph"));
    assert!(DASHBOARD_JS.contains("setAttribute('role', 'img')"));
    assert!(DASHBOARD_JS.contains("setAttribute('aria-label', aria)"));
}

#[test]
fn judgements_json_shape_is_unchanged() {
    let j = full_judgement(
        "workload/app/Pod/web",
        "exploitable — RCE",
        Some("p"),
        Some("r"),
    );
    let v = serde_json::to_value(&j).unwrap();
    assert_eq!(v["entry"], "workload/app/Pod/web");
    assert_eq!(v["objectives"], 3);
    assert_eq!(v["verdict"], "exploitable — RCE");
    assert_eq!(v["prompt"], "p");
    assert_eq!(v["reply"], "r");
    let pre = full_judgement("e", "Refuted(\"x\")", None, None);
    let pv = serde_json::to_value(&pre).unwrap();
    assert!(pv["prompt"].is_null());
    assert!(pv["reply"].is_null());
}

#[test]
fn finding_carries_evidence_in_json_for_programmatic_use() {
    // The /findings JSON must carry the evidence fields (JEF-133 AC).
    let mut f = finding(
        "workload/app/Pod/web",
        "secret/app/s",
        "auto-eligible",
        "can-read",
        true,
        Some("exploitable — RCE"),
    );
    f.evidence = EntryEvidence {
        cves: vec![cve("CVE-2021-44228", Severity::Critical, true)],
        runtime: vec![Behavior::Alert {
            rule: "shell".into(),
        }],
        ..Default::default()
    };
    let v = serde_json::to_value(&f).unwrap();
    assert_eq!(v["evidence"]["cves"][0]["id"], "CVE-2021-44228");
    assert_eq!(v["evidence"]["cves"][0]["severity"], "critical");
    assert_eq!(v["evidence"]["cves"][0]["kev"], true);
    assert_eq!(v["evidence"]["cves"][0]["reachability"], "not-observed");
    assert_eq!(v["evidence"]["runtime"][0]["kind"], "alert");
    assert_eq!(v["evidence"]["runtime"][0]["rule"], "shell");
}

#[test]
fn endpoint_card_renders_both_evidence_blocks() {
    let mut f = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "auto-eligible",
        "can-read",
        true,
        Some("exploitable — RCE reaches the secret"),
    );
    f.evidence = EntryEvidence {
        cves: vec![cve("CVE-2021-44228", Severity::Critical, true)],
        runtime: vec![Behavior::Alert {
            rule: "Terminal shell in container".into(),
        }],
        ..Default::default()
    };
    let refs = vec![&f];
    let html = card_body("workload/app/Pod/web", &refs);
    assert!(html.contains("evidence for this path"));
    assert!(
        html.contains("how bad it would be if exploited"),
        "CVE block: {html}"
    );
    assert!(
        html.contains("is it being exploited right now"),
        "runtime block: {html}"
    );
    assert!(html.contains("CVE-2021-44228"));
    assert!(html.contains("SEEN LIVE"));
}

#[test]
fn endpoint_card_with_no_evidence_renders_both_honest_empty_states() {
    let f = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "structural — propose",
        "can-read",
        true,
        None,
    );
    let refs = vec![&f];
    let html = card_body("workload/app/Pod/web", &refs);
    assert!(html.contains("none on this service's image"));
    assert!(html.contains("no live activity seen on this service"));
    assert!(!html.contains("SEEN LIVE"));
}

#[test]
fn from_chain_pulls_entry_evidence_filtered_to_kev_or_critical() {
    use crate::engine::graph::{
        Edge, Exposure, Grade, Image, Node, Provenance, Relation, RuntimeSignal, Trust, Workload,
    };
    use crate::engine::reason::proof::Link;
    use std::time::SystemTime;

    let mut g = SecurityGraph::new();
    let wl = Node::Workload(Workload {
        namespace: "app".into(),
        name: "web".into(),
        kind: "Pod".into(),
        labels: Default::default(),
        meshed: false,
        exposure: Exposure::Internet,
        runtime: vec![RuntimeSignal {
            behavior: Behavior::Alert {
                rule: "shell".into(),
            },
            provenance: Provenance::new("test", SystemTime::UNIX_EPOCH),
        }],
        persistent: false,
        misconfigs: vec![],
        rbac_findings: vec![],
    });
    let entry_key = wl.key();
    let e = g.upsert_node(wl);
    let img = g.upsert_node(Node::Image(Image {
        digest: "sha256:abc".into(),
        reference: Some("web:1".into()),
        trust: Trust::Unknown,
        vulnerabilities: vec![
            vuln("CVE-2021-0001", Severity::Critical, false),
            vuln("CVE-2021-0002", Severity::High, true),
            vuln("CVE-2021-0003", Severity::Medium, false),
        ],
        exposed_secrets: vec![],
    }));
    g.add_edge(
        e,
        img,
        Edge {
            relation: Relation::RunsImage,
            provenance: Provenance::new("test", SystemTime::UNIX_EPOCH),
            grade: Grade::Proof,
        },
    );

    let cut = Link {
        from: entry_key.clone(),
        to: NodeKey("secret/app/s".into()),
        relation: "can-read".into(),
        technique: None,
        from_labels: Default::default(),
        to_labels: Default::default(),
    };
    let chain = ProvenChain {
        entry: entry_key,
        objective: NodeKey("secret/app/s".into()),
        attack: CREDENTIAL_ACCESS,
        foothold: Some(EXPLOIT_PUBLIC_FACING),
        corroborated: false,
        adjudicated: true,
        promoted: false,
        exposed_entry: true,
        verdict: None,
        links: vec![cut.clone()],
        single_edge_cuts: vec![cut],
    };

    let f = Finding::from_chain(&chain, &g);
    let ids: Vec<&str> = f.evidence.cves.iter().map(|c| c.id.as_str()).collect();
    assert!(ids.contains(&"CVE-2021-0001"), "critical kept: {ids:?}");
    assert!(ids.contains(&"CVE-2021-0002"), "KEV kept: {ids:?}");
    assert!(
        !ids.contains(&"CVE-2021-0003"),
        "plain medium filtered: {ids:?}"
    );
    assert_eq!(f.evidence.runtime.len(), 1, "entry runtime signal carried");
    assert!(f.evidence.runtime[0].is_alert());
}

// ---- JEF-176: no ADR-/JEF- token leaks into operator-facing rendered output ----

#[test]
fn rendered_output_never_leaks_adr_or_jef_refs() {
    let findings = vec![
        rich_finding(
            "workload/app/Pod/web",
            Some("exploitable — CVE-2021-44228 reaches the secret"),
        ),
        rich_finding(
            "workload/api/Pod/svc",
            Some("not exploitable — unreachable"),
        ),
        rich_finding("workload/argo/Pod/server", None),
    ];

    for armed in [false, true] {
        for ready in [ready(), ready_all_met()] {
            let html = render_html(
                &findings,
                armed,
                &bake(80, 20),
                &[],
                Some(SystemTime::now()),
                &ready,
            );
            assert_no_internal_refs("dashboard", &html);
        }
    }

    let first_run = render_html(
        &[],
        false,
        &BakeStats::default(),
        &[],
        Some(SystemTime::now()),
        &ready(),
    );
    assert!(first_run.contains("checklist") || first_run.contains("done"));
    assert_no_internal_refs("first-run dashboard", &first_run);

    // The `/judgements` and `/report` surfaces carry their own no-internal-refs guards in
    // the `components::judgements` / `components::report` tests (JEF-207).
}

/// AC #3: the finding card's attack steps lead with the plain technique name and keep the
/// MITRE code only inside an `<abbr>` tooltip — asserted against the migrated remediation
/// component (JEF-205).
#[test]
fn killchain_leads_with_plain_name_mitre_code_in_abbr() {
    use crate::engine::dashboard::components::findings::remediation;
    use crate::engine::dashboard::view_model::findings::remediation_props;
    let f = rich_finding("workload/app/Pod/web", Some("exploitable — RCE"));
    let card = remediation(&remediation_props(&f, false)).into_string();
    // Plain technique name leads; the foothold is plain phrasing.
    assert!(
        card.contains("Unsecured Credentials"),
        "plain name present: {card}"
    );
    assert!(
        card.contains("internet-facing service"),
        "plain foothold phrasing: {card}"
    );
    // The MITRE code is present but only inside an abbr title (not bare text).
    assert!(card.contains("<abbr title="), "code tucked in abbr: {card}");
    assert!(card.contains("T1552"), "code available in tooltip: {card}");
    // The card caption is plain English — "attack steps", never "kill chain".
    assert!(card.contains("attack steps:"), "plain label: {card}");
    assert!(!card.contains("kill chain"), "no jargon label: {card}");
}
