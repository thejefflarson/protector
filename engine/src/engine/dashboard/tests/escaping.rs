//! Untrusted-text escaping tests for the v2 dashboard (JEF-255, CLAUDE.md invariant): the
//! verdict prose, node names, the raw prompt, and CVE/scanner titles are all model-/scanner-
//! adjacent free text. They are carried verbatim through the data layer and MUST be escaped at
//! render (the maud `{ }` brace). A hostile string must never reach the rendered HTML as live
//! markup.

use super::*;
use crate::engine::graph::{Behavior, Reachability, Severity, Vulnerability};

const XSS: &str = "<script>alert('x')</script>";

fn render_with(findings: &[Finding], prompts: &BTreeMap<String, String>) -> String {
    page(
        findings,
        &covered(),
        &[],
        DecisionTallies::default(),
        &[],
        &BakeStats::default(),
        prompts,
    )
}

#[test]
fn verdict_prose_is_escaped() {
    let fs = vec![finding(
        "workload/app/Pod/web",
        "secret/app/s",
        Some(Verdict::Exploitable(XSS.into())),
    )];
    let html = render_with(&fs, &BTreeMap::new());
    assert!(
        !html.contains("<script>alert"),
        "verdict prose must be escaped"
    );
    assert!(html.contains("&lt;script&gt;"));
}

#[test]
fn node_names_in_the_hop_list_are_escaped() {
    // A hostile objective node key flows into the hop-list and the row's "reaches". Use a
    // slash-free payload so `NodeKey::short_of` (which splits on the first `/`) keeps it whole.
    let payload = "<img src=x onerror=alert(1)>";
    let fs = vec![finding(
        "workload/app/Pod/web",
        payload,
        Some(Verdict::Confirmed),
    )];
    let html = render_with(&fs, &BTreeMap::new());
    assert!(!html.contains("<img src=x"), "node name must be escaped");
    assert!(html.contains("&lt;img src=x"));
}

#[test]
fn raw_prompt_is_escaped() {
    let fs = vec![finding(
        "workload/app/Pod/web",
        "secret/app/s",
        Some(Verdict::Exploitable("y".into())),
    )];
    let mut prompts = BTreeMap::new();
    prompts.insert("workload/app/Pod/web".to_string(), XSS.to_string());
    let html = render_with(&fs, &prompts);
    assert!(
        !html.contains("<script>alert"),
        "raw prompt must be escaped"
    );
    assert!(html.contains("&lt;script&gt;"));
}

#[test]
fn cve_title_is_escaped() {
    let mut f = finding(
        "workload/app/Pod/web",
        "secret/app/s",
        Some(Verdict::Exploitable("y".into())),
    );
    f.evidence = EntryEvidence {
        cves: vec![crate::engine::dashboard::model::CveEvidence::from_vuln(
            &Vulnerability {
                id: "CVE-2021-44228".into(),
                severity: Severity::Critical,
                exploited_in_wild: true,
                reachability: Reachability::NotObserved,
                title: Some(XSS.into()),
                ..Default::default()
            },
        )],
        ..Default::default()
    };
    let html = render_with(&[f], &BTreeMap::new());
    assert!(!html.contains("<script>alert"), "CVE title must be escaped");
    assert!(html.contains("&lt;script&gt;"));
}

#[test]
fn behavior_summary_is_escaped() {
    let mut f = finding(
        "workload/app/Pod/web",
        "secret/app/s",
        Some(Verdict::Exploitable("y".into())),
    );
    f.corroborated = true;
    f.evidence = EntryEvidence {
        runtime: vec![Behavior::Alert { rule: XSS.into() }],
        ..Default::default()
    };
    let html = render_with(&[f], &BTreeMap::new());
    assert!(
        !html.contains("<script>alert"),
        "behavior summary must be escaped"
    );
    assert!(html.contains("&lt;script&gt;"));
}
