//! Page-level render tests for the v2 single-page dashboard (JEF-255): the status line is
//! always present; the BREACH queue appears iff there are breaches; a row expands to the
//! detail (verbatim verdict + rail + evidence + text-hops + what-to-do); the admission strip
//! and the internals disclosure render; and `/fragment` is exactly the page's `#live` region.

use super::*;

#[test]
fn page_renders_the_status_line_and_shell() {
    let fs = vec![finding("workload/app/Pod/web", "secret/app/s", None)];
    let html = page(
        &fs,
        &covered(),
        &[],
        DecisionTallies::default(),
        &[],
        &BakeStats::default(),
        &BTreeMap::new(),
    );
    assert!(html.contains("<!doctype html>"));
    assert!(html.contains("/assets/dashboard.css"));
    assert!(html.contains("/assets/dashboard.js"));
    // The one-line status headline is always present.
    assert!(html.contains("class=\"status"));
    assert!(html.contains("endpoint"));
    assert!(html.contains("coverage"));
    // No tabs / nav — single page.
    assert!(!html.contains("href=\"/report\""));
    assert!(!html.contains("href=\"/judgements\""));
    assert_no_internal_refs("page", &html);
}

#[test]
fn breach_queue_appears_only_when_a_breach_exists() {
    // No breach → no queue.
    let safe = vec![finding(
        "workload/app/Pod/web",
        "secret/app/s",
        Some(Verdict::Refuted("internal only".into())),
    )];
    let html = page(
        &safe,
        &covered(),
        &[],
        DecisionTallies::default(),
        &[],
        &BakeStats::default(),
        &BTreeMap::new(),
    );
    assert!(!html.contains("breach-queue"), "no breach → no queue");

    // A breach → the queue renders, loud, with the decisive clause.
    let breach = vec![finding(
        "workload/app/Pod/web",
        "secret/app/s",
        Some(Verdict::Exploitable("RCE via CVE-2021-44228".into())),
    )];
    let html = page(
        &breach,
        &covered(),
        &[],
        DecisionTallies::default(),
        &[],
        &BakeStats::default(),
        &BTreeMap::new(),
    );
    assert!(html.contains("breach-queue"));
    assert!(html.contains("1 BREACH"));
    assert!(html.contains("exploitable — RCE via CVE-2021-44228"));
    // The status line leads with the breach count and tone.
    assert!(html.contains("s-breach"));
}

#[test]
fn a_row_expands_to_verdict_rail_evidence_hops_and_todo() {
    let breach = vec![finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        Some(Verdict::Exploitable("game over".into())),
    )];
    let mut prompts = BTreeMap::new();
    prompts.insert(
        "workload/app/Pod/web".to_string(),
        "THE RAW PROMPT".to_string(),
    );
    let html = page(
        &breach,
        &covered(),
        &[],
        DecisionTallies::default(),
        &[],
        &BakeStats::default(),
        &prompts,
    );
    // The dense row + its hidden detail.
    assert!(html.contains("class=\"endpoints\""));
    assert!(html.contains("aria-controls=\"detail-workload-app-Pod-web\""));
    assert!(html.contains("class=\"ep-detail\" hidden"));
    // The detail body: verbatim verdict, the raw-prompt expander, the rail, the text hops, todo.
    assert!(html.contains("verdict:"));
    assert!(html.contains("exploitable — game over"));
    assert!(html.contains("raw model prompt"));
    assert!(html.contains("THE RAW PROMPT"));
    assert!(html.contains("proven-reachable"));
    assert!(html.contains("Attack path"));
    assert!(html.contains("(internet-reachable)"));
    assert!(html.contains("✂ cut here"));
    assert!(html.contains("What to do:"));
    // No graph — text hop-list only (Mermaid retired).
    assert!(!html.contains("mermaid"));
    assert!(!html.contains("<svg"));
}

#[test]
fn safe_row_has_no_what_to_do() {
    let safe = vec![finding(
        "workload/app/Pod/web",
        "secret/app/s",
        Some(Verdict::Refuted("not reachable".into())),
    )];
    let html = page(
        &safe,
        &covered(),
        &[],
        DecisionTallies::default(),
        &[],
        &BakeStats::default(),
        &BTreeMap::new(),
    );
    assert!(html.contains("SAFE"));
    assert!(!html.contains("What to do:"));
}

#[test]
fn admission_strip_renders_fractions_and_audit_seam() {
    let records = vec![
        PolicyDecisionRecord::now(
            "admission",
            "allow",
            "Deployment/web",
            "img@sha",
            "signed",
            "meshed",
            "app",
            "ok",
        ),
        PolicyDecisionRecord::now(
            "admission",
            "audit",
            "Deployment/api",
            "img@sha",
            "unsigned",
            "meshed",
            "app",
            "would-deny",
        ),
    ];
    let tallies = DecisionTallies {
        admitted: 1,
        audited: 1,
        denied: 0,
    };
    let html = page(
        &[],
        &covered(),
        &records,
        tallies,
        &[],
        &BakeStats::default(),
        &BTreeMap::new(),
    );
    assert!(html.contains("admission:"));
    assert!(html.contains("signed <b>1/2</b>"));
    assert!(html.contains("meshed <b>2/2</b>"));
    assert!(html.contains("would-deny (audit)"));
}

#[test]
fn internals_disclosure_carries_coverage_reversions_and_bake() {
    let rev = vec![ReversionRecord {
        cut: "a -[reaches]-> b".into(),
        reason: "breach condition cleared".into(),
        at_ms: 1,
    }];
    let mut bake = BakeStats::default();
    bake.signals_by_variant.insert("exec".into(), 7);
    bake.corroborations = 3;
    let html = page(
        &[],
        &covered(),
        &[],
        DecisionTallies::default(),
        &rev,
        &bake,
        &BTreeMap::new(),
    );
    assert!(html.contains("Engine internals"));
    assert!(html.contains("Coverage"));
    assert!(html.contains("Model adjudicator"));
    assert!(html.contains("a -[reaches]-&gt; b"));
    assert!(html.contains("breach condition cleared"));
    assert!(html.contains("Behavioral bake"));
    assert!(html.contains("corroborations this pass"));
}

#[test]
fn model_down_status_is_blind_not_calm() {
    let fs = vec![finding("workload/app/Pod/web", "secret/app/s", None)];
    let html = page(
        &fs,
        &model_down(),
        &[],
        DecisionTallies::default(),
        &[],
        &BakeStats::default(),
        &BTreeMap::new(),
    );
    assert!(html.contains("s-blind"));
    assert!(html.contains("model down — not judging"));
    assert!(!html.contains("all clear"));
}

#[test]
fn empty_clean_covered_cluster_reads_all_clear() {
    let html = page(
        &[],
        &covered(),
        &[],
        DecisionTallies::default(),
        &[],
        &BakeStats::default(),
        &BTreeMap::new(),
    );
    assert!(html.contains("s-clear"));
    assert!(html.contains("all clear"));
    assert!(html.contains("no internet-facing service can reach a target"));
}

#[test]
fn fragment_is_the_pages_live_region() {
    let breach = vec![finding(
        "workload/app/Pod/web",
        "secret/app/s",
        Some(Verdict::Exploitable("y".into())),
    )];
    let frag = fragment(
        &breach,
        &covered(),
        &[],
        DecisionTallies::default(),
        &[],
        &BakeStats::default(),
        &BTreeMap::new(),
    );
    let html = page(
        &breach,
        &covered(),
        &[],
        DecisionTallies::default(),
        &[],
        &BakeStats::default(),
        &BTreeMap::new(),
    );
    // The fragment is the `#live` container, and the full page embeds it verbatim.
    assert!(frag.starts_with("<div id=\"live\">"));
    assert!(
        html.contains(&frag),
        "page embeds the fragment byte-for-byte"
    );
}

#[test]
fn breach_sorts_above_awaiting_and_safe() {
    let fs = vec![
        finding("workload/app/Pod/aaa", "secret/s1", None),
        finding(
            "workload/app/Pod/zzz",
            "secret/s2",
            Some(Verdict::Exploitable("y".into())),
        ),
        finding(
            "workload/app/Pod/mmm",
            "secret/s3",
            Some(Verdict::Refuted("n".into())),
        ),
    ];
    let html = page(
        &fs,
        &covered(),
        &[],
        DecisionTallies::default(),
        &[],
        &BakeStats::default(),
        &BTreeMap::new(),
    );
    let breach = html.find("Pod/zzz").expect("breach row present");
    let safe = html.find("Pod/mmm").expect("safe row present");
    let awaiting = html.find("Pod/aaa").expect("awaiting row present");
    // The breach row sorts first in the table body (after the breach queue, which also names it,
    // but the queue is before the table — find the table region).
    let table = html.find("class=\"endpoints\"").expect("table present");
    let breach_in_table = html[table..].find("Pod/zzz").map(|i| table + i).unwrap();
    let safe_in_table = html[table..].find("Pod/mmm").map(|i| table + i).unwrap();
    let awaiting_in_table = html[table..].find("Pod/aaa").map(|i| table + i).unwrap();
    assert!(breach_in_table < safe_in_table);
    assert!(breach_in_table < awaiting_in_table);
    let _ = (breach, safe, awaiting);
}
