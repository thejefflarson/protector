#![allow(unused_imports)]
use super::*;
use crate::engine::dashboard::legacy::*;
use crate::engine::dashboard::page::FINDINGS_COLS;
use crate::engine::dashboard::page::{render_fragment, render_html};
use crate::engine::dashboard::{DASHBOARD_CSS, DASHBOARD_JS, default_window_report};
use crate::engine::graph::attack::{CREDENTIAL_ACCESS, EXPLOIT_PUBLIC_FACING};
use crate::engine::graph::{Advisory, NodeKey, Reachability, Severity, Vulnerability};
use crate::engine::journal::DecisionJournal;
use crate::engine::reason::proof::Link;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[test]
fn bake_panel_is_quiet_when_nothing_observed() {
    let panel = bake_panel(&BakeStats::default());
    assert!(
        panel.contains("no behavioral signals observed yet"),
        "an empty bake reads as quiet, not as an error"
    );
    // A fully-resolved pass shows no flagged unresolved share.
    let clean = bake_panel(&bake(15, 0));
    assert!(
        !clean.contains("unresolved ("),
        "0 unresolved is not flagged"
    );
}

#[test]
fn render_html_includes_the_behavioral_bake_section() {
    let html = render_html(&[], false, &bake(80, 20), &[], None, &ready());
    assert!(
        html.contains("Live activity the sensors saw"),
        "the section header is present"
    );
    assert!(
        html.contains("connection"),
        "the per-variant volume renders"
    );
}

// ====================================================================
// The shadow would-have-acted report (JEF-143)
// ====================================================================

#[test]
fn verdict_classification_matches_the_findings_convention() {
    assert!(verdict_would_act(
        "exploitable — CVE-2021-44228 reaches the secret"
    ));
    assert!(verdict_would_act("Exploitable — RCE"));
    assert!(verdict_would_act("confirmed — live attack should stand"));
    assert!(!verdict_would_act(
        "not exploitable — code path never invoked"
    ));
    assert!(!verdict_would_act("refuted — same-ns own DB"));
    assert!(!verdict_would_act("uncertain — model unavailable"));
}

#[test]
fn coverage_gap_reads_the_structured_field_not_the_verdict_prose() {
    // JEF-145: a gap is classified from the STRUCTURED enrichment-coverage the model
    // was given, never the verdict wording.
    // No CVE and no behavioral signal ⇒ a gap.
    assert!(is_coverage_gap(Some(&EnrichmentCoverage {
        cves: vec![],
        behavioral: false,
    })));
    // A CVE backs it ⇒ NOT a gap.
    assert!(!is_coverage_gap(Some(&EnrichmentCoverage {
        cves: vec!["CVE-2021-44228".into()],
        behavioral: false,
    })));
    // A behavioral signal backs it ⇒ NOT a gap.
    assert!(!is_coverage_gap(Some(&EnrichmentCoverage {
        cves: vec![],
        behavioral: true,
    })));
    // Back-compat: an old line with no structured coverage is "unknown", NOT a gap.
    assert!(!is_coverage_gap(None));
}

#[test]
fn empty_journal_is_an_honest_no_decisions_state() {
    // The acceptance criterion: an empty journal reads as "no decisions yet", not
    // an error or a misleading zero-diff.
    let report = aggregate_report(&[], report_now(), WEEK, FIVE_MIN);
    assert!(report.journal_empty, "no breach decisions ⇒ journal_empty");
    assert_eq!(report.would_act_count(), 0);
    assert_eq!(report.left_alone_count(), 0);
    let panel = report_panel(&report);
    assert!(panel.contains("no decisions yet"), "honest empty state");
    // The full page wraps it and stays a valid document.
    let page = render_report_html(&report);
    assert!(page.contains("would-have-acted report"));
    assert!(page.contains("no decisions yet"));
}

#[test]
fn window_filtering_excludes_decisions_outside_the_window() {
    // A breach 8 days ago is outside a 7-day window; an in-window decision survives.
    // The journal is NOT empty (history exists), but nothing falls in the window.
    let entries = vec![breach(
        "workload/app/Pod/old",
        "exploitable — CVE-2020-0001 RCE",
        8 * 24 * 3600,
    )];
    let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
    assert!(!report.journal_empty, "the journal has history");
    assert_eq!(
        report.decisions_in_window, 0,
        "but none in the 7-day window"
    );
    assert_eq!(report.would_act_count(), 0);
    // A wider window pulls it back in.
    let wide = aggregate_report(
        &entries,
        report_now(),
        Duration::from_secs(30 * 24 * 3600),
        FIVE_MIN,
    );
    assert_eq!(
        wide.would_act_count(),
        1,
        "30-day window includes the old one"
    );
}

#[test]
fn a_sustained_then_cleared_path_is_a_would_act_with_a_real_lifetime() {
    // Breach held exploitable for an hour (two decisions an hour apart), then cleared.
    // The projected cut lifetime is ~1h — sustained, not short-lived — and the entry
    // shows in would-act, NOT left-alone (it WOULD have been cut, even though it later
    // cleared: that's the whole point of the lifetime).
    let entries = vec![
        breach(
            "workload/app/Pod/web",
            "exploitable — CVE-2021-44228 RCE",
            7200,
        ),
        breach(
            "workload/app/Pod/web",
            "exploitable — CVE-2021-44228 RCE",
            3600,
        ),
        breach("workload/app/Pod/web", "not exploitable — patched", 0),
    ];
    let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
    assert_eq!(report.would_act_count(), 1);
    let w = &report.would_act[0];
    assert_eq!(w.entry, "workload/app/Pod/web");
    assert_eq!(
        w.would_act_decisions, 2,
        "two exploitable decisions in the run"
    );
    assert_eq!(w.episodes, 1);
    assert!(!w.open, "it cleared, so the episode is closed");
    assert_eq!(
        w.max_lifetime_secs, 7200,
        "first exploitable → the clear at now-3600"
    );
    assert!(!w.short_lived, "a 2h cut is sustained, not an FP");
    // It is NOT double-counted as left-alone.
    assert_eq!(report.left_alone_count(), 0);
}

#[test]
fn a_short_lived_would_act_is_flagged_as_a_likely_false_positive() {
    // Exploitable once, then cleared 60s later: a 60s would-be cut — under the 5-min
    // threshold ⇒ short-lived ⇒ likely FP.
    let entries = vec![
        breach(
            "workload/app/Pod/blip",
            "exploitable — CVE-2022-1 brief RCE",
            120,
        ),
        breach(
            "workload/app/Pod/blip",
            "not exploitable — scanner artifact",
            60,
        ),
    ];
    let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
    assert_eq!(report.would_act_count(), 1);
    assert!(report.would_act[0].short_lived, "a 60s cut is short-lived");
    assert_eq!(report.short_lived_count(), 1);
}

#[test]
fn an_open_episode_projects_to_now_and_is_never_short_lived() {
    // Exploitable 30s ago and never cleared: the cut would still be standing. Even
    // though only 30s old, an OPEN episode is sustained-by-definition (not an FP yet).
    let entries = vec![breach(
        "workload/app/Pod/live",
        "exploitable — CVE-2023-9 active",
        30,
    )];
    let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
    assert_eq!(report.would_act_count(), 1);
    let w = &report.would_act[0];
    assert!(w.open, "still standing");
    assert!(!w.short_lived, "an open cut is never an FP");
    assert_eq!(w.max_lifetime_secs, 30);
}

#[test]
fn a_cleared_only_path_is_left_alone_trust_evidence() {
    // The model proved the path reachable but cleared it (never exploitable). This is
    // the trust half: a proven path deliberately left alone, NOT a would-act.
    let entries = vec![breach(
        "workload/app/Pod/safe",
        "not exploitable — the CVE is in a code path this service never invokes",
        600,
    )];
    let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
    assert_eq!(report.would_act_count(), 0);
    assert_eq!(report.left_alone_count(), 1);
    assert_eq!(report.left_alone[0].entry, "workload/app/Pod/safe");
    assert!(report.left_alone[0].verdict.contains("not exploitable"));
}

#[test]
fn coverage_gap_would_acts_are_counted_and_flagged() {
    // JEF-145 acceptance: a breach with NO enrichment (no CVE, no behavioral signal)
    // is flagged as a gap...
    let gap = vec![breach_cov(
        "workload/app/Pod/escape",
        "exploitable — a privileged container escape reaches the node",
        45,
        Some(EnrichmentCoverage {
            cves: vec![],
            behavioral: false,
        }),
    )];
    let report = aggregate_report(&gap, report_now(), WEEK, FIVE_MIN);
    assert_eq!(
        report.coverage_gap_count(),
        1,
        "no enrichment ⇒ coverage gap"
    );
    assert!(report.would_act[0].coverage_gap);

    // ...and a breach WITH CVE/behavioral backing is NOT flagged — regardless of the
    // verdict wording. Here the verdict prose mentions no CVE token at all, yet the
    // structured coverage carries one, so the prose heuristic would have misfired.
    let backed_cve = vec![breach_cov(
        "workload/app/Pod/web",
        "exploitable — a remote code-execution path reaches the secret",
        45,
        Some(EnrichmentCoverage {
            cves: vec!["CVE-2021-44228".into()],
            behavioral: false,
        }),
    )];
    let r2 = aggregate_report(&backed_cve, report_now(), WEEK, FIVE_MIN);
    assert_eq!(
        r2.coverage_gap_count(),
        0,
        "CVE backing ⇒ not a gap, even with no CVE in the prose"
    );
    assert!(!r2.would_act[0].coverage_gap);

    // The inverse misclassification is also gone: a verdict whose PROSE cites a CVE
    // but whose structured backing is empty IS still a gap (the old grep would have
    // read it as covered).
    let prose_only = vec![breach_cov(
        "workload/app/Pod/prose",
        "exploitable — resembles CVE-2099-0001 in shape but no advisory matched",
        45,
        Some(EnrichmentCoverage {
            cves: vec![],
            behavioral: false,
        }),
    )];
    let r3 = aggregate_report(&prose_only, report_now(), WEEK, FIVE_MIN);
    assert_eq!(
        r3.coverage_gap_count(),
        1,
        "empty structured backing ⇒ a gap, even with a CVE in the prose"
    );

    // A behavioral signal (no CVE) also backs the decision ⇒ not a gap.
    let backed_behavioral = vec![breach_cov(
        "workload/app/Pod/runtime",
        "exploitable — live reverse shell observed",
        45,
        Some(EnrichmentCoverage {
            cves: vec![],
            behavioral: true,
        }),
    )];
    let r4 = aggregate_report(&backed_behavioral, report_now(), WEEK, FIVE_MIN);
    assert_eq!(r4.coverage_gap_count(), 0, "behavioral backing ⇒ not a gap");
}

#[test]
fn a_pre_jef145_breach_with_no_structured_coverage_is_not_a_false_gap() {
    // Back-compat (AC #3): an old journal line has `coverage: None`. It is a would-act
    // (exploitable), but its coverage is "unknown" — it must NOT be counted as a gap.
    let entries = vec![breach_cov(
        "workload/app/Pod/legacy",
        "exploitable — reaches the secret",
        45,
        None,
    )];
    let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
    assert_eq!(report.would_act_count(), 1, "still a would-act");
    assert_eq!(
        report.coverage_gap_count(),
        0,
        "unknown coverage is not a gap (no false positive on old records)"
    );
    assert!(!report.would_act[0].coverage_gap);
}

#[test]
fn recurring_breach_counts_multiple_episodes() {
    // Exploitable, cleared, then exploitable again: two distinct would-act episodes
    // for the same workload (the breach condition recurred). The entry is a would-act
    // (its latest run is exploitable), with episodes == 2.
    let entries = vec![
        breach(
            "workload/app/Pod/web",
            "exploitable — CVE-2021-44228 RCE",
            3000,
        ),
        breach("workload/app/Pod/web", "not exploitable — patched", 2000),
        breach(
            "workload/app/Pod/web",
            "exploitable — CVE-2021-44228 regressed",
            1000,
        ),
    ];
    let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
    assert_eq!(report.would_act_count(), 1);
    assert_eq!(report.would_act[0].episodes, 2, "the breach recurred");
    assert!(
        report.would_act[0].open,
        "latest run is exploitable ⇒ still open"
    );
}

#[test]
fn report_panel_renders_the_diff_headline_and_both_tables() {
    // The HTML panel frames the diff (isolated N / left M alone), distinguishes
    // short-lived from sustained, and calls out the coverage-gap subset.
    let entries = vec![
        // A sustained, CVE-backed would-act (cleared after 2h).
        breach(
            "workload/app/Pod/web",
            "exploitable — CVE-2021-44228 RCE",
            7200,
        ),
        breach(
            "workload/app/Pod/web",
            "exploitable — CVE-2021-44228 RCE",
            3600,
        ),
        breach("workload/app/Pod/web", "not exploitable — patched", 0),
        // A short-lived, coverage-gap would-act (60s, no CVE).
        breach("workload/app/Pod/blip", "exploitable — brief escape", 120),
        breach("workload/app/Pod/blip", "not exploitable — gone", 60),
        // A left-alone proven path.
        breach(
            "workload/app/Pod/safe",
            "not exploitable — never invoked",
            600,
        ),
    ];
    let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
    assert_eq!(report.would_act_count(), 2);
    assert_eq!(report.left_alone_count(), 1);
    assert_eq!(report.short_lived_count(), 1);
    assert_eq!(report.coverage_gap_count(), 1);

    let panel = report_panel(&report);
    // The diff headline frames both halves.
    assert!(panel.contains("would have isolated"));
    assert!(panel.contains("left alone") || panel.contains("left <b>1</b>"));
    // Short-lived is visually distinct, sustained too.
    assert!(panel.contains("short-lived"), "FP tell rendered");
    assert!(panel.contains("class=\"shortlived\""));
    assert!(panel.contains("class=\"sustained\""));
    // The coverage-gap would-act is flagged for scrutiny.
    assert!(panel.contains("coverage gap"));
    assert!(panel.contains("class=\"flagged\""));
    // Both workloads and the left-alone one appear (short labels).
    assert!(panel.contains("web"));
    assert!(panel.contains("blip"));
    assert!(panel.contains("safe"));

    // The full page is a self-contained document.
    let page = render_report_html(&report);
    assert!(page.contains("<!doctype html>"));
    assert!(page.contains("would-have-acted report"));
    assert!(page.contains("Shadow would-have-acted diff"));
    let _ = std::fs::write("/tmp/protector-report.html", &page);
}

#[test]
fn most_sustained_would_act_is_ranked_first() {
    // Open (still standing) ranks above a closed long one, which ranks above a short one.
    let entries = vec![
        breach("workload/app/Pod/short", "exploitable — x", 200),
        breach("workload/app/Pod/short", "not exploitable — gone", 100),
        breach("workload/app/Pod/longclosed", "exploitable — y", 10_000),
        breach(
            "workload/app/Pod/longclosed",
            "not exploitable — patched",
            100,
        ),
        breach("workload/app/Pod/open", "exploitable — z", 50),
    ];
    let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
    assert_eq!(
        report.would_act[0].entry, "workload/app/Pod/open",
        "open first"
    );
    assert_eq!(report.would_act[1].entry, "workload/app/Pod/longclosed");
    assert_eq!(report.would_act[2].entry, "workload/app/Pod/short");
}

#[test]
fn report_query_resolves_window_and_threshold_with_defaults() {
    // Defaults: 7-day window, 5-min short-lived.
    let q = ReportQuery::default();
    assert_eq!(q.window(), Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600));
    assert_eq!(
        q.short_lived(),
        Duration::from_secs(DEFAULT_SHORT_LIVED_SECS)
    );
    // `days` sugar, and `hours` taking precedence over `days`.
    let by_days = ReportQuery {
        days: Some(3),
        ..Default::default()
    };
    assert_eq!(by_days.window(), Duration::from_secs(3 * 24 * 3600));
    let both = ReportQuery {
        hours: Some(2),
        days: Some(30),
        short_lived_secs: Some(10),
    };
    assert_eq!(both.window(), Duration::from_secs(2 * 3600), "hours wins");
    assert_eq!(both.short_lived(), Duration::from_secs(10));
}

#[test]
fn default_window_report_reads_an_in_memory_disabled_journal_as_empty() {
    // The OTLP-mirror helper on a disabled journal (no volume) is an empty report —
    // a cheap no-op, never a crash. (The enabled-journal round trip is covered by the
    // journal module's own tests; here we only need the headline math to be zero.)
    let report = default_window_report(&DecisionJournal::disabled());
    assert!(report.journal_empty);
    assert_eq!(report.would_act_count(), 0);
    assert_eq!(report.left_alone_count(), 0);
}

// ====================================================================
// The readiness / coverage panel (JEF-160)
// ====================================================================

#[test]
fn readiness_reports_each_input_from_live_state() {
    // Acceptance #1: every input shows present/absent/degraded from LIVE state.
    let r = derive_readiness(
        &full_config(),
        ModelHealth::Ok,
        &feeds_bake(3, 12),
        Some(SystemTime::now()),
    );
    assert!(!r.warming_up, "a pass completed");
    assert_eq!(rrow(&r, "model").state, InputState::Present);
    assert!(rrow(&r, "model").detail.contains("last call ok"));
    assert_eq!(rrow(&r, "kev").state, InputState::Present);
    assert!(rrow(&r, "kev").detail.contains("1500"));
    assert_eq!(rrow(&r, "advisory").state, InputState::Present);
    assert_eq!(rrow(&r, "falco").state, InputState::Present);
    assert!(rrow(&r, "falco").detail.contains("3 signals last pass"));
    assert_eq!(rrow(&r, "ebpf-agent").state, InputState::Present);
    assert!(
        rrow(&r, "ebpf-agent")
            .detail
            .contains("12 signals last pass")
    );
    assert_eq!(rrow(&r, "journal").state, InputState::Present);
    // Arm-state is posture, always present; reports the shadow default here.
    assert_eq!(rrow(&r, "arm-state").state, InputState::Present);
    assert!(rrow(&r, "arm-state").detail.contains("shadow"));
    // Fully covered ⇒ nothing unmet.
    assert!(!r.has_unmet(), "every input wired ⇒ no unmet inputs");
}

#[test]
fn absent_enrichment_inputs_are_marked_and_flagged_as_weakening() {
    // Acceptance #1: an absent input that weakens decisions is distinct. With nothing
    // configured, every enrichment input is Absent AND flagged `weakens_decisions`.
    let r = derive_readiness(
        &ReadinessConfig::default(),
        ModelHealth::Unknown,
        &BakeStats::default(),
        Some(SystemTime::now()),
    );
    for id in ["kev", "advisory", "falco", "ebpf-agent"] {
        assert_eq!(rrow(&r, id).state, InputState::Absent, "{id} absent");
        assert!(rrow(&r, id).weakens_decisions, "{id} weakens decisions");
    }
    // The journal absent is a durability gap, NOT a decision-weakening one.
    assert_eq!(rrow(&r, "journal").state, InputState::Absent);
    assert!(!rrow(&r, "journal").weakens_decisions);
    assert!(r.has_unmet());
}

#[test]
fn no_model_says_so_explicitly_and_that_no_calls_are_made() {
    // Acceptance #3: no model configured ⇒ explicit, and that no exploitability calls
    // are made.
    let r = derive_readiness(
        &ReadinessConfig {
            model_attached: false,
            ..full_config()
        },
        ModelHealth::Unknown,
        &feeds_bake(1, 1),
        Some(SystemTime::now()),
    );
    let model = rrow(&r, "model");
    assert_eq!(model.state, InputState::Absent);
    assert!(model.weakens_decisions);
    assert!(
        model.detail.contains("no exploitability calls")
            || model.detail.contains("no model configured"),
        "explicit that no calls are made: {}",
        model.detail
    );
    let panel = readiness_panel(&r);
    assert!(panel.contains("no exploitability calls are made"));
}

#[test]
fn attached_model_that_timed_out_is_degraded_not_absent() {
    // A model that's wired but whose last call timed out is Degraded — the model IS
    // configured, it just isn't answering. Distinct from Absent.
    let r = derive_readiness(
        &full_config(),
        ModelHealth::Timeout,
        &feeds_bake(1, 1),
        Some(SystemTime::now()),
    );
    let model = rrow(&r, "model");
    assert_eq!(model.state, InputState::Degraded);
    assert!(model.detail.contains("timed out"));
}

#[test]
fn readiness_warming_up_when_no_pass_has_completed() {
    // Cold start: no pass ⇒ warming_up, so the bake window reads as expected.
    let r = derive_readiness(
        &full_config(),
        ModelHealth::Unknown,
        &BakeStats::default(),
        None,
    );
    assert!(r.warming_up);
    let panel = readiness_panel(&r);
    assert!(
        panel.contains("warming up") && panel.contains("CPU model"),
        "cold-start note explains the bake window"
    );
}

#[test]
fn readiness_panel_states_are_in_text_not_glyph_only() {
    // Accessibility: the status word is IN TEXT for every row.
    let r = derive_readiness(
        &ReadinessConfig {
            model_attached: true,
            ..ReadinessConfig::default()
        },
        ModelHealth::Ok,
        &feeds_bake(0, 0),
        Some(SystemTime::now()),
    );
    let panel = readiness_panel(&r);
    // It's an ordered list with the state words present as text.
    assert!(panel.contains("<ol class=\"readiness\">"));
    assert!(panel.contains(">present<"));
    assert!(panel.contains(">absent<"));
    // An absent decision-weakening input carries the explicit tag.
    assert!(panel.contains("weakens decisions"));
    // The enable hint for an unmet input is shown.
    assert!(panel.contains("PROTECTOR_KEV_FILE"));
}

#[test]
fn first_run_checklist_replaces_the_empty_body_when_inputs_unmet() {
    // Acceptance #4: empty + unmet inputs ⇒ the instructional checklist, never a bare
    // page. No breach findings, nothing configured → the checklist, with each unmet
    // input linking its enable var.
    let r = derive_readiness(
        &ReadinessConfig::default(),
        ModelHealth::Unknown,
        &BakeStats::default(),
        Some(SystemTime::now()),
    );
    let html = render_html(
        &[],
        false,
        &BakeStats::default(),
        &[],
        Some(SystemTime::now()),
        &r,
    );
    assert!(
        html.contains(r#"class="firstrun""#) && html.contains(r#"ol class="checklist""#),
        "the instructional checklist replaces the empty findings body"
    );
    assert!(
        html.contains("PROTECTOR_ENGINE_MODEL"),
        "model enable linked"
    );
    assert!(
        html.contains("PROTECTOR_ADVISORY_FILE"),
        "advisory enable linked"
    );
    // It frames itself as a guided start, never a bare/error-looking page.
    assert!(html.contains("guided start, not a blank page"));
}

#[test]
fn clean_cluster_with_full_coverage_keeps_the_honest_empty_state() {
    // First-run discrimination: no findings BUT every input wired ⇒ NOT first-run; the
    // existing honest-empty idiom stands (a genuinely clean, fully-covered cluster).
    let r = derive_readiness(
        &full_config(),
        ModelHealth::Ok,
        &feeds_bake(2, 5),
        Some(SystemTime::now()),
    );
    assert!(!r.has_unmet());
    let html = render_html(
        &[],
        false,
        &feeds_bake(2, 5),
        &[],
        Some(SystemTime::now()),
        &r,
    );
    assert!(
        html.contains("no internet-facing service can reach a target"),
        "a clean, covered cluster keeps the honest-empty state"
    );
    assert!(
        !html.contains(r#"class="firstrun""#),
        "no first-run checklist when every input is covered"
    );
}

#[test]
fn render_html_includes_the_readiness_panel_section() {
    let r = derive_readiness(
        &full_config(),
        ModelHealth::Ok,
        &feeds_bake(1, 1),
        Some(SystemTime::now()),
    );
    // A breach finding is present so the body is the normal graph (not the checklist),
    // and the coverage panel still renders above it.
    let findings = vec![breach_finding("workload/app/Pod/web")];
    let html = render_html(
        &findings,
        false,
        &feeds_bake(1, 1),
        &[],
        Some(SystemTime::now()),
        &r,
    );
    // Renamed to "Readiness" inside the collapsed diagnostics region (JEF-175).
    assert!(html.contains("Readiness"));
    assert!(html.contains("<a href=\"/readiness\">json</a>"));
    assert!(html.contains("Model adjudicator"));
    assert!(html.contains("<ol class=\"readiness\">"));
}

#[test]
fn readiness_json_shape_matches_the_panel_data() {
    // Acceptance #2: `/readiness` returns the same data as JSON. Assert the serialized
    // shape: kebab-case states, the stable ids, and the live fields.
    let r = derive_readiness(
        &ReadinessConfig {
            model_attached: true,
            advisory_count: 7,
            ..ReadinessConfig::default()
        },
        ModelHealth::Ok,
        &feeds_bake(0, 4),
        Some(SystemTime::now()),
    );
    let json = serde_json::to_value(&r).expect("readiness serializes");
    assert_eq!(json["warming_up"], serde_json::json!(false));
    let inputs = json["inputs"].as_array().expect("inputs array");
    // The ids are stable and the model row serializes its present state in kebab-case.
    let model = inputs
        .iter()
        .find(|r| r["id"] == "model")
        .expect("model row in json");
    assert_eq!(model["state"], serde_json::json!("present"));
    assert_eq!(model["weakens_decisions"], serde_json::json!(true));
    let kev = inputs
        .iter()
        .find(|r| r["id"] == "kev")
        .expect("kev row in json");
    assert_eq!(kev["state"], serde_json::json!("absent"));
    let ebpf = inputs
        .iter()
        .find(|r| r["id"] == "ebpf-agent")
        .expect("ebpf row in json");
    assert_eq!(ebpf["state"], serde_json::json!("present"));
    assert!(
        ebpf["detail"].as_str().unwrap().contains("4 signals"),
        "live signal count is in the json detail"
    );
}

#[test]
fn findings_round_trips_the_readiness_config_and_model_health() {
    // The shared findings handle carries the config summary + live model health the
    // dashboard reads back — the engine writes them, the panel renders them.
    let findings = Findings::new();
    // Defaults: nothing configured, model unknown.
    assert!(!findings.readiness_config().model_attached);
    assert_eq!(findings.model_health(), ModelHealth::Unknown);
    findings.set_readiness_config(ReadinessConfig {
        model_attached: true,
        kev_count: 10,
        advisory_count: 5,
        journal_durable: true,
        armed: true,
    });
    findings.set_model_health(ModelHealth::Timeout);
    let cfg = findings.readiness_config();
    assert!(cfg.model_attached && cfg.armed && cfg.journal_durable);
    assert_eq!(cfg.kev_count, 10);
    assert_eq!(findings.model_health(), ModelHealth::Timeout);
}

// ===================================================================
// JEF-161 — verdict-first card + human /judgements view
// ===================================================================

#[test]
fn posture_chip_selection_per_verdict_state() {
    // The model's affirmation → [BREACH]; a "not exploitable" call → [SAFE]; no
    // verdict yet → [awaiting judgement]. The Debug form (capitalized) maps too.
    assert_eq!(Posture::of(None), Posture::Awaiting);
    assert_eq!(Posture::of(None).label(), "[awaiting judgement]");
    assert_eq!(
        Posture::of(Some("exploitable — RCE reaches the secret")),
        Posture::Breach
    );
    assert_eq!(
        Posture::of(Some("Exploitable(\"reason\")")),
        Posture::Breach
    );
    assert_eq!(Posture::Breach.label(), "[BREACH]");
    assert_eq!(
        Posture::of(Some("not exploitable — authorized RBAC, no CVE")),
        Posture::Safe
    );
    assert_eq!(Posture::of(Some("Refuted(\"benign\")")), Posture::Safe);
    assert_eq!(Posture::Safe.label(), "[SAFE]");
}
