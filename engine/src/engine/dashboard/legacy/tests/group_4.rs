#![allow(unused_imports)]
use super::*;
use crate::engine::dashboard::legacy::*;
use crate::engine::dashboard::page::FINDINGS_COLS;
use crate::engine::dashboard::page::{render_fragment, render_html};
use crate::engine::dashboard::{DASHBOARD_CSS, DASHBOARD_JS, default_window_report};
use crate::engine::graph::attack::{CREDENTIAL_ACCESS, EXPLOIT_PUBLIC_FACING};
use crate::engine::graph::{Advisory, NodeKey, Reachability, Severity, Vulnerability};
use crate::engine::reason::proof::Link;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[test]
fn table_is_primary_no_full_card_until_a_row_is_expanded() {
    // JEF-202: the dense table leads; the verbose card body (rail, evidence, what-to-do)
    // is ONLY in the hidden detail row, never rendered as a standalone open card.
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
    // The verbose body content exists, but only inside the hidden detail row.
    let body_at = html
        .find("what to do:")
        .expect("body present (in detail row)");
    let detail_at = html
        .find("class=\"f-detail\" hidden")
        .expect("hidden detail row");
    // The detail row opens BEFORE the body content it wraps.
    assert!(
        detail_at < body_at,
        "the card body lives inside the hidden detail row"
    );
    // No old-style standalone open endpoint card wrapper survives.
    assert!(!html.contains("card-context"), "no old card wrapper");
}

// ---- JEF-199: verdict gist = crisp tag + one decisive clause ----

#[test]
fn verdict_gist_tag_mirrors_posture() {
    // The tag is the Posture label, never the prose.
    let safe = finding_with_cves(Some("not exploitable — authorized RBAC"), vec![]);
    assert_eq!(
        verdict_gist(safe.verdict.as_deref(), &safe.evidence, &[&safe]).0,
        "[SAFE]"
    );
    let breach = finding_with_cves(Some("exploitable — RCE"), vec![]);
    assert_eq!(
        verdict_gist(breach.verdict.as_deref(), &breach.evidence, &[&breach]).0,
        "[BREACH]"
    );
    let awaiting = finding_with_cves(None, vec![]);
    assert_eq!(
        verdict_gist(
            awaiting.verdict.as_deref(),
            &awaiting.evidence,
            &[&awaiting]
        )
        .0,
        "[awaiting judgement]"
    );
}

#[test]
fn verdict_gist_prefers_a_cited_kev_or_critical_cve() {
    // A KEV CVE in the structured evidence wins the clause, naming the id + KEV.
    let f = finding_with_cves(
        Some("exploitable — reaches the secret via a long prose paragraph that should not appear"),
        vec![cve("CVE-2021-44228", Severity::Critical, true)],
    );
    let (tag, clause) = verdict_gist(f.verdict.as_deref(), &f.evidence, &[&f]);
    assert_eq!(tag, "[BREACH]");
    assert!(clause.contains("CVE-2021-44228"), "names the CVE: {clause}");
    assert!(clause.contains("KEV"), "flags KEV: {clause}");
    // The prose paragraph is NEVER the clause (it stays verbatim in the body).
    assert!(
        !clause.contains("long prose paragraph"),
        "not a prose dump: {clause}"
    );
}

#[test]
fn verdict_gist_falls_back_to_a_cited_cve_id_when_no_structured_cve() {
    // No structured CVE, but the verdict cites one → name it.
    let f = finding_with_cves(Some("uncertain — CVE-2023-1234 may be reachable"), vec![]);
    let (_, clause) = verdict_gist(f.verdict.as_deref(), &f.evidence, &[&f]);
    assert!(clause.contains("CVE-2023-1234"), "cites the id: {clause}");
}

#[test]
fn verdict_gist_reads_runtime_corroboration_when_no_cve() {
    let mut f = finding_with_cves(Some("exploitable — live shell"), vec![]);
    f.corroborated = true;
    let (_, clause) = verdict_gist(f.verdict.as_deref(), &f.evidence, &[&f]);
    assert_eq!(clause, "runtime-corroborated");
}

#[test]
fn verdict_gist_falls_back_to_the_terminal_reach_clause() {
    // No CVE, no corroboration → the deterministic terminal relation from the path.
    let entry = "workload/argocd/Pod/argocd-server";
    let fs: Vec<Finding> = (0..3)
        .map(|n| {
            let mut f = finding(
                entry,
                &format!("secret/argocd/secret-{n}"),
                "durable-fix PR",
                "can-do/get/secrets",
                true,
                Some("not exploitable — authorized RBAC"),
            );
            f.corroborated = false;
            f
        })
        .collect();
    let refs: Vec<&Finding> = fs.iter().collect();
    let ev = EntryEvidence::default();
    let (_, clause) = verdict_gist(Some("not exploitable — authorized RBAC"), &ev, &refs);
    assert!(clause.starts_with("reaches "), "reaches clause: {clause}");
    assert!(
        clause.contains("secret"),
        "names the objective kind: {clause}"
    );
    assert!(
        clause.contains("authorized RBAC"),
        "names the relation: {clause}"
    );
}

#[test]
fn verdict_gist_last_resort_truncates_the_first_clause() {
    // No structured fact and no path facts → truncate the verdict's first clause.
    let long = "uncertain because the analysis ran out of budget and a very long winded \
                explanation with no structured fact whatsoever keeps going and going past ninety";
    let ev = EntryEvidence::default();
    let (_, clause) = verdict_gist(Some(long), &ev, &[]);
    assert!(clause.ends_with('…'), "truncated with ellipsis: {clause}");
    assert!(clause.chars().count() <= 91, "respects the cap: {clause}");
}

#[test]
fn verdict_cell_is_a_tag_plus_clause_not_a_paragraph() {
    // JEF-199: the row's verdict cell shows the tag + one clause; the model's PARAGRAPH
    // is only in the expanded body (verbatim).
    let f = finding_with_cves(
        Some(
            "exploitable — a long verbatim model paragraph that explains the whole chain in detail",
        ),
        vec![cve("CVE-2021-44228", Severity::Critical, true)],
    );
    let row = row_html("workload/app/Pod/web", &[&f]);
    // The summary cell carries the tag + the crisp CVE clause.
    assert!(row.contains("c-verdict"), "verdict cell present");
    assert!(row.contains("[BREACH]"));
    assert!(row.contains("CVE-2021-44228"));
    // The paragraph is in the detail body, not the summary cell.
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

// ---- JEF-202: evidence glyphs + next-lever tag ----

#[test]
fn evidence_glyphs_render_compact_badges() {
    let ev = EntryEvidence {
        cves: vec![
            cve("CVE-2021-0001", Severity::Critical, true),
            cve("CVE-2021-0002", Severity::High, false),
        ],
        runtime: vec![],
    };
    let g = evidence_glyphs(&ev, true, false);
    assert!(g.contains("2 CVE"), "CVE count: {g}");
    assert!(g.contains("1·KEV"), "KEV badge: {g}");
    assert!(g.contains("1 crit"), "crit count: {g}");
    assert!(g.contains("◆live"), "live glyph from corroboration: {g}");
}

#[test]
fn evidence_glyphs_dash_when_none_unjudged_when_awaiting() {
    // No evidence, judged → an em dash.
    let g = evidence_glyphs(&EntryEvidence::default(), false, false);
    assert!(
        g.contains("—") && !g.contains("CVE"),
        "dash for no evidence: {g}"
    );
    // No evidence, awaiting → the honest "unjudged" (not an implied no-evidence).
    let g2 = evidence_glyphs(&EntryEvidence::default(), false, true);
    assert!(g2.contains("unjudged"), "awaiting reads unjudged: {g2}");
}

#[test]
fn next_lever_tag_keys_on_disposition() {
    let cases = [
        ("auto-eligible", "arm network"),
        ("latent foothold — propose", "arm network"),
        ("structural — propose", "arm network"),
        ("vetoed — propose", "arm network"),
        ("durable-fix PR", "durable fix"),
        ("forbidden", "manual (escape)"),
        ("no-cut", "manual (no cut)"),
        ("unclassified", "manual"),
    ];
    for (disp, expect) in cases {
        let f = finding("e", "secret/app/s", disp, "can-read", true, None);
        assert_eq!(next_lever_tag(&f), expect, "disposition {disp}");
    }
}

#[test]
fn row_open_state_persistence_hooks_are_present() {
    // JEF-202: the row-expand button state AND the lazy graph must survive the /fragment
    // swap — the dashboard module carries the row-toggle persistence machinery and
    // re-applies it after the swap, alongside the existing <details> machinery (not
    // reinvented). Since JEF-203 this module is the self-hosted /assets/dashboard.js,
    // so the behavior is asserted against the served asset (DASHBOARD_JS).
    let js = DASHBOARD_JS;
    // Row-toggle persistence keyed by the stable aria-controls id, in localStorage.
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
    // The hidden-row deferral so a graph in a closed row renders on first reveal.
    assert!(
        js.contains("closest('[hidden]')"),
        "graphs in a hidden row are deferred to first reveal"
    );
    // The existing <details> machinery is still there (not reinvented / clobbered).
    assert!(js.contains("function hydrate(root)") && js.contains("detailsKey"));
}

#[test]
fn judgements_html_renders_the_three_meta_states_with_prose_first() {
    // AC #3: prose-led, three honest meta-states, raw behind an expander.
    let rows = vec![
        // Normal: model answered → its prose verdict.
        full_judgement(
            "workload/app/Pod/web",
            "exploitable — RCE reaches the secret",
            Some("PROMPT TEXT the injection surface"),
            Some("the model raw reply"),
        ),
        // Pre-filter: prompt None → decided without the model.
        full_judgement(
            "workload/app/Pod/api",
            "Refuted(\"no promotion ground\")",
            None,
            None,
        ),
        // Timeout: reply None → safe fallback.
        full_judgement(
            "workload/app/Pod/cache",
            "Uncertain(\"model timed out\")",
            Some("PROMPT TEXT"),
            None,
        ),
    ];
    let html = render_judgements_html(&rows);

    // Prose verdict leads the normal card.
    assert!(html.contains("exploitable — RCE reaches the secret"));
    assert!(html.contains("[BREACH]"));
    // The three meta-states.
    assert!(html.contains("decided without the model (pre-filter)"));
    assert!(html.contains("model timed out — safe fallback"));
    // The raw prompt is behind an expander, not inline above the prose.
    assert!(html.contains("show full prompt"));
    assert!(html.contains("<details"));
    let prompt_at = html.find("PROMPT TEXT the injection surface").unwrap();
    let prose_at = html.find("exploitable — RCE reaches the secret").unwrap();
    assert!(
        prose_at < prompt_at,
        "the prose verdict comes before the raw prompt"
    );
    // The JSON link is documented on the page.
    assert!(html.contains("/judgements.json"));
}

#[test]
fn judgements_html_empty_state_is_honest() {
    let html = render_judgements_html(&[]);
    assert!(html.contains("no model judgements yet"));
    assert!(html.contains("hasn't reached"));
}

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
    // The JS wires data-aria → role="img" + aria-label on the rendered SVG. Since
    // JEF-203 that JS is the self-hosted /assets/dashboard.js asset (DASHBOARD_JS).
    assert!(DASHBOARD_JS.contains("setAttribute('role', 'img')"));
    assert!(DASHBOARD_JS.contains("setAttribute('aria-label', aria)"));
}

#[test]
fn judgements_json_shape_is_unchanged() {
    // The /judgements.json contract is the same Judgement shape as before JEF-161 —
    // entry, objectives, verdict, prompt, reply — so existing scrapers keep working.
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
    // The pre-filter / timeout meta-states serialize as JSON null.
    let pre = full_judgement("e", "Refuted(\"x\")", None, None);
    let pv = serde_json::to_value(&pre).unwrap();
    assert!(pv["prompt"].is_null());
    assert!(pv["reply"].is_null());
}

// ---- JEF-133: per-path CVE + runtime-alert evidence blocks ----

#[test]
fn cve_block_summarizes_count_and_top_severities() {
    let ev = EntryEvidence {
        cves: vec![
            cve("CVE-2021-0001", Severity::Critical, true),
            cve("CVE-2021-0002", Severity::High, false),
            cve("CVE-2021-0003", Severity::Critical, false),
        ],
        runtime: vec![],
    };
    let html = cve_block(&ev);
    // Count + per-severity tally, worst first.
    assert!(html.contains("<b>3</b> CVEs"), "count: {html}");
    assert!(
        html.contains("2 critical, 1 high"),
        "tally worst-first: {html}"
    );
    // Each id surfaces, with its severity and reachability.
    assert!(html.contains("CVE-2021-0001"));
    assert!(html.contains("reachability: not-observed"));
    // The KEV-listed CVE is badged.
    assert!(html.contains(">KEV<"), "KEV badge: {html}");
    // Labeled as the severity-input block (ADR-0016) in plain words.
    assert!(html.contains("how bad it would be if exploited"));
}

#[test]
fn cve_block_lists_long_sets_behind_a_details_expander() {
    let cves: Vec<CveEvidence> = (0..7)
        .map(|i| CveEvidence::from_vuln(&vuln(&format!("CVE-2021-000{i}"), Severity::High, false)))
        .collect();
    let ev = EntryEvidence {
        cves,
        runtime: vec![],
    };
    let html = cve_block(&ev);
    // The inline cap is small; the remainder hides behind a "show all" details.
    assert!(
        html.contains("<details><summary>show all 7 CVEs"),
        "expander: {html}"
    );
    // The expander still names every CVE (all 7 appear somewhere in the block).
    for i in 0..7 {
        assert!(
            html.contains(&format!("CVE-2021-000{i}")),
            "CVE {i} present"
        );
    }
}

#[test]
fn cve_block_empty_state_is_honest_not_implied_absent() {
    let html = cve_block(&EntryEvidence::default());
    assert!(
        html.contains("none on this service's image"),
        "honest none: {html}"
    );
    // Still a labeled block, never a missing/empty box.
    assert!(html.contains("how bad it would be if exploited"));
    // No phantom count or list.
    assert!(!html.contains("<ul>"), "no empty list: {html}");
}

#[test]
fn cve_block_renders_cwe_and_advisory_title() {
    let mut v = vuln("CVE-2021-44228", Severity::Critical, true);
    v.title = Some("Log4Shell remote code execution".into());
    v.advisory = Some(Advisory {
        summary: "deserialization".into(),
        cwe: vec!["CWE-502".into()],
        fix_ref: None,
    });
    v.fixed_version = Some("2.17.0".into());
    v.installed_version = Some("2.14.0".into());
    let html = cve_block(&EntryEvidence {
        cves: vec![CveEvidence::from_vuln(&v)],
        runtime: vec![],
    });
    assert!(html.contains("CWE-502"), "cwe surfaced: {html}");
    assert!(html.contains("Log4Shell"), "title surfaced: {html}");
    assert!(
        html.contains("fix available: 2.14.0 to 2.17.0"),
        "fix phrasing matches the prompt: {html}"
    );
}

#[test]
fn runtime_block_separates_corroborating_alerts_from_context_behaviors() {
    let ev = EntryEvidence {
        cves: vec![],
        runtime: vec![
            Behavior::Alert {
                rule: "Terminal shell in container".into(),
            },
            Behavior::NetworkConnection {
                peer: "10.0.0.5".into(),
                internet: false,
            },
        ],
    };
    let html = runtime_block(&ev);
    // The alert is seen live; the connection is background (behind a details).
    assert!(html.contains("SEEN LIVE"), "alert seen live: {html}");
    assert!(html.contains("Terminal shell in container"));
    assert!(
        html.contains("1 agent behavior (background, not seen exploited)"),
        "background count: {html}"
    );
    assert!(html.contains("connects to 10.0.0.5"));
    // Labeled as the live-activity block (ADR-0016) in plain words.
    assert!(html.contains("is it being exploited right now"));
}

#[test]
fn runtime_block_empty_state_is_honest() {
    let html = runtime_block(&EntryEvidence::default());
    assert!(
        html.contains("no live activity seen on this service"),
        "honest none: {html}"
    );
    assert!(html.contains("is it being exploited right now"));
    assert!(!html.contains("SEEN LIVE"));
}

#[test]
fn runtime_block_behaviors_without_an_alert_read_as_context_only() {
    // Agent behaviors with no Falco alert: context, never an implied corroboration.
    let ev = EntryEvidence {
        cves: vec![],
        runtime: vec![Behavior::SecretRead {
            secret: "db-password".into(),
        }],
    };
    let html = runtime_block(&ev);
    assert!(!html.contains("SEEN LIVE"), "no false live signal: {html}");
    assert!(html.contains("nothing seen happening live"));
    assert!(html.contains("reads secret db-password"));
}

#[test]
fn finding_carries_evidence_in_json_for_programmatic_use() {
    // A finding with both CVEs and a runtime alert: the /findings JSON must carry the
    // new fields (JEF-133 AC). Built via the render `finding` helper, then evidence set.
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
    };
    let v = serde_json::to_value(&f).unwrap();
    assert_eq!(v["evidence"]["cves"][0]["id"], "CVE-2021-44228");
    assert_eq!(v["evidence"]["cves"][0]["severity"], "critical");
    assert_eq!(v["evidence"]["cves"][0]["kev"], true);
    assert_eq!(v["evidence"]["cves"][0]["reachability"], "not-observed");
    // The runtime Behavior serializes via its wire tag (`kind`).
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
    };
    let refs = vec![&f];
    let html = card_body("workload/app/Pod/web", &refs);
    // Both ADR-0016 blocks present, clearly labeled and distinct (plain words).
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
    // Neither block is omitted; each shows its honest "none/unknown" (JEF-161 idiom).
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

    // Build a minimal graph: an entry workload runs an image carrying three CVEs —
    // one critical, one KEV-high, one plain medium (must be filtered out — the
    // dashboard surfaces the same KEV-or-critical bar the foothold/model uses).
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
    });
    let entry_key = wl.key();
    let e = g.upsert_node(wl);
    let img = g.upsert_node(Node::Image(Image {
        digest: "sha256:abc".into(),
        reference: Some("web:1".into()),
        trust: Trust::Unknown,
        vulnerabilities: vec![
            vuln("CVE-2021-0001", Severity::Critical, false),
            vuln("CVE-2021-0002", Severity::High, true), // KEV
            vuln("CVE-2021-0003", Severity::Medium, false), // filtered
        ],
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
        "plain medium filtered (same bar as the foothold): {ids:?}"
    );
    // The entry's runtime alert is pulled too (the live-corroboration signal).
    assert_eq!(f.evidence.runtime.len(), 1, "entry runtime signal carried");
    assert!(f.evidence.runtime[0].is_alert());
}

// ---- JEF-176: no ADR-/JEF- token leaks into operator-facing rendered output ----

/// AC #1: rendering every representative operator surface — a populated dashboard with
/// a finding card, /judgements, /report, the first-run checklist, and each banner
/// state — never emits an `ADR-` or `JEF-` substring.
#[test]
fn rendered_output_never_leaks_adr_or_jef_refs() {
    // The main dashboard, populated: a flagged card (Needs attention), a watched card,
    // remediations, and the full diagnostics region (readiness/attack-surface/sensor).
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

    // Armed and shadow, all-met and with-unmet readiness — exercises every banner
    // state (contained / needs-attention / unjudged / quiet) and the first-run path.
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

    // First-run checklist: no findings + an unmet input replaces the findings region.
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

    // /judgements — a model verdict, a pre-filter meta-state, and a timeout meta-state.
    let judgements = vec![
        Judgement {
            entry: "workload/app/Pod/web".into(),
            objectives: 3,
            verdict: "Exploitable(\"RCE\")".into(),
            prompt: Some("system: judge this chain".into()),
            reply: Some("exploitable".into()),
        },
        judgement("workload/api/Pod/svc"),
    ];
    let judgements_html = render_judgements_html(&judgements);
    assert_no_internal_refs("/judgements", &judgements_html);
    // The empty state too.
    assert_no_internal_refs("/judgements empty", &render_judgements_html(&[]));

    // /report — a populated would-have-acted diff and the empty state.
    let entries = vec![
        breach(
            "workload/app/Pod/web",
            "exploitable — CVE-2021-44228 RCE",
            60,
        ),
        breach("workload/api/Pod/svc", "not exploitable — cleared", 120),
    ];
    let report = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
    assert_no_internal_refs("/report", &render_report_html(&report));
    let empty_report = aggregate_report(&[], report_now(), WEEK, FIVE_MIN);
    assert_no_internal_refs("/report empty", &render_report_html(&empty_report));
}

/// AC #3: the finding card's attack steps lead with the plain technique name and keep
/// the MITRE code only inside an `<abbr>` tooltip — never bare on the line.
#[test]
fn killchain_leads_with_plain_name_mitre_code_in_abbr() {
    let f = rich_finding("workload/app/Pod/web", Some("exploitable — RCE"));
    let kc = killchain_html(&f);
    // Plain technique name leads.
    assert!(
        kc.contains("Unsecured Credentials"),
        "plain name present: {kc}"
    );
    assert!(
        kc.contains("internet-facing service"),
        "plain foothold phrasing: {kc}"
    );
    // The MITRE code is present but only inside an abbr title (not bare text).
    assert!(kc.contains("<abbr title="), "code tucked in abbr: {kc}");
    assert!(kc.contains("T1552"), "code available in tooltip: {kc}");
    // The card caption is plain English — "attack steps", never "kill chain".
    let card = remediation_card(&f, false);
    assert!(card.contains("attack steps:"), "plain label: {card}");
    assert!(!card.contains("kill chain"), "no jargon label: {card}");
}
