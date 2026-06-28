//! Tests for the findings DATA layer (JEF-205) — the pure Props-shaping migrated from the
//! legacy `cards`/`rows` string-concat helpers. These exercise the LOGIC (verdict gist,
//! evidence glyphs, tier/sort, the rail/evidence/graph data, what-to-do); the byte-stable
//! HTML is asserted by the render-level tests in `dashboard::tests` and the component modules.

use super::*;
use crate::engine::dashboard::model::{
    AUTO_ELIGIBLE, CveEvidence, EntryEvidence, Finding, PathStep,
};
use crate::engine::graph::{Behavior, Reachability, Severity, Vulnerability};

/// Build a Finding with a two-hop path entry →reaches→ store →&lt;rel&gt;→ objective.
fn finding(
    entry: &str,
    objective: &str,
    disposition: &str,
    terminal_rel: &str,
    verdict: Option<&str>,
) -> Finding {
    Finding {
        entry: entry.into(),
        objective: objective.into(),
        tactic: "TA0006".into(),
        tactic_name: "Credential Access".into(),
        technique: "T1552".into(),
        technique_name: "Unsecured Credentials".into(),
        foothold: false,
        corroborated: true,
        adjudicated: true,
        promoted: false,
        disposition: disposition.into(),
        cut: Some(format!("{entry} -[reaches/Tcp]-> workload/app/Pod/store")),
        breach_relevant: true,
        killchain: "T1190 → T1552".into(),
        verdict: verdict.map(str::to_string),
        path: vec![
            PathStep {
                from: entry.into(),
                relation: "reaches/Tcp".into(),
                to: "workload/app/Pod/store".into(),
            },
            PathStep {
                from: "workload/app/Pod/store".into(),
                relation: terminal_rel.into(),
                to: objective.into(),
            },
        ],
        evidence: EntryEvidence::default(),
        recency: None,
    }
}

fn cve(id: &str, severity: Severity, kev: bool) -> CveEvidence {
    CveEvidence::from_vuln(&Vulnerability {
        id: id.into(),
        severity,
        exploited_in_wild: kev,
        reachability: Reachability::NotObserved,
        ..Default::default()
    })
}

fn ranked_finding(
    entry: &str,
    disposition: &str,
    corroborated: bool,
    verdict: Option<&str>,
) -> Finding {
    let mut f = finding(
        entry,
        "secret/app/session-key",
        disposition,
        "can-do/get/secrets",
        verdict,
    );
    f.corroborated = corroborated;
    f.foothold = disposition.contains("latent foothold");
    f
}

// ---- posture / flagged --------------------------------------------------------------

#[test]
fn posture_maps_each_verdict_state() {
    assert_eq!(Posture::of(None), Posture::Awaiting);
    assert_eq!(Posture::of(None).label(), "[awaiting judgement]");
    assert_eq!(Posture::of(Some("exploitable — RCE")), Posture::Breach);
    assert_eq!(Posture::of(Some("Exploitable(\"x\")")), Posture::Breach);
    assert_eq!(Posture::Breach.label(), "[BREACH]");
    assert_eq!(Posture::of(Some("not exploitable — RBAC")), Posture::Safe);
    assert_eq!(Posture::of(Some("Refuted(\"x\")")), Posture::Safe);
    assert_eq!(Posture::Safe.label(), "[SAFE]");
    assert_eq!(Posture::Breach.tone(), "chip-breach");
    assert_eq!(Posture::Safe.tone(), "chip-safe");
    assert_eq!(Posture::Awaiting.tone(), "chip-awaiting");
}

#[test]
fn flagged_only_on_the_models_own_affirmation() {
    assert!(flagged(Some("exploitable — RCE")));
    assert!(flagged(Some("  Exploitable(\"x\")")));
    assert!(!flagged(Some("not exploitable — denied")));
    assert!(!flagged(None));
}

// ---- attention ranking (JEF-163) ----------------------------------------------------

#[test]
fn attention_rank_assigns_each_tier_from_existing_fields() {
    let flagged_f = ranked_finding(
        "e",
        AUTO_ELIGIBLE,
        false,
        Some("exploitable — CVE-2021-44228"),
    );
    assert_eq!(attention_rank(&flagged_f), (0, Tier::Flagged));

    let latent_cve = ranked_finding(
        "e",
        "latent foothold — propose",
        false,
        Some("uncertain — CVE-2023-1234 may be reachable"),
    );
    assert_eq!(attention_rank(&latent_cve), (1, Tier::Watch));

    let corrob = ranked_finding("e", "structural — propose", true, None);
    assert_eq!(attention_rank(&corrob), (2, Tier::Watch));

    let other = ranked_finding("e", "structural — propose", false, None);
    assert_eq!(attention_rank(&other), (3, Tier::Context));
}

#[test]
fn latent_foothold_without_a_cve_is_only_context() {
    let latent_no_cve = ranked_finding(
        "e",
        "latent foothold — propose",
        false,
        Some("uncertain — no CVE cited"),
    );
    assert_eq!(attention_rank(&latent_no_cve), (3, Tier::Context));
}

#[test]
fn endpoint_attention_rank_takes_the_worst_case_in_the_group() {
    let calm = ranked_finding(
        "e",
        "structural — propose",
        true,
        Some("not exploitable — ok"),
    );
    let one_flagged = ranked_finding("e", AUTO_ELIGIBLE, false, Some("exploitable — boom"));
    assert_eq!(
        endpoint_attention_rank(&[&calm, &one_flagged]),
        (0, Tier::Flagged)
    );
}

#[test]
fn tier_labels_and_classes() {
    assert_eq!(Tier::Flagged.label(), "flagged");
    assert_eq!(Tier::Watch.label(), "watch");
    assert_eq!(Tier::Context.label(), "context");
    assert_eq!(Tier::Flagged.chip_class(), "tier-flagged");
    assert_eq!(Tier::Watch.chip_class(), "tier-watch");
    assert_eq!(Tier::Context.chip_class(), "tier-context");
}

// ---- verdict gist (JEF-199) ---------------------------------------------------------

#[test]
fn verdict_gist_tag_mirrors_posture() {
    let ev = EntryEvidence::default();
    assert_eq!(
        verdict_gist(Some("not exploitable — RBAC"), &ev, &[]).0,
        "[SAFE]"
    );
    assert_eq!(
        verdict_gist(Some("exploitable — RCE"), &ev, &[]).0,
        "[BREACH]"
    );
    assert_eq!(verdict_gist(None, &ev, &[]).0, "[awaiting judgement]");
}

#[test]
fn verdict_gist_prefers_a_cited_kev_or_critical_cve() {
    let ev = EntryEvidence {
        cves: vec![cve("CVE-2021-44228", Severity::Critical, true)],
        runtime: vec![],
        ..Default::default()
    };
    let (tag, clause) = verdict_gist(
        Some("exploitable — long prose that should not appear"),
        &ev,
        &[],
    );
    assert_eq!(tag, "[BREACH]");
    assert!(
        clause.contains("CVE-2021-44228") && clause.contains("KEV"),
        "{clause}"
    );
    assert!(!clause.contains("long prose"), "not a prose dump: {clause}");
}

#[test]
fn verdict_gist_falls_back_to_a_cited_cve_id_then_corroboration_then_reach() {
    let ev = EntryEvidence::default();
    let (_, id) = verdict_gist(Some("uncertain — CVE-2023-1234 may be reachable"), &ev, &[]);
    assert!(id.contains("CVE-2023-1234"), "{id}");

    let mut f = finding(
        "workload/app/Pod/web",
        "secret/app/s",
        "durable-fix PR",
        "can-do/get/secrets",
        Some("exploitable — live shell"),
    );
    f.corroborated = true;
    let (_, clause) = verdict_gist(f.verdict.as_deref(), &f.evidence, &[&f]);
    assert_eq!(clause, "runtime-corroborated");

    let fs: Vec<Finding> = (0..3)
        .map(|n| {
            let mut g = finding(
                "workload/argocd/Pod/srv",
                &format!("secret/argocd/secret-{n}"),
                "durable-fix PR",
                "can-do/get/secrets",
                Some("not exploitable — authorized RBAC"),
            );
            g.corroborated = false;
            g
        })
        .collect();
    let refs: Vec<&Finding> = fs.iter().collect();
    let (_, reach) = verdict_gist(
        Some("not exploitable — authorized RBAC"),
        &EntryEvidence::default(),
        &refs,
    );
    assert!(reach.starts_with("reaches "), "{reach}");
    assert!(
        reach.contains("secret") && reach.contains("authorized RBAC"),
        "{reach}"
    );
}

#[test]
fn verdict_gist_last_resort_truncates_the_first_clause() {
    let long = "uncertain because the analysis ran out of budget and a very long winded \
                explanation with no structured fact whatsoever keeps going and going past ninety";
    let (_, clause) = verdict_gist(Some(long), &EntryEvidence::default(), &[]);
    assert!(clause.ends_with('…'), "{clause}");
    assert!(clause.chars().count() <= 91, "{clause}");
}

#[test]
fn cve_id_extracts_a_cited_cve_and_handles_absence() {
    assert_eq!(
        cve_id("exploitable — CVE-2021-44228 is a remote RCE"),
        Some("CVE-2021-44228")
    );
    assert_eq!(cve_id("see CVE-2024-3094."), Some("CVE-2024-3094"));
    assert_eq!(cve_id("not exploitable — authorized RBAC"), None);
    assert_eq!(cve_id("CVE-"), None);
}

// ---- evidence glyphs (JEF-202) ------------------------------------------------------

#[test]
fn glyph_props_count_cve_kev_crit_and_live() {
    let ev = EntryEvidence {
        cves: vec![
            cve("CVE-2021-0001", Severity::Critical, true),
            cve("CVE-2021-0002", Severity::High, false),
        ],
        runtime: vec![],
        ..Default::default()
    };
    let g = glyph_props(&ev, true, false);
    assert_eq!(
        (g.cves, g.kev, g.crit, g.live, g.awaiting),
        (2, 1, 1, true, false)
    );

    let none = glyph_props(&EntryEvidence::default(), false, true);
    assert_eq!((none.cves, none.live, none.awaiting), (0, false, true));
}

// ---- next lever + what-to-do (JEF-202 / JEF-179 / JEF-225) --------------------------

/// JEF-225: advice is gated on the model's POSTURE. For a FLAGGED breach the lever names the
/// next step in plain words; the disposition only chooses WHICH plain word.
#[test]
fn next_lever_tag_for_a_breach_is_plain_per_disposition() {
    let cases = [
        (AUTO_ELIGIBLE, "arm network"),
        ("latent foothold — propose", "arm network"),
        ("durable-fix PR", "permanent fix"),
        ("forbidden", "fix by hand (escape)"),
        ("no-cut", "fix by hand"),
        ("unclassified", "fix by hand"),
    ];
    for (disp, expect) in cases {
        let f = finding("e", "secret/app/s", disp, "can-read", None);
        assert_eq!(next_lever_tag(&f, Posture::Breach), expect, "{disp}");
    }
}

/// JEF-225 (complaints 1 & 3): a NON-breach finding never shows a remediation verb in the
/// lever cell — every posture other than Breach collapses to the em-dash, regardless of the
/// mechanical disposition (the argocd SAFE+RBAC case is `durable-fix PR` + Safe here).
#[test]
fn next_lever_tag_is_em_dash_for_every_non_breach_posture() {
    let dispositions = [
        AUTO_ELIGIBLE,
        "durable-fix PR",
        "forbidden",
        "no-cut",
        "unclassified",
    ];
    for disp in dispositions {
        let f = finding("e", "secret/app/s", disp, "can-do/get/secrets", None);
        assert_eq!(next_lever_tag(&f, Posture::Safe), "—", "safe/{disp}");
        assert_eq!(
            next_lever_tag(&f, Posture::Awaiting),
            "—",
            "awaiting/{disp}"
        );
    }
}

#[test]
fn what_to_do_per_disposition_class_for_a_breach() {
    let auto = finding(
        "workload/app/Pod/web",
        "secret/app/k",
        AUTO_ELIGIBLE,
        "can-read",
        None,
    );
    assert_eq!(
        what_to_do(&auto, Posture::Breach).as_deref(),
        Some("would cut in shadow; arm `network` to act")
    );

    let rbac = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "durable-fix PR",
        "can-do/get/secrets",
        None,
    );
    let r = what_to_do(&rbac, Posture::Breach).expect("breach has advice");
    assert!(
        r.starts_with("Permanent fix")
            && r.contains("get/secrets")
            && r.contains("revoke")
            && r.contains("re-checks next pass"),
        "{r}"
    );

    let mut forbidden = finding(
        "workload/app/Pod/web",
        "host/node/worker-1",
        "forbidden",
        "escapes-to/CAP_SYS_ADMIN",
        None,
    );
    forbidden.path[1].to = "host/node/worker-1".into();
    let fb = what_to_do(&forbidden, Posture::Breach).expect("breach has advice");
    assert!(
        fb.starts_with("Fix by hand")
            && fb.contains("escapes via CAP_SYS_ADMIN")
            && fb.contains("clears this finding on its own"),
        "{fb}"
    );

    let no_cut = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "no-cut",
        "can-read",
        None,
    );
    let nc = what_to_do(&no_cut, Posture::Breach).expect("breach has advice");
    assert!(
        nc.starts_with("No automatic fix")
            && nc.contains("session-key")
            && nc.contains("clears this finding on its own"),
        "{nc}"
    );

    let unclassified = what_to_do(
        &finding("e", "secret/app/k", "unclassified", "can-read", None),
        Posture::Breach,
    )
    .expect("breach has advice");
    assert!(
        unclassified.starts_with("No automatic fix"),
        "{unclassified}"
    );

    // JEF-225: no raw mechanical-disposition token reaches the rendered advice text.
    for token in ["no-cut", "durable-fix PR", "unclassified", "manual"] {
        for disp in [
            AUTO_ELIGIBLE,
            "durable-fix PR",
            "forbidden",
            "no-cut",
            "unclassified",
        ] {
            let f = finding("e", "secret/app/s", disp, "can-do/get/secrets", None);
            let advice = what_to_do(&f, Posture::Breach).unwrap_or_default();
            assert!(
                !advice.contains(token),
                "disposition {disp} leaked raw token {token:?}: {advice}"
            );
        }
    }
}

/// JEF-225 core rule: a finding the model did NOT flag as a breach gets NO advice — neither a
/// `what_to_do` line nor a lever verb — for EVERY non-breach posture and disposition.
#[test]
fn what_to_do_is_none_for_every_non_breach_posture() {
    let dispositions = [
        AUTO_ELIGIBLE,
        "durable-fix PR",
        "forbidden",
        "no-cut",
        "unclassified",
    ];
    for disp in dispositions {
        let f = finding("e", "secret/app/s", disp, "can-do/get/secrets", None);
        assert_eq!(what_to_do(&f, Posture::Safe), None, "safe/{disp}");
        assert_eq!(what_to_do(&f, Posture::Awaiting), None, "awaiting/{disp}");
    }
}

#[test]
fn what_to_do_degrades_gracefully_when_path_empty() {
    let mut durable = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "durable-fix PR",
        "can-read",
        None,
    );
    durable.path.clear();
    assert_eq!(
        what_to_do(&durable, Posture::Breach).as_deref(),
        Some("Permanent fix: revoke the grant / remove the mount, then protector re-checks.")
    );
    let mut no_cut = durable.clone();
    no_cut.disposition = "no-cut".into();
    assert!(
        what_to_do(&no_cut, Posture::Breach)
            .unwrap()
            .contains("change the workload by hand")
    );
    // Still nothing for a non-breach even with no path.
    assert_eq!(what_to_do(&durable, Posture::Safe), None);
}

// ---- rail / evidence / graph data ---------------------------------------------------

#[test]
fn rail_facts_carry_entry_relation_and_cve_fact() {
    let mut f = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "auto-eligible",
        "can-read",
        Some("exploitable — reachable"),
    );
    f.evidence = EntryEvidence {
        cves: vec![
            cve("CVE-2021-0001", Severity::Critical, true),
            cve("CVE-2021-0002", Severity::Critical, false),
            cve("CVE-2021-0003", Severity::High, false),
        ],
        runtime: vec![],
        ..Default::default()
    };
    let rail = rail_facts(&f.entry, &[&f], &f.evidence);
    // `short` drops only the kind prefix (first path segment), per `NodeKey::short_of`.
    assert_eq!(rail.entry_short, "app/Pod/web");
    assert!(
        rail.relations.iter().any(|r| r == "mounts (direct read)"),
        "{:?}",
        rail.relations
    );
    assert_eq!(
        rail.cve,
        CveFact::Present {
            n: 3,
            critical: 2,
            kev: 1
        }
    );

    // No CVE evidence ⇒ the honest-empty CveFact::None (never scraped from prose).
    let g = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "no-cut",
        "can-read",
        Some("not exploitable — even though CVE-2021-44228 is on the image, RBAC denies it"),
    );
    assert_eq!(rail_facts(&g.entry, &[&g], &g.evidence).cve, CveFact::None);
}

#[test]
fn cve_block_props_sort_tally_and_split() {
    let ev = EntryEvidence {
        cves: (0..7)
            .map(|i| cve(&format!("CVE-2021-000{i}"), Severity::High, false))
            .collect(),
        runtime: vec![],
        ..Default::default()
    };
    let block = cve_block_props(&ev).expect("present");
    assert_eq!(block.n, 7);
    assert_eq!(block.inline.len(), CVE_INLINE_CAP);
    assert_eq!(block.rest.len(), 7 - CVE_INLINE_CAP);
    assert_eq!(block.tally, vec![("high", 7)]);
    assert!(
        cve_block_props(&EntryEvidence::default()).is_none(),
        "empty ⇒ honest-empty"
    );
}

#[test]
fn runtime_block_props_split_corroborating_from_context() {
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
        ..Default::default()
    };
    let rt = runtime_block_props(&ev);
    assert_eq!(rt.corroborating.len(), 1);
    assert!(rt.corroborating[0].contains("Terminal shell"));
    assert_eq!(rt.context.len(), 1);
    assert!(rt.context[0].1.contains("10.0.0.5"));
}

#[test]
fn detail_props_collapse_fanout_by_tier_and_set_broad_calm() {
    let entry = "workload/argocd/Pod/argocd-server";
    let fs: Vec<Finding> = (0..25)
        .map(|n| {
            finding(
                entry,
                &format!("secret/argocd/secret-{n}"),
                "durable-fix PR",
                "can-do/get/secrets",
                Some("not exploitable — authorized RBAC"),
            )
        })
        .collect();
    let refs: Vec<&Finding> = fs.iter().collect();
    let (detail, meta) = detail_props(entry, &refs);
    assert_eq!(meta.objectives, 25);
    assert!(meta.calm, "broad + safe ⇒ calm");
    assert_eq!(detail.broad_lead, BroadLead::Calm);
    assert!(detail.graph.broad);
    // 25 terminal objectives share one (from, relation, kind) group ⇒ one aggregate edge.
    assert_eq!(
        detail.graph.fanouts.len(),
        1,
        "fan-out collapses to one aggregate group"
    );
    assert_eq!(detail.graph.fanouts[0].count, 25);

    // Awaiting + broad ⇒ the honest note, not calm.
    let awaiting: Vec<Finding> = (0..25)
        .map(|n| {
            finding(
                entry,
                &format!("secret/argocd/secret-{n}"),
                "durable-fix PR",
                "can-do/get/secrets",
                None,
            )
        })
        .collect();
    let arefs: Vec<&Finding> = awaiting.iter().collect();
    let (adet, ameta) = detail_props(entry, &arefs);
    assert!(!ameta.calm);
    assert_eq!(adet.broad_lead, BroadLead::AwaitingNote);
}

#[test]
fn endpoint_props_carry_row_cells_and_detail() {
    let f = ranked_finding(
        "workload/app/Pod/web",
        "latent foothold — propose",
        false,
        Some("exploitable — boom"),
    );
    let props = endpoint_props("workload/app/Pod/web", &[&f], Tier::Flagged, None);
    assert_eq!(props.row.tier, Tier::Flagged);
    assert_eq!(props.row.row_id, "row-workload-app-Pod-web");
    assert_eq!(props.row.detail_id, "row-workload-app-Pod-web-detail");
    assert_eq!(props.row.entry_short, "app/Pod/web");
    assert_eq!(props.row.verdict_tag, "[BREACH]");
    assert_eq!(props.detail.posture, Posture::Breach);
}

#[test]
fn remediation_props_dash_the_cut_edge() {
    let mut f = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        AUTO_ELIGIBLE,
        "can-read",
        Some("exploitable — RCE"),
    );
    f.foothold = true;
    f.cut = Some("workload/app/Pod/web -[reaches/Tcp]-> workload/app/Pod/store".into());
    let props = remediation_props(&f, false);
    let cut_edge = props
        .graph
        .edges
        .iter()
        .find(|e| e.cut)
        .expect("a dashed cut edge");
    assert_eq!(cut_edge.edge_label, "✂ NetworkPolicy cut");
    assert!(!props.armed);
    assert_eq!(props.killchain.technique, "T1552");
}

#[test]
fn row_id_is_html_id_safe_and_stable() {
    assert_eq!(row_id("workload/app/Pod/web"), "row-workload-app-Pod-web");
    assert_eq!(row_id("a b/c"), "row-a-b-c");
}

#[test]
fn humanize_and_reach_relations() {
    assert_eq!(humanize_relation("can-read"), "mounts (direct read)");
    assert_eq!(
        humanize_relation("can-do/get/secrets"),
        "RBAC get secrets (API)"
    );
    assert_eq!(reach_relation_phrase("can-read"), "a mounted secret");
    assert_eq!(
        reach_relation_phrase("can-do/get/secrets"),
        "authorized RBAC"
    );
}
