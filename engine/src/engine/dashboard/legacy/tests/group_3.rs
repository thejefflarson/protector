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
fn what_to_do_per_disposition_class() {
    // AC #1/#3: the "what to do" line is derived per disposition class plus the
    // finding's path, no model call. Auto-eligible classes are unchanged.
    let auto = |d: &str| {
        finding(
            "workload/app/Pod/web",
            "secret/app/k",
            d,
            "can-read",
            true,
            None,
        )
    };
    assert_eq!(
        what_to_do(&auto(AUTO_ELIGIBLE)),
        "would cut in shadow; arm `network` to act"
    );
    assert_eq!(
        what_to_do(&auto("latent foothold — propose")),
        "would cut in shadow; arm `network` to act"
    );
    assert_eq!(
        what_to_do(&auto("structural — propose")),
        "would cut in shadow; arm `network` to act"
    );

    // durable-fix names the concrete mount and workload from the terminal hop.
    let mount = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "durable-fix PR",
        "can-read",
        true,
        None,
    );
    let m = what_to_do(&mount);
    assert!(
        m.contains("session-key"),
        "durable-fix names the secret: {m}"
    );
    assert!(m.contains("store"), "durable-fix names the workload: {m}");
    assert!(
        m.contains("re-checks next pass"),
        "durable-fix names self-recheck: {m}"
    );

    // durable-fix via an RBAC grant names the grant + the workload.
    let rbac = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "durable-fix PR",
        "can-do/get/secrets",
        true,
        None,
    );
    let r = what_to_do(&rbac);
    assert!(
        r.contains("get/secrets"),
        "durable-fix names the RBAC grant: {r}"
    );
    assert!(r.contains("Revoke"), "durable-fix says revoke: {r}");

    // forbidden names the blocking escape primitive edge + the auto-clear sentence.
    let mut forbidden = finding(
        "workload/app/Pod/web",
        "host/node/worker-1",
        "forbidden",
        "escapes-to/CAP_SYS_ADMIN",
        true,
        None,
    );
    forbidden.path[1].to = "host/node/worker-1".into();
    let fb = what_to_do(&forbidden);
    assert!(fb.starts_with("manual"), "forbidden stays manual: {fb}");
    assert!(
        fb.contains("escapes via CAP_SYS_ADMIN"),
        "forbidden names the edge: {fb}"
    );
    assert!(
        fb.contains("clears this finding on its own"),
        "forbidden states the finding auto-clears: {fb}"
    );

    // no-cut names the specific blocking hop + the auto-clear sentence.
    let no_cut = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "no-cut",
        "can-read",
        true,
        None,
    );
    let nc = what_to_do(&no_cut);
    assert!(nc.starts_with("manual"), "no-cut stays manual: {nc}");
    assert!(
        nc.contains("session-key"),
        "no-cut names the blocking edge target: {nc}"
    );
    assert!(
        nc.contains("clears this finding on its own"),
        "no-cut states the finding auto-clears: {nc}"
    );

    // An unknown/future disposition falls back to the safe, conservative default.
    assert!(what_to_do(&auto("unclassified")).starts_with("manual"));
    assert!(what_to_do(&auto("something-new")).starts_with("manual"));
}

#[test]
fn what_to_do_degrades_gracefully_when_path_empty() {
    // JEF-179: a finding whose path lacks the specific object names falls back to the
    // prior generic text rather than crashing or printing empty `<>` placeholders.
    let mut durable = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "durable-fix PR",
        "can-read",
        true,
        None,
    );
    durable.path.clear();
    assert_eq!(
        what_to_do(&durable),
        "revoke the grant / remove the mount (durable fix)"
    );
    assert!(!what_to_do(&durable).contains("<>"));

    let mut forbidden = durable.clone();
    forbidden.disposition = "forbidden".into();
    let fb = what_to_do(&forbidden);
    assert!(fb.starts_with("manual") && !fb.contains("<>"));
    assert!(fb.contains("clears this finding on its own"));

    let mut no_cut = durable.clone();
    no_cut.disposition = "no-cut".into();
    let nc = what_to_do(&no_cut);
    assert!(nc.starts_with("manual") && !nc.contains("<>"));
    assert!(nc.contains("clears this finding on its own"));
}

#[test]
fn what_to_do_escapes_injected_object_names() {
    // JEF-179: the injected names are untrusted node keys — HTML-escaped so a crafted
    // name can't break out of the rendered <div>.
    let mut durable = finding(
        "workload/app/Pod/web",
        "secret/app/<img src=x onerror=alert(1)>",
        "durable-fix PR",
        "can-read",
        true,
        None,
    );
    durable.path[1].to = "secret/app/<img src=x onerror=alert(1)>".into();
    let m = what_to_do(&durable);
    assert!(!m.contains("<img"), "raw tag must not survive: {m}");
    assert!(m.contains("&lt;img"), "name must be HTML-escaped: {m}");
}

#[test]
fn cve_id_extracts_a_cited_cve_and_handles_absence() {
    assert_eq!(
        cve_id("exploitable — CVE-2021-44228 is a remote RCE reaching the secret"),
        Some("CVE-2021-44228")
    );
    // Trailing punctuation is trimmed.
    assert_eq!(cve_id("see CVE-2024-3094."), Some("CVE-2024-3094"));
    // No CVE cited → None (the rail then reads "none cited", never implied-absent).
    assert_eq!(cve_id("not exploitable — authorized RBAC"), None);
    assert_eq!(cve_id("CVE-"), None);
}

#[test]
fn certainty_rail_carries_entry_and_relation_facts() {
    // The non-CVE rail facts (internet-reachability + the humanized terminal relation)
    // still come through; the CVE fact now reads from `EntryEvidence`, not the verdict.
    let f = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "no-cut",
        "can-read",
        true,
        Some("not exploitable — authorized RBAC, nothing concerning"),
    );
    let joined = proven_facts(&f.entry, std::slice::from_ref(&&f), &f.evidence).join(" ");
    assert!(
        joined.contains("internet-reachable"),
        "the entry's internet-reachability is a proven fact"
    );
    assert!(
        joined.contains("mounts (direct read)"),
        "the terminal relation is humanized into the rail"
    );
}

#[test]
fn certainty_rail_honest_empty_distinguishes_none_present_from_data_absent() {
    // AC #3: with no KEV/critical CVE on the entry, the rail says exactly that —
    // never "none cited / coverage unknown", and never claims the image is clean
    // (lower-severity CVEs are out of this subset, so coverage honesty is preserved).
    let f = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "no-cut",
        "can-read",
        true,
        // A prose verdict that happens to mention a CVE id MUST NOT drive the rail.
        Some("not exploitable — even though CVE-2021-44228 is on the image, RBAC denies it"),
    );
    assert!(
        f.evidence.cves.is_empty(),
        "this finding has no CVE evidence"
    );
    let joined = proven_facts(&f.entry, std::slice::from_ref(&&f), &f.evidence).join(" ");
    assert!(
        joined.contains("no KEV or critical CVE"),
        "honest-empty names the breach-relevant subset: {joined}"
    );
    assert!(
        joined.contains("lower-severity CVEs not shown"),
        "honest-empty keeps coverage-gap honesty (doesn't claim the image is clean): {joined}"
    );
    assert!(
        !joined.contains("none cited") && !joined.contains("coverage unknown"),
        "the verdict-scrape phrasing is gone: {joined}"
    );
    // The prose CVE id is NOT scraped into the rail fact.
    assert!(
        !joined.contains("CVE present"),
        "a CVE id in the prose must not fabricate a 'CVE present' fact: {joined}"
    );
}

#[test]
fn certainty_rail_reads_real_cve_counts_from_evidence() {
    // AC #1 + #2: the CVE fact derives from `EntryEvidence.cves`, with real counts —
    // and when the evidence block lists CVEs the rail NEVER says "none cited".
    let mut f = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "auto-eligible",
        "can-read",
        true,
        // Deliberately a verdict with NO CVE id — the rail must still report the CVEs,
        // proving it reads the evidence, not the prose.
        Some("exploitable — reachable over the network"),
    );
    f.evidence = EntryEvidence {
        cves: vec![
            cve("CVE-2021-0001", Severity::Critical, true),
            cve("CVE-2021-0002", Severity::Critical, false),
            cve("CVE-2021-0003", Severity::High, false),
        ],
        runtime: vec![],
    };
    let joined = proven_facts(&f.entry, std::slice::from_ref(&&f), &f.evidence).join(" ");
    assert!(
        joined.contains("CVE present") && joined.contains("<b>3</b> known vulns"),
        "the rail reports the real CVE count from evidence: {joined}"
    );
    assert!(
        joined.contains("2 critical") && joined.contains("1 KEV-listed"),
        "the rail tallies critical and KEV from the evidence: {joined}"
    );
    // The block below lists CVEs, so the rail must NOT claim none / unknown coverage.
    assert!(
        !joined.contains("none cited") && !joined.contains("coverage unknown"),
        "rail never says 'none cited' when CVEs exist on the entry: {joined}"
    );
}

#[test]
fn certainty_rail_cve_fact_matches_the_evidence_block_count() {
    // AC #4 (alignment): the rail's count and the evidence block's count agree because
    // both read the SAME `EntryEvidence`. A KEV-but-not-critical CVE still tallies KEV.
    let ev = EntryEvidence {
        cves: vec![cve("CVE-2022-0001", Severity::High, true)],
        runtime: vec![],
    };
    let fact = cve_fact(&ev);
    assert!(
        fact.contains("<b>1</b> known vuln "),
        "singular, count 1: {fact}"
    );
    assert!(
        fact.contains("1 KEV-listed"),
        "the KEV tally surfaces: {fact}"
    );
    assert!(
        !fact.contains("critical"),
        "no critical when none are: {fact}"
    );
    // The evidence block over the same data also reports one CVE.
    assert!(cve_block(&ev).contains("<b>1</b> CVE"));
}

#[test]
fn expanded_card_body_is_verdict_first_with_rail_todo_and_aria() {
    // JEF-202: the EXPANDED row body keeps today's full card UNCHANGED — the verbatim
    // model words lead, then the proof rail, then the what-to-do, then the graph (now
    // collapsed-by-default, with its aria-label preserved). The crisp tag lives in the
    // summary row (asserted separately).
    let f = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "durable-fix PR",
        "can-do/get/secrets",
        true,
        Some("not exploitable — authorized RBAC, no CVE"),
    );
    let html = card_body("workload/app/Pod/web", &[&f]);
    // Posture chip TEXT (not color/glyph alone).
    assert!(html.contains("[SAFE]"), "the posture chip carries text");
    assert!(html.contains("chip-safe"));
    // The model's words VERBATIM.
    assert!(html.contains("not exploitable — authorized RBAC, no CVE"));
    // The certainty rail and its compressed caption (JEF-200).
    assert!(html.contains("proven facts"));
    assert!(html.contains("internet-reachable"));
    // The disposition-derived "what to do" — naming the concrete RBAC grant and
    // workload from the path (JEF-179).
    assert!(html.contains("what to do:"));
    assert!(html.contains("Revoke the `get/secrets` RBAC grant"));
    assert!(html.contains("re-checks next pass"));
    // The graph's aria-label (data-aria on the <pre>, applied to the SVG by the JS).
    assert!(html.contains("data-aria=\""));
    assert!(html.contains("Attack-path graph"));
    // The verbatim verdict still leads the body, before the graph.
    let chip_at = html.find("[SAFE]").unwrap();
    let graph_at = html.find("class=\"mermaid\"").unwrap();
    assert!(chip_at < graph_at, "the verdict leads the card body");
}

#[test]
fn expanded_card_body_awaiting_state_is_honest_not_clear() {
    // Coverage-gap honesty: no verdict yet reads "awaiting", never "clear".
    let f = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "no-cut",
        "can-read",
        true,
        None,
    );
    let html = card_body("workload/app/Pod/web", &[&f]);
    assert!(html.contains("[awaiting judgement]"));
    assert!(html.contains("chip-awaiting"));
    assert!(html.contains("hasn't reached this entry yet"));
}

#[test]
fn safe_broad_row_reads_working_as_intended_and_calm_class() {
    // JEF-200/202: a Safe + broad endpoint's ROW carries the terse "working as intended"
    // next-lever tag and the calm row class — the verbose broad-lead paragraph is gone.
    // No retired severity/urgency wording, no internal ref.
    let entry = "workload/argocd/Pod/argocd-server";
    let fs = broad_findings(
        entry,
        Some("not exploitable — authorized RBAC, no CVE, no behavior"),
    );
    let refs: Vec<&Finding> = fs.iter().collect();
    let html = row_html(entry, &refs);
    // The terse next-lever tag carries the wide-reach reassurance now.
    assert!(
        html.contains("working as intended"),
        "the next-lever tag reads working as intended: {html}"
    );
    // The retired verbose paragraph is gone.
    assert!(
        !html.contains("Broadly privileged, working as intended"),
        "no verbose broad-lead paragraph: {html}"
    );
    assert!(!html.contains("broad-lead muted") && !html.contains("breadth muted"));
    // Calm row treatment.
    assert!(html.contains("f-calm"), "calm row class applied");
    // The expanded body still leads with the verbatim verdict tag.
    assert!(html.contains("[SAFE]"));
    // No retired severity-vs-urgency axis phrasing, no internal ref.
    assert!(!html.contains("breadth is severity"));
    assert!(!html.contains("severity, not urgency"));
    assert!(!html.contains("not urgency"));
    assert!(!html.contains("ADR-") && !html.contains("JEF-"));
}

#[test]
fn awaiting_broad_card_shows_the_honest_broad_note() {
    // The Awaiting + broad case keeps the honest one-line broad-reach note in the body,
    // and does NOT claim "working as intended" (the model hasn't judged it).
    let entry = "workload/argocd/Pod/argocd-server";
    let fs = broad_findings(entry, None);
    let refs: Vec<&Finding> = fs.iter().collect();
    let html = card_body(entry, &refs);
    assert!(
        html.contains("Broad reach — the model hasn't finished judging this one"),
        "honest broad-reach note: {html}"
    );
    assert!(
        html.contains("Wide access isn't itself a break-in"),
        "honest note frames wide access as not-a-break-in"
    );
    assert!(
        !html.contains("working as intended"),
        "an unjudged entry body does NOT claim working as intended"
    );
    // Awaiting is honest, not calm-green (only a Safe verdict earns the calm row).
    let row = row_html(entry, &refs);
    assert!(!row.contains("f-calm"), "awaiting is not a calm row");
    assert!(!row.contains("working as intended"));
    assert!(!html.contains("breadth is severity") && !html.contains("not urgency"));
    assert!(!html.contains("ADR-") && !html.contains("JEF-"));
}

#[test]
fn breach_broad_row_is_not_softened() {
    // Wide reach softens only a Safe/Awaiting row — a BREACH the model flagged keeps
    // no calm treatment and no "working as intended" lever, broad or not.
    let entry = "workload/argocd/Pod/argocd-server";
    let breach = broad_findings(
        entry,
        Some("exploitable — CVE-2021-44228 reaches everything"),
    );
    let brefs: Vec<&Finding> = breach.iter().collect();
    let bhtml = row_html(entry, &brefs);
    assert!(
        !bhtml.contains("working as intended"),
        "a breach is not softened"
    );
    assert!(!bhtml.contains("f-calm"), "a breach row is not calm-green");
    // No retired severity/urgency phrasing leaks anywhere.
    assert!(!bhtml.contains("breadth is severity"));
}

// ---- JEF-163: presentation-only "look at this first" attention ranking ----

#[test]
fn attention_rank_assigns_each_tier_from_existing_fields() {
    // 1. model-flagged exploitable → priority 0, Flagged.
    let flagged_f = ranked_finding(
        "e",
        "auto-eligible",
        false,
        Some("exploitable — CVE-2021-44228 chains to the secret"),
    );
    assert_eq!(attention_rank(&flagged_f), (0, Tier::Flagged));

    // 2. latent foothold WITH a cited CVE → priority 1, Watch.
    let latent_cve = ranked_finding(
        "e",
        "latent foothold — propose",
        false,
        Some("uncertain — CVE-2023-1234 may be reachable"),
    );
    assert_eq!(attention_rank(&latent_cve), (1, Tier::Watch));

    // 3. runtime-corroborated (no flag, no latent+CVE) → priority 2, Watch.
    let corrob = ranked_finding("e", "structural — propose", true, None);
    assert_eq!(attention_rank(&corrob), (2, Tier::Watch));

    // 4. everything else → priority 3, Context.
    let other = ranked_finding("e", "structural — propose", false, None);
    assert_eq!(attention_rank(&other), (3, Tier::Context));
}

#[test]
fn latent_foothold_without_a_cve_is_only_context() {
    // A latent foothold with NO cited CVE does NOT reach the watch tier — the CVE
    // signal is required for level 2 (the conservative reading of the missing
    // KEV/severity field: a cited CVE, not mere latency, promotes it).
    let latent_no_cve = ranked_finding(
        "e",
        "latent foothold — propose",
        false,
        Some("uncertain — no CVE cited, just reachable"),
    );
    assert_eq!(attention_rank(&latent_no_cve), (3, Tier::Context));
}

#[test]
fn flagged_sorts_above_a_larger_unflagged_endpoint() {
    // AC #2 (explicit): a flagged-exploitable endpoint ALWAYS sorts above a
    // larger-but-unflagged one — blast radius can never overcome a higher tier.
    let small_flagged = ranked_finding(
        "e1",
        "auto-eligible",
        false,
        Some("exploitable — reaches it"),
    );
    // A big, calm endpoint: 50 unflagged, corroborated paths.
    let big_calm: Vec<Finding> = (0..50)
        .map(|n| {
            let mut f = ranked_finding(
                "e2",
                "structural — propose",
                true,
                Some("not exploitable — authorized RBAC"),
            );
            f.objective = format!("secret/app/s-{n}");
            f
        })
        .collect();

    let small_refs = vec![&small_flagged];
    let big_refs: Vec<&Finding> = big_calm.iter().collect();
    let mut endpoints: Vec<(&str, Vec<&Finding>)> = vec![("e2", big_refs), ("e1", small_refs)];
    // Apply EXACTLY the render-site key: priority, then blast radius desc, then entry.
    endpoints.sort_by(|a, b| {
        endpoint_attention_rank(&a.1)
            .0
            .cmp(&endpoint_attention_rank(&b.1).0)
            .then_with(|| b.1.len().cmp(&a.1.len()))
            .then_with(|| a.0.cmp(b.0))
    });
    assert_eq!(
        endpoints[0].0, "e1",
        "the small flagged endpoint outranks the 50-path calm one"
    );
}

#[test]
fn blast_radius_only_tiebreaks_within_a_tier() {
    // Two endpoints in the SAME (context) tier: the larger graph sorts first.
    let make = |entry: &str, n: usize| -> Vec<Finding> {
        (0..n)
            .map(|i| {
                let mut f = ranked_finding(entry, "structural — propose", false, None);
                f.objective = format!("secret/app/{entry}-{i}");
                f
            })
            .collect()
    };
    let small = make("a", 2);
    let large = make("b", 9);
    let small_refs: Vec<&Finding> = small.iter().collect();
    let large_refs: Vec<&Finding> = large.iter().collect();
    // Same tier.
    assert_eq!(endpoint_attention_rank(&small_refs).1, Tier::Context);
    assert_eq!(endpoint_attention_rank(&large_refs).1, Tier::Context);

    let mut endpoints: Vec<(&str, Vec<&Finding>)> = vec![("a", small_refs), ("b", large_refs)];
    endpoints.sort_by(|a, b| {
        endpoint_attention_rank(&a.1)
            .0
            .cmp(&endpoint_attention_rank(&b.1).0)
            .then_with(|| b.1.len().cmp(&a.1.len()))
            .then_with(|| a.0.cmp(b.0))
    });
    assert_eq!(
        endpoints[0].0, "b",
        "the wider graph wins the in-tier tiebreak"
    );
}

#[test]
fn sort_is_stable_for_fully_equal_keys() {
    // Same priority AND same blast radius → the entry-key tiebreak gives a stable,
    // deterministic total order (so equal cards never shuffle between renders).
    let a = ranked_finding("aaa", "structural — propose", false, None);
    let b = ranked_finding("bbb", "structural — propose", false, None);
    let c = ranked_finding("ccc", "structural — propose", false, None);
    let mut endpoints: Vec<(&str, Vec<&Finding>)> =
        vec![("ccc", vec![&c]), ("aaa", vec![&a]), ("bbb", vec![&b])];
    endpoints.sort_by(|x, y| {
        endpoint_attention_rank(&x.1)
            .0
            .cmp(&endpoint_attention_rank(&y.1).0)
            .then_with(|| y.1.len().cmp(&x.1.len()))
            .then_with(|| x.0.cmp(y.0))
    });
    let order: Vec<&str> = endpoints.iter().map(|(e, _)| *e).collect();
    assert_eq!(order, vec!["aaa", "bbb", "ccc"]);
}

#[test]
fn endpoint_attention_rank_takes_the_worst_case_in_the_group() {
    // A card coalesces a group; one flagged path makes the whole card flagged.
    let calm = ranked_finding(
        "e",
        "structural — propose",
        true,
        Some("not exploitable — ok"),
    );
    let one_flagged = ranked_finding("e", "auto-eligible", false, Some("exploitable — boom"));
    let group = vec![&calm, &one_flagged];
    assert_eq!(endpoint_attention_rank(&group), (0, Tier::Flagged));
}

#[test]
fn context_tier_collapses_to_one_summary_row() {
    // JEF-202: the context tier collapses behind a SINGLE summary row (a row-toggle
    // button) that expands to its hidden ctx-rows; the row still carries the "context"
    // tier label, and the verbose body lives behind each row's own expand.
    let f = ranked_finding("workload/argo/Pod/ctx", "structural — propose", false, None);
    let html = render_html(
        &[f],
        false,
        &BakeStats::default(),
        &[],
        Some(SystemTime::now()),
        &ready_all_met(),
    );
    assert!(
        html.contains("ctx-summary"),
        "context collapses to a summary row"
    );
    assert!(html.contains("ctx-toggle"), "with a group toggle");
    assert!(
        html.contains("ctx-row"),
        "the context rows ride behind the group"
    );
    assert!(html.contains(">context<"), "the context tier label shows");
    // The context rows are HIDDEN by default (revealed by the group toggle).
    assert!(
        html.contains("<tr hidden class=\"ctx-row f-row"),
        "context rows are hidden until the group is opened: {html}"
    );
}

#[test]
fn rows_carry_their_tier_label_and_expand_control() {
    // JEF-202: each endpoint is a summary <tr> with the tier chip doubling as the
    // row-expand <button aria-expanded aria-controls>, plus a hidden detail <tr>.
    let f = ranked_finding(
        "workload/app/Pod/web",
        "auto-eligible",
        false,
        Some("exploitable — boom"),
    );
    let html = row_html("workload/app/Pod/web", &[&f]);
    assert!(html.contains(">flagged<"), "the flagged tier label shows");
    // A real button expand control, not a <details> wrapping a <tr>.
    assert!(
        html.contains("<button class=\"row-toggle\""),
        "button expand control"
    );
    assert!(
        html.contains("aria-expanded=\"false\""),
        "aria-expanded present"
    );
    assert!(
        html.contains("aria-controls=\""),
        "aria-controls wires the detail row"
    );
    // The detail row is hidden until expanded and spans every column.
    assert!(
        html.contains(&format!(
            "class=\"f-detail\" hidden><td colspan=\"{FINDINGS_COLS}\""
        )),
        "hidden colspan detail row: {html}"
    );

    let w = ranked_finding("workload/app/Pod/web", "structural — propose", true, None);
    let whtml = row_html("workload/app/Pod/web", &[&w]);
    assert!(whtml.contains(">watch<"), "the watch tier label shows");
}

#[test]
fn graph_is_collapsed_by_default_in_every_card_body() {
    // JEF-202: the graph stays collapsed-by-default for EVERY tier (the whole body is
    // already one expand behind its row), open on demand. The summary names the reach
    // when broad and the depth otherwise; the SVG a11y wiring survives the collapse.
    let entry = "workload/app/Pod/web";

    // Flagged: graph collapsed behind "show attack path (N hops)".
    let f = ranked_finding(
        entry,
        "latent foothold — propose",
        false,
        Some("exploitable — boom"),
    );
    let fhtml = card_body(entry, &[&f]);
    assert!(
        fhtml.contains("class=\"mermaid\""),
        "flagged still has a graph"
    );
    assert!(
        graph_is_collapsed(&fhtml),
        "flagged graph is collapsed by default"
    );
    assert!(
        fhtml.contains("show attack path"),
        "names the attack path: {fhtml}"
    );

    // Watch: also collapsed behind "show attack path (N hops)".
    let w = ranked_finding(entry, "structural — propose", true, None);
    let whtml = card_body(entry, &[&w]);
    assert!(graph_is_collapsed(&whtml), "watch graph is collapsed");
    assert!(whtml.contains("show attack path"));

    // Broad: collapsed, "show what it can reach (N targets)".
    let entry_b = "workload/argocd/Pod/argocd-server";
    let broad = broad_findings(entry_b, Some("not exploitable — authorized RBAC"));
    let brefs: Vec<&Finding> = broad.iter().collect();
    let bhtml = card_body(entry_b, &brefs);
    assert!(graph_is_collapsed(&bhtml), "broad graph is collapsed");
    assert!(
        bhtml.contains("show what it can reach"),
        "names the reach: {bhtml}"
    );
    assert!(
        bhtml.contains("data-aria=\""),
        "aria label preserved through collapse"
    );
}

#[test]
fn trust_line_is_absent_from_the_polled_region() {
    // JEF-200: the verbose "How protector decides" trust line is GONE from the live /
    // /fragment region entirely; only ONE compact "how it decides" pointer remains in
    // the static page header (outside #findings-region), never in the polled fragment.
    let trust_needle = "How protector decides:"; // the retired verbose line
    let f = ranked_finding(
        "workload/app/Pod/web",
        "latent foothold — propose",
        false,
        Some("exploitable — boom"),
    );
    // The /fragment (the polled region) carries no trust explainer at all.
    let frag = render_fragment(
        std::slice::from_ref(&f),
        false,
        Some(SystemTime::now()),
        &ready_all_met(),
    );
    assert!(
        !frag.contains(trust_needle) && !frag.contains("how protector decides"),
        "no trust line in the polled region: {frag}"
    );
    // The full page keeps ONE compact header pointer, outside the findings region.
    let html = render_html(
        &[f],
        false,
        &BakeStats::default(),
        &[],
        Some(SystemTime::now()),
        &ready_all_met(),
    );
    assert_eq!(
        html.matches("how protector decides").count(),
        1,
        "exactly one header pointer in the full page"
    );
    // The pointer is a header <details class="howto">, sitting AFTER the polled
    // findings-region container (which itself carries no trust copy — proven above).
    assert!(
        html.contains("<details class=\"howto\">"),
        "header pointer present"
    );
    let pointer_at = html.find("<details class=\"howto\">").unwrap();
    let region_at = html.find("id=\"findings-region\"").unwrap();
    assert!(
        region_at < pointer_at,
        "the pointer sits after the findings region container, in the static header"
    );
    // No internal refs leak from the new copy.
    assert!(!html.contains("ADR-") && !html.contains("JEF-"));
}

#[test]
fn render_html_splits_findings_into_attention_and_watching_tables() {
    // JEF-202: a flagged endpoint heads the "Needs attention" table; a context endpoint
    // lands behind the collapsed context group in the "Watching" table. Both are dense
    // tables with the tier labels in their rows. The flagged finding uses a NON-auto-
    // eligible disposition so it stays an endpoint row (auto-eligible findings are pulled
    // into the remediations section instead).
    let flagged = ranked_finding(
        "workload/app/Pod/web",
        "latent foothold — propose",
        false,
        Some("exploitable — boom"),
    );
    let context = {
        let mut f = ranked_finding("workload/argo/Pod/srv", "structural — propose", false, None);
        f.entry = "workload/argo/Pod/srv".into();
        f
    };
    let findings = vec![flagged, context];
    let html = render_html(
        &findings,
        false,
        &BakeStats::default(),
        &[],
        Some(SystemTime::now()),
        &ready(),
    );
    // Both answer-first sections render as tables; Needs attention comes first.
    let needs = html
        .find("Needs attention")
        .expect("needs-attention section");
    let watching = html.find("Watching").expect("watching section");
    assert!(needs < watching, "Needs attention precedes Watching");
    // Real table semantics with a header.
    assert!(html.contains("<table class=\"findings\">"), "dense table");
    assert!(html.contains("<th scope=\"col\">tier</th>"), "table header");
    assert!(html.contains(">flagged<"), "the flagged tier label appears");
    // The context-tier endpoint collapses behind the context group summary row.
    assert!(
        html.contains("ctx-summary") && html.contains("ctx-row"),
        "the context tier collapses to one group summary row"
    );
}
