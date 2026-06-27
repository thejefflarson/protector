#![allow(unused_imports)]
use super::*;
use crate::engine::dashboard::model::*;
use crate::engine::dashboard::page::FINDINGS_COLS;
use crate::engine::dashboard::page::{render_fragment, render_html};
use crate::engine::dashboard::view_model::readiness_data::*;
use crate::engine::dashboard::view_model::report_data::*;
use crate::engine::dashboard::{DASHBOARD_CSS, DASHBOARD_JS, default_window_report};
use crate::engine::graph::attack::{CREDENTIAL_ACCESS, EXPLOIT_PUBLIC_FACING};
use crate::engine::graph::{
    Advisory, NodeKey, Reachability, SecurityGraph, Severity, Vulnerability,
};
use crate::engine::reason::adjudicate::Verdict;
use crate::engine::reason::proof::{Link, ProvenChain};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[test]
fn judgement_log_is_newest_first_and_capped() {
    let log = JudgementLog::new();
    // Overflow the ring by one so the oldest is evicted.
    for n in 0..=JudgementLog::CAP {
        log.record(judgement(&format!("entry-{n}")));
    }
    let snap = log.snapshot();
    assert_eq!(snap.len(), JudgementLog::CAP, "ring is bounded by CAP");
    assert_eq!(
        snap[0].entry,
        format!("entry-{}", JudgementLog::CAP),
        "newest judgement is first"
    );
    assert_eq!(
        snap.last().unwrap().entry,
        "entry-1",
        "the oldest (entry-0) was evicted"
    );
}

/// JEF-157 (the no-lag fix): a verdict written to the shared store is visible on the
/// `/findings` snapshot WITHOUT re-publishing the rows. This is exactly the bug the
/// ticket fixes — `/findings` used to update only at the end-of-pass re-publish, so a
/// just-judged entry showed in `/judgements` but not yet on the dashboard. With the
/// single store, the same rows published once reflect the verdict the instant it lands.
#[test]
fn findings_snapshot_reflects_a_store_write_without_republishing() {
    let findings = Findings::new();
    let verdicts = findings.verdicts();

    // Publish the rows ONCE, with no verdict (what the engine does before judging).
    findings.replace(vec![breach_finding("workload/app/Pod/web")]);
    assert!(
        findings.snapshot()[0].verdict.is_none(),
        "no verdict before the model has judged the entry"
    );

    // The model judges the entry: write its verdict to the store. NO `replace` follows.
    verdicts.set_display(
        "workload/app/Pod/web",
        Verdict::Exploitable("RCE reaches the secret".into()),
    );

    // The verdict is visible on the very next snapshot — no re-publish needed.
    let snap = findings.snapshot();
    assert_eq!(
        snap[0].verdict.as_deref(),
        Some("exploitable — RCE reaches the secret"),
        "a store write surfaces on /findings immediately, mid-pass"
    );
}

/// JEF-157 carry-forward: a journal-restored verdict shows until a live verdict
/// supersedes it, and the live verdict then wins — the precedence the engine used to
/// apply per-chain at publish time, now in one place.
#[test]
fn restored_verdict_shows_until_a_live_verdict_supersedes_it() {
    let store = VerdictStore::new();
    store.seed_restored(
        "workload/app/Pod/web",
        "exploitable — from before restart".into(),
    );
    assert_eq!(
        store.display_summary("workload/app/Pod/web").as_deref(),
        Some("exploitable — from before restart"),
        "the restored verdict shows on boot"
    );

    // A live verdict supersedes the restored one (and clears the restored slot).
    store.set_display(
        "workload/app/Pod/web",
        Verdict::Refuted("benign on review".into()),
    );
    assert_eq!(
        store.display_summary("workload/app/Pod/web").as_deref(),
        Some("not exploitable — benign on review"),
        "a live verdict supersedes the restored one"
    );
}

/// JEF-157 cache: a decisive verdict is served from the store for a matching
/// fingerprint (no re-judge), and a changed fingerprint misses (re-judge).
#[test]
fn cache_serves_a_matching_fingerprint_and_misses_a_changed_one() {
    let store = VerdictStore::new();
    store.cache_decisive("e", "fp-1".into(), Verdict::Refuted("r".into()));
    assert!(
        store.cached_for("e", "fp-1").is_some(),
        "an unchanged fingerprint serves the cached verdict"
    );
    assert!(
        store.cached_for("e", "fp-2").is_none(),
        "a changed fingerprint misses (re-judge)"
    );
    assert!(
        store.cached_for("other", "fp-1").is_none(),
        "an unknown entry misses"
    );
}

#[test]
fn reversion_log_is_newest_first_and_capped() {
    // The recent-reversions ring (JEF-141) is bounded and newest-first, like the
    // judgement ring — so a restart-seeded history can't grow unbounded.
    let log = ReversionLog::new();
    for n in 0..=ReversionLog::CAP {
        log.record(reversion(&format!("cut-{n}")));
    }
    let snap = log.snapshot();
    assert_eq!(snap.len(), ReversionLog::CAP, "ring is bounded by CAP");
    assert_eq!(
        snap[0].cut,
        format!("cut-{}", ReversionLog::CAP),
        "newest reversion is first"
    );
    assert_eq!(snap.last().unwrap().cut, "cut-1", "the oldest was evicted");
}

#[test]
fn relative_time_renders_human_freshness() {
    // The "last pass NNs ago" freshness (JEF-141): None reads as waiting, a recent
    // time as seconds, older as minutes/hours — never a raw timestamp.
    assert_eq!(relative_time(None), "waiting for first pass");
    assert_eq!(relative_time(Some(SystemTime::now())), "just now");
    let ninety_s = SystemTime::now() - std::time::Duration::from_secs(90);
    assert_eq!(relative_time(Some(ninety_s)), "1m ago");
    let two_h = SystemTime::now() - std::time::Duration::from_secs(7200);
    assert_eq!(relative_time(Some(two_h)), "2h ago");
}

// `reversions_panel_shows_lifted_cuts_or_a_quiet_default` migrated to
// `components::panels::reversions` (JEF-206).

#[test]
fn render_html_shows_the_freshness_line_and_reversions_section() {
    // The dashboard surfaces "last pass NNs ago" and a recent-reversions section
    // (JEF-141), both populated.
    let revs = vec![ReversionRecord {
        cut: "workload/app/Pod/web -[reaches/Tcp]-> workload/app/Pod/db".into(),
        reason: "no proven chain still justifies this control".into(),
        at_ms: unix_now_ms(),
    }];
    let html = render_html(
        &[],
        false,
        &BakeStats::default(),
        &revs,
        Some(SystemTime::now()),
        &ready(),
    );
    assert!(
        html.contains("last pass <b>just now</b>"),
        "freshness line present"
    );
    assert!(
        html.contains("Recently lifted"),
        "lifted-cuts section header present"
    );
    assert!(
        html.contains("no proven chain still justifies"),
        "the lifted cut's reason is shown"
    );
}

// -- JEF-159: the glanceable cluster status banner --------------------------------

#[test]
fn render_html_includes_the_banner_and_nav_without_a_meta_refresh() {
    // The dashboard leads with the status banner, has a persistent nav with the
    // current page marked, and (JEF-180) does NOT do a full-page meta-refresh.
    let html = render_html(
        &[],
        false,
        &BakeStats::default(),
        &[],
        Some(SystemTime::now()),
        &ready(),
    );
    // Banner is the first child of <body>, above <h1>.
    let body_at = html.find("<body>").expect("body present");
    let banner_at = html.find("class=\"banner").expect("banner present");
    let h1_at = html.find("<h1>").expect("h1 present");
    assert!(
        banner_at > body_at && banner_at < h1_at,
        "banner above <h1>"
    );
    assert!(
        html.contains("role=\"status\""),
        "banner is a status region"
    );
    // Trimmed nav (JEF-175): only dashboard · why · shadow log, with aria-current on
    // the dashboard. `/readiness`, `/bake`, and `/reversions` are de-listed from nav.
    assert!(html.contains("<a href=\"/\" aria-current=\"page\">dashboard</a>"));
    assert!(html.contains("<a href=\"/judgements\">why</a>"));
    assert!(html.contains("<a href=\"/report\">shadow log</a>"));
    let nav_at = html.find("class=\"nav\"").expect("nav present");
    let nav_end = html[nav_at..].find("</nav>").expect("nav closes") + nav_at;
    let nav = &html[nav_at..nav_end];
    assert!(
        !nav.contains("href=\"/reversions\""),
        "reversions de-listed"
    );
    assert!(!nav.contains("href=\"/readiness\""), "readiness de-listed");
    assert!(!nav.contains("href=\"/bake\""), "bake de-listed");
    assert_eq!(nav.matches("<a ").count(), 3, "exactly three nav items");
    // JEF-180 AC #2: the 30s full-page meta-refresh is GONE — no http-equiv refresh
    // of any kind. A timer must never reload the whole document (resetting scroll,
    // focus, and every <details>).
    assert!(
        !html.contains("http-equiv=\"refresh\""),
        "no meta-refresh of any kind"
    );
    assert!(
        !html.contains("http-equiv"),
        "no http-equiv directive at all"
    );
}

/// JEF-180 AC #1, carried through the JEF-203 asset extraction: the AA-passing
/// contrast values still gate the dashboard, only now they live in the self-hosted
/// stylesheet's `:root` token block and the high-traffic classes CONSUME those
/// tokens. We assert BOTH halves so the contract isn't weakened by the move: (a) each
/// token is DEFINED as its AA value in `:root`, and (b) the class still resolves to it.
/// The old failing raw values (`.muted{color:#777}`, mermaid `#999`) stay gone.
#[test]
fn render_html_uses_aa_contrast_tokens() {
    // The page now LINKS the stylesheet rather than inlining it — the token+class
    // contract is asserted against the served asset (DASHBOARD_CSS), the exact bytes
    // /assets/dashboard.css serves.
    let css = DASHBOARD_CSS;

    // (a) `:root` defines the AA values verbatim (JEF-180):
    //   muted #6a6a6a (>=4.5:1 on white), the legend/mermaid grey #555, the calm
    //   green #1a7f37 and its AA text-on-tint #155f29.
    assert!(
        css.contains("--color-muted: var(--c-grey-3)") && css.contains("--c-grey-3: #6a6a6a"),
        "muted token resolves to the AA value #6a6a6a"
    );
    assert!(
        css.contains("--c-grey-1: #555"),
        "the legend/mermaid grey token is the AA value #555"
    );
    assert!(
        css.contains("--c-green: #1a7f37"),
        "the calm green token is preserved verbatim"
    );
    assert!(
        css.contains("--color-safe-text: var(--c-green-text)")
            && css.contains("--c-green-text: #155f29"),
        "the safe text-on-tint token is the AA value #155f29"
    );

    // (b) the high-traffic classes CONSUME the tokens (not raw hexes):
    assert!(
        css.contains(".muted{color:var(--color-muted)}"),
        ".muted consumes the muted token"
    );
    assert!(
        css.contains(
            ".verdict.muted{color:var(--color-muted);border-left-color:var(--c-grey-line)}"
        ),
        ".verdict.muted consumes the muted token"
    );
    assert!(
        css.contains(
            ".banner-warming .banner-glyph,.banner-warming .banner-word{color:var(--color-muted)}"
        ),
        "the warming banner word/glyph consumes the muted token"
    );
    assert!(
        css.contains(".mermaid{") && css.contains("font-size:.75rem;color:var(--c-grey-1)}"),
        "the mermaid fallback text consumes the AA grey token"
    );

    // The old failing tokens are gone everywhere (page + stylesheet): no
    // `.muted{color:#777}`, no mermaid `color:#999`.
    let html = render_html(
        &[],
        false,
        &BakeStats::default(),
        &[],
        Some(SystemTime::now()),
        &ready(),
    );
    for hay in [css, html.as_str()] {
        assert!(
            !hay.contains(".muted{color:#777}"),
            "old failing #777 muted token removed"
        );
        assert!(
            !hay.contains("font-size:.75rem;color:#999}"),
            "old failing #999 mermaid token removed"
        );
        // No raw #6a6a6a / #777 left as the muted *class* value (the AA value now
        // only appears as the token definition).
        assert!(
            !hay.contains(".muted{color:#6a6a6a}"),
            ".muted no longer carries a raw hex; it consumes the token"
        );
    }
}

/// JEF-180 AC #2 + the JEF-177 interaction: the page swaps the live region in place
/// via a same-origin poll instead of a full reload. Assert the markup carries the
/// swap hooks — the two id'd regions, the `/fragment` poll, no full `location.reload`,
/// and that the deferred Mermaid-on-open wiring is preserved (re-run via `hydrate`).
#[test]
fn render_html_carries_the_incremental_poll_hooks() {
    let html = render_html(
        &[],
        false,
        &BakeStats::default(),
        &[],
        Some(SystemTime::now()),
        &ready(),
    );
    // The two swap targets the poll replaces in place — still emitted by the page.
    assert!(html.contains("id=\"banner-region\""), "banner region id");
    assert!(
        html.contains("id=\"findings-region\""),
        "findings region id"
    );
    // JEF-203: the poll/hydrate logic now lives in the self-hosted module the page
    // loads same-origin (no inline <script>). The page links it; the behavior is
    // asserted against the served asset (DASHBOARD_JS).
    assert!(
        html.contains("<script type=\"module\" src=\"/assets/dashboard.js\"></script>"),
        "page loads the self-hosted dashboard module same-origin"
    );
    assert!(
        !html.contains("<script type=\"module\">"),
        "no inline module script left in the page"
    );
    let js = DASHBOARD_JS;
    // Same-origin fragment fetch (zero new egress) on a 30s timer, not a doc reload.
    assert!(
        js.contains("fetch('/fragment'"),
        "polls /fragment same-origin"
    );
    assert!(
        js.contains("setInterval(poll, 30000)"),
        "30s incremental poll"
    );
    assert!(
        !js.contains("location.reload"),
        "never a full document reload"
    );
    // JEF-177 deferred-Mermaid-on-open wiring is preserved and re-applied after a swap
    // via the shared `hydrate(root)` over the new DOM (not duplicated, not clobbered).
    assert!(js.contains("function hydrate(root)"), "hydrate over a root");
    assert!(
        js.contains("addEventListener('toggle'"),
        "render graphs on details open"
    );
    assert!(
        js.contains("hydrate(region)"),
        "re-hydrate the swapped findings region"
    );
    // <details> open-state survives a swap via localStorage keyed by a stable id.
    assert!(
        js.contains("localStorage") && js.contains("detailsKey"),
        "details open-state persisted across swaps"
    );
    // SVG a11y contract (JEF-161) is intact in the module.
    assert!(
        js.contains("setAttribute('role', 'img')"),
        "rendered graph stays role=img"
    );
    assert!(
        js.contains("setAttribute('aria-label', aria)"),
        "rendered graph keeps its aria-label"
    );
    // Banner a11y contract (JEF-159) stays in the page markup.
    assert!(
        html.contains("role=\"status\" aria-live=\"polite\""),
        "banner keeps role=status aria-live=polite"
    );
}

/// JEF-180: the `/fragment` endpoint returns JUST the live region (banner + findings),
/// byte-for-byte the swap targets the page poll replaces — and NOT a whole document.
#[test]
fn render_fragment_is_the_live_region_only() {
    let findings = [];
    let readiness = ready();
    let frag = render_fragment(&findings, false, Some(SystemTime::now()), &readiness);
    assert!(
        frag.contains("id=\"banner-region\""),
        "fragment has the banner region"
    );
    assert!(
        frag.contains("id=\"findings-region\""),
        "fragment has the findings region"
    );
    // The banner inside the fragment keeps its a11y contract.
    assert!(
        frag.contains("role=\"status\" aria-live=\"polite\""),
        "fragment banner keeps role=status aria-live=polite"
    );
    // It is a FRAGMENT, not a page: no doctype/head/style/script.
    assert!(
        !frag.contains("<!doctype"),
        "fragment is not a full document"
    );
    assert!(!frag.contains("<style>"), "fragment carries no <style>");
    assert!(!frag.contains("<script"), "fragment carries no <script>");
    // The fragment's banner region is identical to the one the full page embeds, so
    // the in-place swap can never drift from the page.
    let page = render_html(
        &findings,
        false,
        &BakeStats::default(),
        &[],
        Some(SystemTime::now()),
        &readiness,
    );
    let frag_banner = {
        let s = frag.find("<div id=\"banner-region\">").unwrap();
        let e = frag.find("<h1>protector</h1>").unwrap();
        &frag[s..e]
    };
    assert!(
        page.contains(frag_banner),
        "the page embeds the same banner-region markup the fragment serves"
    );
}

/// JEF-203 fragment⊂page parity: the WHOLE `render_fragment` output is a substring of
/// `render_html` for the same inputs. The page embeds the live region verbatim, so the
/// `/fragment` poll can swap it in place and never drift from the page. This pins the
/// invariant for the later dashboard-refactor chunks (any future divergence between the
/// fragment and the page's live region breaks this test, not production).
#[test]
fn render_fragment_is_a_substring_of_render_html() {
    let findings = vec![
        finding(
            "workload/app/Pod/web",
            "secret/app/session-key",
            "auto-eligible",
            "can-do/get/secrets",
            true,
            Some("exploitable — RCE reaches the secret"),
        ),
        finding(
            "workload/api/Pod/svc",
            "secret/api/token",
            "durable-fix PR",
            "can-read",
            true,
            Some("not exploitable — authorized RBAC"),
        ),
    ];
    let last_pass = Some(SystemTime::now());
    let readiness = ready();
    let frag = render_fragment(&findings, true, last_pass, &readiness);
    let page = render_html(
        &findings,
        true,
        &BakeStats::default(),
        &[],
        last_pass,
        &readiness,
    );
    assert!(
        page.contains(&frag),
        "render_fragment output must be a verbatim substring of render_html"
    );
}

// -- JEF-175: answer-first reorder (findings on top, engine internals collapsed) -----

/// AC #1+#2+#3: the findings lead the page and the engine internals are collapsed
/// BELOW them. Concretely: findings (Needs attention / Watching) come before the
/// single "Engine & coverage" diagnostics region, which is a <details>, and the
/// readiness/attack-surface/sensor-activity/recently-lifted sections live inside it.
#[test]
fn render_html_puts_findings_above_a_collapsed_diagnostics_region() {
    let findings = vec![
        // A model-flagged endpoint ⇒ "Needs attention".
        finding(
            "workload/app/Pod/web",
            "secret/app/session-key",
            "latent foothold — propose",
            "can-read",
            true,
            Some("exploitable — CVE-2021-44228 reaches the secret"),
        ),
    ];
    let html = render_html(
        &findings,
        false,
        &bake(80, 20),
        &[],
        Some(SystemTime::now()),
        &ready_all_met(),
    );

    let needs = html
        .find("Needs attention")
        .expect("needs-attention section");
    let watching = html.find("Watching").expect("watching section");
    let diag = html
        .find("Engine &amp; coverage")
        .expect("diagnostics region");
    let readiness = html.find("Readiness").expect("readiness section");
    let surface = html
        .find("What an attacker could reach")
        .expect("attack-surface section");
    let sensor = html
        .find("Live activity the sensors saw")
        .expect("sensor-activity section");
    let lifted = html
        .find("Recently lifted")
        .expect("recently-lifted section");

    // Findings (both sub-sections) precede the diagnostics region.
    assert!(
        needs < diag,
        "Needs attention is above the diagnostics region"
    );
    assert!(watching < diag, "Watching is above the diagnostics region");
    // Remediations render between the findings and the diagnostics region (AC #2):
    // the remediations heading sits after the findings and before "Engine & coverage".
    let rem = html
        .find("What protector would do")
        .expect("remediations section");
    assert!(
        needs < rem && rem < diag,
        "remediations after findings, before diag"
    );
    // All four engine sub-sections live inside the diagnostics region.
    for (name, at) in [
        ("Readiness", readiness),
        ("What an attacker could reach", surface),
        ("Live activity the sensors saw", sensor),
        ("Recently lifted", lifted),
    ] {
        assert!(at > diag, "{name} is inside the diagnostics region");
    }
    // The diagnostics region is ONE collapsible <details>.
    assert!(
        html.contains("<details class=\"diag\""),
        "diagnostics is a <details> region"
    );
}

/// AC #3: the Readiness section auto-opens (<details open>) iff a decision-weakening
/// input is absent/degraded — a healthy cluster gets a collapsed one-line summary.
#[test]
fn readiness_section_auto_opens_only_when_inputs_are_unmet() {
    // Degraded/absent inputs (default `ready()`) ⇒ the readiness sub-section opens
    // (and so does the enclosing region) so the gap surfaces prominently.
    let unmet = render_html(&[], false, &BakeStats::default(), &[], None, &ready());
    assert!(
        unmet.contains("<details id=\"coverage\" open>"),
        "readiness auto-opens when inputs unmet"
    );
    assert!(
        unmet.contains("<details class=\"diag\" open>"),
        "diagnostics region auto-opens when inputs unmet"
    );

    // Every input met ⇒ the readiness sub-section (and the region) stay collapsed.
    let met = render_html(
        &[],
        false,
        &bake(80, 20),
        &[],
        Some(SystemTime::now()),
        &ready_all_met(),
    );
    assert!(
        met.contains("<details id=\"coverage\">"),
        "readiness stays collapsed when every input is met"
    );
    assert!(
        !met.contains("<details id=\"coverage\" open>"),
        "readiness has no open attribute when every input is met"
    );
    assert!(
        met.contains("<details class=\"diag\">"),
        "diagnostics region stays collapsed when every input is met"
    );
}

/// AC #5: NO JSON endpoint or route is removed — the readiness/bake/reversions JSON
/// routes are only DE-LISTED from the human nav, but still reachable. The diagnostics
/// sections link to the readiness + reversions JSON (bake stays reachable at /bake).
#[test]
fn diagnostics_sections_keep_the_json_links() {
    let html = render_html(&[], false, &bake(80, 20), &[], None, &ready_all_met());
    assert!(
        html.contains("<a href=\"/readiness\">json</a>"),
        "readiness json link kept"
    );
    assert!(
        html.contains("<a href=\"/reversions\">json</a>"),
        "reversions json link kept (folded into Recently lifted)"
    );
}

/// AC #2: "Needs attention" is OMITTED entirely when no endpoint is model-flagged —
/// the operator's eye isn't drawn to an empty alarm section.
#[test]
fn needs_attention_section_is_omitted_when_nothing_is_flagged() {
    // A breach-relevant endpoint the model did NOT flag ⇒ Watching only.
    let findings = vec![finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "latent foothold — propose",
        "can-read",
        true,
        Some("not exploitable — the CVE is in a code path this service never invokes"),
    )];
    let html = render_html(
        &findings,
        false,
        &BakeStats::default(),
        &[],
        Some(SystemTime::now()),
        &ready_all_met(),
    );
    assert!(
        !html.contains("Needs attention"),
        "no flagged ⇒ no attention section"
    );
    assert!(
        html.contains("Watching"),
        "the watching section is still present"
    );
}

#[test]
fn disposition_keys_on_what_the_cut_can_actually_do() {
    // Disposition keys on the cut + chain flags, not on the per-entry evidence, so an
    // empty graph (no CVEs/behaviors) is fine here.
    let g = SecurityGraph::new();
    let disp = |c: &ProvenChain| Finding::from_chain(c, &g).disposition;

    // A network cut that meets the bar is the only thing that auto-applies.
    assert_eq!(
        disp(&chain("reaches/Tcp", false, true, true)),
        "auto-eligible"
    );
    assert_eq!(
        disp(&chain("reaches/Tcp", true, false, true)),
        "latent foothold — propose"
    );
    assert_eq!(
        disp(&chain("reaches/Tcp", false, false, true)),
        "structural — propose"
    );
    assert_eq!(
        disp(&chain("reaches/Tcp", false, true, false)),
        "vetoed — propose"
    );

    // Corroborated, but the cut is subtractive (RBAC/data) → NOT auto-eligible;
    // it's a durable-fix PR. This is the "198 auto-eligible" mislabel, fixed.
    assert_eq!(
        disp(&chain("can-do/get/secrets", false, true, true)),
        "durable-fix PR"
    );
    assert_eq!(
        disp(&chain("can-read", false, true, true)),
        "durable-fix PR"
    );
    // An escape primitive is irreversible — never auto.
    assert_eq!(
        disp(&chain("escapes-to/privileged", false, true, true)),
        "forbidden"
    );

    // A model-promoted network chain is auto-eligible even without corroboration.
    let promoted = ProvenChain {
        promoted: true,
        ..chain("reaches/Tcp", false, false, true)
    };
    assert_eq!(
        Finding::from_chain(&promoted, &g).disposition,
        "auto-eligible"
    );
}

// The `mm()` XSS-strip test migrated to `components::graph` (JEF-205), the canonical home
// of the Mermaid sink + its `PreEscaped` guard.

#[test]
fn renders_two_graph_sections_and_drops_internal_paths() {
    let findings = vec![
        // Remediation: the model judged it exploitable → auto-eligible cut.
        finding(
            "workload/app/Pod/web",
            "secret/app/session-key",
            "auto-eligible",
            "reaches/Tcp",
            true,
            Some("exploitable — CVE-2021-44228 is a remote RCE reaching the secret"),
        ),
        // Un-remediated paths from the SAME endpoint (coalesce into one graph).
        finding(
            "workload/app/Pod/web",
            "capability/cluster/create/pods",
            "durable-fix PR",
            "can-do/create/pods",
            true,
            None,
        ),
        // The model's NEGATIVE call is kept too — shown as the reason.
        finding(
            "workload/app/Pod/web",
            "secret/app/other",
            "latent foothold — propose",
            "can-read",
            true,
            Some("not exploitable — the CVE is in a code path this service never invokes"),
        ),
        // Internal (not breach-relevant): must NOT appear in either section.
        finding(
            "workload/argocd/Pod/argocd-application-controller-0",
            "secret/argocd/argocd-secret",
            "durable-fix PR",
            "can-do/get/secrets",
            false,
            None,
        ),
    ];

    let html = render_html(&findings, false, &BakeStats::default(), &[], None, &ready());
    // Remediations verb (JEF-175): shadow → "What protector would do"; armed →
    // "What protector is doing".
    assert!(html.contains("What protector would do"));
    assert!(
        render_html(&findings, true, &BakeStats::default(), &[], None, &ready())
            .contains("What protector is doing")
    );
    // The findings region carries the answer-first "Watching" section (the web
    // endpoint's card is not model-flagged, so it lands under Watching, not the
    // omitted-when-empty "Needs attention").
    assert!(html.contains("Watching"));
    // The attack-vector summary names the ATT&CK outcomes reachable, with the
    // model-flagged count (one objective was judged exploitable above). Plain-English
    // heading "What an attacker could reach" under the diagnostics region (JEF-176).
    assert!(html.contains("What an attacker could reach"));
    assert!(html.contains("Credential Access"));
    assert!(html.contains("Unsecured Credentials"));
    assert!(html.contains("class=\"flagged\""));
    // Graphs are Mermaid flowcharts with an Internet source.
    assert!(html.contains("class=\"mermaid\""));
    assert!(html.contains("flowchart LR"));
    assert!(html.contains("Internet"));
    // The remediation graph marks the cut (dashed edge + scissors).
    assert!(html.contains("✂"));
    // BOTH the positive verdict (on the remediation) and the negative one (on the
    // un-remediated path) are surfaced with the model's reasoning.
    assert!(html.contains("exploitable — CVE-2021-44228 is a remote RCE"));
    assert!(html.contains("not exploitable — the CVE is in a code path"));
    // The internal control-plane path is dropped entirely (one endpoint: web).
    assert!(!html.contains("argocd-secret"));
    assert!(html.contains("1</b> exposed endpoint"));
    // Dump for eyeballing the UX (ignored by CI artifacts; just a dev aid).
    let _ = std::fs::write("/tmp/protector-dashboard.html", &html);
}

#[test]
fn bake_stats_total_and_unresolved_fraction() {
    let b = bake(80, 20);
    assert_eq!(b.total_signals(), 20, "sum across the three variants");
    assert!(
        (b.unresolved_fraction() - 0.2).abs() < 1e-9,
        "20 of 100 attributed are unresolved"
    );
    // No attributed signals → no misses (avoid a divide-by-zero NaN).
    assert_eq!(BakeStats::default().unresolved_fraction(), 0.0);
}

// `bake_panel_renders_volume_attribution_and_corroborations` migrated to
// `components::panels::bake` (JEF-206).
