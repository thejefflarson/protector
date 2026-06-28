//! The dashboard "App" (ADR-0019): the page-level composition that assembles the maud
//! components (nav, banner, findings table, panels) into the full page (`render_html`) and
//! the `/fragment` live region (`live_region` / `render_fragment`). Every surface here is
//! auto-escaped maud — there is no string-concat rendering left; the only un-escaped splices
//! are already-rendered child `Markup` and the byte-stable `chips` entity constants
//! (`PreEscaped` allowances #1 / #3).

use std::collections::BTreeMap;
use std::time::SystemTime;

use maud::{Markup, html};

use crate::engine::dashboard::components;
use crate::engine::dashboard::components::chips;
use crate::engine::dashboard::components::findings::findings_table;

/// The number of columns in the dense findings table (JEF-202). Canonical home is
/// `components::findings`; re-exported here for the page composition and the render tests.
pub(crate) use crate::engine::dashboard::components::findings::FINDINGS_COLS;
use crate::engine::dashboard::model::{
    AUTO_ELIGIBLE, BakeStats, Finding, ReversionRecord, relative_time,
};
use crate::engine::dashboard::view_model::findings::{
    RecencyTally, Tier, endpoint_attention_rank, endpoint_props, recency_tally, remediation_props,
    tier_of_priority,
};
use crate::engine::dashboard::view_model::readiness_data::Readiness;
use crate::engine::dashboard::view_model::{
    attack_vectors_props, bake_props, banner_props, first_run_props, nav_props, readiness_props,
    reversions_props,
};

/// The per-pass "live region" (JEF-180): the status banner plus the findings region
/// (summary line, findings body, remediations), each wrapped in a stable `id` container.
/// The full page embeds this verbatim; the same-origin `/fragment` poll fetches THIS and
/// swaps only these two containers in place, so a timer never reloads the whole document
/// (which used to reset scroll, focus, and every `<details>` open/closed state). Sharing
/// one builder keeps the page and the incrementally-swapped fragment from ever drifting.
fn live_region(
    findings: &[Finding],
    armed: bool,
    last_pass: Option<SystemTime>,
    readiness: &Readiness,
) -> Markup {
    // The banner + nav are maud components fed by the view-model (ADR-0019); the findings
    // region is the maud findings table + panels composed below. All three are child Markup.
    let banner = components::banner(&banner_props(
        findings,
        armed,
        last_pass,
        &relative_time(last_pass),
        readiness.model_judging,
    ));
    let nav = components::nav(&nav_props("/"));
    html! {
        div id="banner-region" { (banner) }
        h1 { "protector" }
        (nav)
        div id="findings-region" { (findings_region(findings, armed, last_pass, readiness)) }
    }
}

/// The edge-legend glossary, collapsed behind a closed `<details>` (JEF-200) — the token
/// names stay reachable on demand, but no longer crowd the findings region as inline prose.
fn edge_legend() -> Markup {
    html! {
        details class="legend-d" {
            summary { "edge legend" }
            p class="legend" {
                code { "mounts (direct read)" } ": the secret is mounted into the pod, read with no API call (just that one secret) · "
                code { "RBAC … (API)" } ": the pod's ServiceAccount can read via the Kubernetes API (often any secret in scope) · "
                code { "network reach" } ": a NetworkPolicy- or Linkerd-authorized connection · "
                code { "runs as" } ": assumes the ServiceAccount identity · "
                code { "escapes via" } ": a container-escape primitive to the host node"
            }
        }
    }
}

/// The single `ctx-summary` group toggle row (JEF-202) that the Context tier collapses to —
/// it reveals the hidden `ctx-row` group when opened.
fn context_summary_row(ctx_n: usize) -> Markup {
    html! {
        tr class="ctx-summary" {
            td colspan=(FINDINGS_COLS) {
                button class="row-toggle ctx-toggle" aria-expanded="false"
                    data-ctx-group="watching" {
                    span class="chip tier-context" { "context" } " "
                    span class="muted" {
                        (ctx_n) " background path" (plural(ctx_n))
                        " — proven-reachable, neither flagged nor seen live"
                    }
                }
            }
        }
    }
}

/// The findings region's inner HTML (JEF-202 dense table): the summary line, the dense
/// findings TABLE(s) (the primary view — one row per endpoint, the verbose card body behind
/// each row's expand), and the remediations section. Pure over the findings and arm-state;
/// reused by [`live_region`] for both the full page and the poll fragment.
fn findings_region(
    findings: &[Finding],
    armed: bool,
    last_pass: Option<SystemTime>,
    readiness: &Readiness,
) -> Markup {
    // One pass over the breach-relevant findings: the auto-eligible ones are
    // remediations; the rest group by endpoint (entry) for the attack-path graphs.
    let mut remediations: Vec<&Finding> = Vec::new();
    let mut endpoints: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in findings.iter().filter(|f| f.breach_relevant) {
        if f.disposition == AUTO_ELIGIBLE {
            remediations.push(f);
        } else {
            endpoints.entry(f.entry.as_str()).or_default().push(f);
        }
    }

    // Rank "look at this first" (JEF-163): the OPERATOR-PRIORITY tiers first
    // (flagged → watch → context, via `endpoint_attention_rank`), with the blast
    // radius (graph size) only as the FINAL tiebreaker WITHIN a tier. This is a
    // presentation-only sort key — a view, never a gate (ADR-0016): it reorders the
    // already-decided cards and touches no verdict/disposition and no model input. A
    // flagged-exploitable endpoint therefore ALWAYS sorts above a larger-but-unflagged
    // one (AC #2). `sort_by` is STABLE, so equal keys keep their (entry-sorted, since
    // `endpoints` is a BTreeMap) order — and we tiebreak on the entry key last anyway
    // to make the order fully deterministic.
    let mut ranked: Vec<(&&str, &Vec<&Finding>)> = endpoints.iter().collect();
    ranked.sort_by(|a, b| {
        let (ap, _) = endpoint_attention_rank(a.1);
        let (bp, _) = endpoint_attention_rank(b.1);
        ap.cmp(&bp) // priority level: lower = more attention, first
            .then_with(|| b.1.len().cmp(&a.1.len())) // then widest blast radius
            .then_with(|| a.0.cmp(b.0)) // then entry key, for a stable total order
    });

    // The findings-region recency tally for the latest pass (JEF-201): how many endpoints are
    // NEW and how many newly FLAGGED (escalated). Counted per endpoint over the same per-entry
    // groups the region renders, from each endpoint's stored Δ — pure presentation (ADR-0016).
    let recency = recency_tally(ranked.iter().map(|(_, fs)| fs.as_slice()));

    // Partition the ranked endpoints into the answer-first split, as dense table ROWS
    // (JEF-202): "Needs attention" is the Flagged tier (the model judged a real breach);
    // "Watching" holds the Watch tier directly plus the Context tier collapsed behind a
    // single summary row. The partition keys on the SAME `endpoint_attention_rank` tier the
    // rows carry, so a row's section and its tier cell can never drift.
    let mut attention_rows: Vec<Markup> = Vec::new();
    let mut watch_rows: Vec<Markup> = Vec::new();
    let mut context_rows: Vec<Markup> = Vec::new();
    let mut flagged_n = 0usize;
    let mut exposed_n = 0usize; // watch + context: exposed, not flagged
    for (entry, fs) in &ranked {
        let (priority, tier) = endpoint_attention_rank(fs);
        let mut props = endpoint_props(entry, fs, tier_of_priority(priority), last_pass);
        match tier {
            Tier::Flagged => {
                flagged_n += 1;
                attention_rows.push(components::findings::endpoint(&props));
            }
            Tier::Watch => {
                exposed_n += 1;
                watch_rows.push(components::findings::endpoint(&props));
            }
            Tier::Context => {
                exposed_n += 1;
                // Context detail-group rows: HIDDEN by default behind the single context
                // summary row, so the group toggle reveals them together (JEF-202). The
                // `context` flag makes the summary `<tr>` render `hidden class="ctx-row …"`.
                props.row.context = true;
                context_rows.push(components::findings::endpoint(&props));
            }
        }
    }

    let freshness = relative_time(last_pass);

    // The instructional first-run state (JEF-160): when the engine has NO breach-relevant
    // findings AND a decision input is unmet, an empty findings body would otherwise read
    // as a (possibly false) "all clear". Replace the whole findings region with the guided
    // checklist so a blind cluster is never indistinguishable from a clean one. A clean
    // cluster with every input wired keeps the existing honest-empty idiom.
    let no_breach_findings = !findings.iter().any(|f| f.breach_relevant);
    let first_run = no_breach_findings && readiness.has_unmet();

    let ctx_n = context_rows.len();
    let rem_n = remediations.len();
    let ep_n = endpoints.len();

    html! {
        // The summary line + findings body + remediations section — the per-pass content the
        // poll swaps in place (JEF-180). The wrapping `#findings-region` div is added by the
        // caller ([`live_region`]).
        p class="sum" {
            b { (rem_n) } " " (if armed { "active" } else { "proposed" })
            " · " b { (ep_n) } " exposed endpoint" (plural(ep_n))
            " with possible attack paths · last pass " b { (freshness) }
            " " (chips::sep()) " " a href="/findings" { "json" }
        }
        // The recency tally for the latest pass (JEF-201): "N new · M newly flagged since last
        // pass". Omitted when nothing changed (a hollow "0 new" reads worse than silence).
        (recency_tally_line(recency))
        // The dense findings region (JEF-202) — the primary view, leading below the banner.
        // Answer-first: a "Needs attention — N flagged" table (OMITTED entirely when nothing
        // is flagged) then a "Watching — N exposed, not flagged" table. Counts live in the
        // headers (JEF-200). On first run the guided checklist replaces the whole region.
        @if first_run {
            (components::panels::first_run(&first_run_props(readiness)))
        } @else {
            @if !attention_rows.is_empty() {
                h2 id="attack-paths" {
                    "Needs attention " span class="muted" { "— " (flagged_n) " flagged" }
                }
                (findings_table(markup_join(&attention_rows)))
            }
            h2 id="watching" {
                "Watching " span class="muted" { "— " (exposed_n) " exposed, not flagged" }
            }
            @let watching_body = html! {
                @if watch_rows.is_empty() && context_rows.is_empty() {
                    tr {
                        td colspan=(FINDINGS_COLS) class="muted" {
                            "no internet-facing service can reach a target"
                        }
                    }
                } @else {
                    (markup_join(&watch_rows))
                    // The Context tier collapses to ONE summary row that expands to its rows.
                    @if !context_rows.is_empty() {
                        (context_summary_row(ctx_n))
                        (markup_join(&context_rows))
                    }
                }
            };
            (findings_table(watching_body))
            (edge_legend())
        }
        // Remediations verb (JEF-175): answer-first phrasing — "What protector would do"
        // (shadow, proposing) vs "What protector is doing" (armed, acting).
        h2 {
            (if armed { "What protector is doing" } else { "What protector would do" })
            " " span class="muted" { "(" (rem_n) ")" }
        }
        @if remediations.is_empty() {
            p class="muted" { "none" }
        } @else {
            @for f in &remediations {
                (components::findings::remediation(&remediation_props(f, armed)))
            }
        }
    }
}

/// Join already-rendered child `Markup` rows into one `Markup` (their braces escaped at
/// their own components; this composes them, the `PreEscaped` child-markup allowance).
fn markup_join(rows: &[Markup]) -> Markup {
    html! { @for r in rows { (r) } }
}

/// Pluralize a count: the empty suffix for one, `s` otherwise.
fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// The findings-region recency tally line (JEF-201): "N new · M newly flagged since last
/// pass". Rendered only when something changed this pass; an all-quiet pass renders nothing
/// (a "0 new · 0 newly flagged" line reads as noise). Counts only — pure presentation.
fn recency_tally_line(tally: RecencyTally) -> Markup {
    html! {
        @if !tally.is_empty() {
            p class="recency-tally" {
                @if tally.new > 0 {
                    b { (tally.new) } " new"
                }
                @if tally.new > 0 && tally.newly_flagged > 0 { " · " }
                @if tally.newly_flagged > 0 {
                    b { (tally.newly_flagged) } " newly flagged"
                }
                " since last pass"
            }
        }
    }
}

/// Render the dashboard: the live region (banner + findings, [`live_region`]) plus the
/// collapsed engine-and-coverage diagnostics (readiness, attack vectors, behavioral bake,
/// recent reversions). The live region is swapped in place by the same-origin poll; the
/// diagnostics block is served once with the full page (JEF-141, JEF-160, JEF-175).
pub(crate) fn render_html(
    findings: &[Finding],
    armed: bool,
    bake: &BakeStats,
    reversions: &[ReversionRecord],
    last_pass: Option<SystemTime>,
    readiness: &Readiness,
) -> String {
    let live = live_region(findings, armed, last_pass, readiness);
    // The diagnostics panels are maud components fed by the view-model (ADR-0019, JEF-206).
    let vectors_body = components::panels::attack_vectors(&attack_vectors_props(findings));
    let bake_body = components::panels::bake(&bake_props(bake));
    let reversions_body = components::panels::reversions(&reversions_props(reversions));
    let readiness_body = components::panels::readiness(&readiness_props(readiness));

    // AC #3: a degraded/absent decision-weakening input must still surface — the Readiness
    // section (and its enclosing diagnostics region) auto-open ONLY when `has_unmet()`; a
    // healthy cluster gets a one-line summary it can expand.
    let unmet = readiness.has_unmet();

    // The page CSS + JS are self-hosted static assets (JEF-203): the stylesheet at
    // /assets/dashboard.css and the module at /assets/dashboard.js, both served SAME-ORIGIN
    // from the embedded `web/dist` (zero egress, no third-party CDN). The graph renderer the
    // module imports (beautiful-mermaid, ELK layout) is likewise vendored + served at
    // /assets. (Pre-JEF-203 these were inlined into the document head; the only
    // rendered-output change was inline -> linked delivery.)
    let page = html! {
        (chips::doctype())
        html {
            head {
                meta charset="utf-8";
                title { "protector" }
                link rel="stylesheet" href="/assets/dashboard.css";
                script type="module" src="/assets/dashboard.js" {}
            }
            body {
                (live)
                details class="howto" {
                    summary { "how protector decides" }
                    p class="sum" {
                        "It maps every real path an attacker could walk — proven from your "
                        "cluster's config and live traffic, it can't invent one — then a local "
                        "model judges whether each is actually being exploited. A flagged breach "
                        "means proven path + the model saw exploitation evidence."
                    }
                }
                details class="diag" open[unmet] {
                    summary { h2 class="diag-h" { "Engine & coverage" } }
                    details id="coverage" open[unmet] {
                        summary {
                            h3 class="diag-h" {
                                "Readiness " span class="muted" { "(decision inputs)" }
                            }
                        }
                        p class="sum" {
                            "Each decision input and its LIVE state; an " b { "absent" }
                            " input that " b { "weakens decisions" } " is called out. "
                            (chips::sep()) " " a href="/readiness" { "json" }
                        }
                        (readiness_body)
                    }
                    details {
                        summary { h3 class="diag-h" { "What an attacker could reach" } }
                        p class="sum" {
                            "What an internet-facing service can reach. "
                            b { "Reachable" } " = proven the service can get there; "
                            b { "model-flagged" } " = the model judged it a real breach."
                        }
                        (vectors_body)
                    }
                    details {
                        summary {
                            h3 class="diag-h" {
                                "Live activity the sensors saw "
                                span class="muted" { "(shadow)" }
                            }
                        }
                        p class="sum" {
                            "What the behavioral agent observed last pass (shadow — only "
                            "watching); " b { "corroborations" }
                            " counts findings a live signal backed up."
                        }
                        (bake_body)
                    }
                    details {
                        summary {
                            h3 class="diag-h" {
                                "Recently lifted " span class="muted" { "(lifted cuts)" }
                            }
                        }
                        p class="sum" {
                            "Cuts the engine lifted, and why. An isolation stays only while the "
                            "breach lasts, then lifts on its own once the path is gone or the "
                            "evidence clears. " (chips::sep()) " " a href="/reversions" { "json" }
                        }
                        (reversions_body)
                    }
                }
            }
        }
    };
    page.into_string()
}

/// The incremental-refresh fragment (JEF-180): JUST the live region — the `#banner-region`
/// and `#findings-region` containers, byte-for-byte the same markup the full page embeds
/// (both come from [`live_region`]). The same-origin poll fetches this and swaps those two
/// containers in place, so the page is never reloaded on a timer. This is a NEW route that
/// changes no existing route or its JSON contract; it carries the same presentation-only,
/// no-internal-refs data the page already serves (no new egress, same origin).
pub(crate) fn render_fragment(
    findings: &[Finding],
    armed: bool,
    last_pass: Option<SystemTime>,
    readiness: &Readiness,
) -> String {
    live_region(findings, armed, last_pass, readiness).into_string()
}
