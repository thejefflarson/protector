//! The `/report` page (JEF-143), migrated to maud (ADR-0019): the shadow would-have-acted
//! diff over a rolling window — the workloads protector WOULD have isolated, how often the
//! breach condition held, the projected cut lifetime (short-lived = likely FP), and the
//! proven paths the model deliberately left alone (the trust evidence).
//!
//! PRESENTATION ONLY: this renderer takes its [`ReportProps`] and nothing else. It imports
//! NO `engine::` domain type — only its props (from the `view_model`), the shared `chips`
//! primitives, and maud. The page CSS is the shared self-hosted `/assets/dashboard.css`
//! (JEF-203); there is NO inline `<style>` block. The `report_imports_no_engine_domain_type`
//! test documents the boundary (ADR-0019); the byte-stability tests pin the output to the
//! pre-maud string-concat render.

use crate::engine::dashboard::components::chips::{doctype, sep};
use crate::engine::dashboard::view_model::{Lifetime, ReportBody, ReportDiff, ReportProps};
use maud::{Markup, html};

/// The would-act table's "Workload" first column: the short label in a `<code>` cell. Auto-
/// escapes the (untrusted) workload key.
fn workload_cell(entry: &str) -> Markup {
    html! { td { code { (entry) } } }
}

/// The projected-cut-lifetime cell — the FP tell made visually distinct: open episodes and
/// sustained cuts read "sustained", a short-lived one reads as the likely false positive.
fn lifetime_cell(row: &crate::engine::dashboard::view_model::WouldActRow) -> Markup {
    html! {
        td {
            @match row.lifetime_kind {
                Lifetime::Open => {
                    span class="sustained" { (row.lifetime) " (open)" }
                }
                Lifetime::ShortLived => {
                    span class="shortlived" { (row.lifetime) " (short-lived)" }
                }
                Lifetime::Sustained => {
                    span class="sustained" { (row.lifetime) }
                }
            }
        }
    }
}

/// The evidence-coverage cell: the coverage-gap flag for a would-act with no enrichment
/// backing (scrutinize first), or a muted dash.
fn coverage_cell(coverage_gap: bool) -> Markup {
    html! {
        td {
            @if coverage_gap {
                span class="flagged" { "coverage gap" }
            } @else {
                span class="muted" { "—" }
            }
        }
    }
}

/// The would-act table body — one row per workload protector would have isolated, or the
/// "none" placeholder when every proven path was cleared.
fn would_act_table(diff: &ReportDiff) -> Markup {
    html! {
        tbody {
            @if diff.would_act.is_empty() {
                tr { td class="muted" colspan="5" { "none — every proven path was cleared" } }
            } @else {
                @for w in &diff.would_act {
                    tr {
                        (workload_cell(&w.entry))
                        td { (w.would_act_decisions) }
                        (lifetime_cell(w))
                        (coverage_cell(w.coverage_gap))
                        td class="verdict-cell" { (w.last_verdict) }
                    }
                }
            }
        }
    }
}

/// The left-alone (trust-evidence) table body — one row per proven-but-cleared path, or the
/// "none" placeholder.
fn left_alone_table(diff: &ReportDiff) -> Markup {
    html! {
        tbody {
            @if diff.left_alone.is_empty() {
                tr { td class="muted" colspan="2" { "none" } }
            } @else {
                @for l in &diff.left_alone {
                    tr {
                        (workload_cell(&l.entry))
                        td class="verdict-cell" { (l.verdict) }
                    }
                }
            }
        }
    }
}

/// Pluralize: the empty suffix for one, `s` otherwise.
fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// The populated would-have-acted diff body: the headline sentence, the would-act table,
/// and the left-alone table.
fn diff_body(diff: &ReportDiff) -> Markup {
    html! {
        div class="sum" {
            "over the last " b { (diff.window) } " protector would have isolated "
            b { (diff.would_act_count) } " workload" (plural(diff.would_act_count))
            " and deliberately left " b { (diff.left_alone_count) }
            " proven-but-cleared path" (plural(diff.left_alone_count)) " alone. "
            (diff.short_lived_count) " short-lived (likely FP) · "
            (diff.coverage_gap_count) " with thin evidence coverage (scrutinize first)."
        }
        h3 {
            "Would have isolated " span class="muted" { "(" (diff.would_act_count) ")" }
        }
        table class="vectors" {
            thead { tr {
                th { "Workload" } th { "Would-cut decisions" }
                th { "Projected cut lifetime" } th { "Evidence coverage" }
                th { "Latest verdict" }
            } }
            (would_act_table(diff))
        }
        h3 {
            "Left alone "
            span class="muted" { "(" (diff.left_alone_count) ") — proven, then cleared" }
        }
        table class="vectors" {
            thead { tr { th { "Workload" } th { "Clearing verdict" } } }
            (left_alone_table(diff))
        }
    }
}

/// The `/report` body (the `report_panel` of the pre-maud render): the honest empty/quiet
/// states, or the populated would-have-acted diff.
fn report_panel(props: &ReportProps) -> Markup {
    html! {
        @match &props.body {
            ReportBody::Empty { window } => {
                p class="muted" {
                    "no decisions yet — the decision journal is empty (no pass has recorded a \
                     breach decision, or no durable journal volume is configured). Once the \
                     engine judges an internet-facing workload, this report fills in over the \
                     last " (window) "."
                }
            }
            ReportBody::OutOfWindow { window } => {
                p class="muted" {
                    "no breach decisions in the last " (window) " (the journal has older \
                     history — widen the window with " code { "?days=N" } ")."
                }
            }
            ReportBody::Diff(diff) => { (diff_body(diff)) }
        }
    }
}

/// The full `/report` HTML page (JEF-143): a self-contained document wrapping
/// [`report_panel`], styled by the shared self-hosted `/assets/dashboard.css` (no inline
/// `<style>`). Pure `Props -> Markup`.
pub fn report(props: &ReportProps) -> Markup {
    html! {
        (doctype())
        html {
            head {
                meta charset="utf-8";
                title { "protector — would-have-acted report" }
                link rel="stylesheet" href="/assets/dashboard.css";
            }
            body {
                h1 { "protector — would-have-acted report" }
                p class="sum" {
                    "The shadow diff that gates exiting shadow: over a rolling window, the \
                     workloads protector " b { "would" } " have isolated, how often the breach \
                     condition held, the projected cut lifetime (short-lived = likely false \
                     positive), and the proven paths the model deliberately " b { "left alone" }
                    " — the trust evidence. Read-only; no action. Tune the window with "
                    code { "?days=N" } " or " code { "?hours=N" } " and the short-lived \
                     threshold with " code { "?short_lived_secs=N" } ". "
                    (sep()) " " a href="/" { "dashboard" } " " (sep()) " "
                    a href="/report.json" { "json" }
                }
                h2 { "Shadow would-have-acted diff" }
                (report_panel(props))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::legacy::{
        EnrichmentCoverage, JournalEntry, Report, aggregate_report,
    };
    use crate::engine::dashboard::view_model::report_props;
    use crate::engine::journal::Decision;
    use std::time::{Duration, SystemTime};

    const WEEK: Duration = Duration::from_secs(7 * 24 * 3600);
    const FIVE_MIN: Duration = Duration::from_secs(300);

    /// A deterministic `now` anchor for the lifetime/window math.
    fn report_now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    /// A breach journal entry whose structured coverage is derived from the verdict's CVE
    /// mentions (a CVE-less verdict reads as a coverage gap).
    fn breach(entry: &str, verdict: &str, secs_before: u64) -> JournalEntry {
        let cves: Vec<String> = verdict
            .match_indices("CVE-")
            .map(|(i, _)| {
                verdict[i..]
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();
        let at = report_now() - Duration::from_secs(secs_before);
        JournalEntry {
            at_ms: at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            decision: Decision::Breach {
                entry: entry.to_string(),
                objectives: 1,
                verdict: verdict.to_string(),
                coverage: Some(EnrichmentCoverage {
                    cves,
                    behavioral: false,
                }),
            },
        }
    }

    /// Render a [`Report`] through the view-model into the component — the full page render
    /// path (`report_props` → `components::report`), as the route handler wires it.
    fn page(r: &Report) -> String {
        super::report(&report_props(r)).into_string()
    }

    /// JEF-207: the empty-journal page is byte-for-byte the pre-maud `render_report_html`.
    #[test]
    fn empty_report_page_is_byte_stable() {
        let r = aggregate_report(&[], report_now(), WEEK, FIVE_MIN);
        let got = page(&r);
        let want = "<!doctype html><html><head><meta charset=\"utf-8\">\
             <title>protector — would-have-acted report</title>\
             <link rel=\"stylesheet\" href=\"/assets/dashboard.css\">\
             </head><body>\
             <h1>protector — would-have-acted report</h1>\
             <p class=\"sum\">The shadow diff that gates exiting shadow: over a rolling \
             window, the workloads protector <b>would</b> have isolated, how often the breach \
             condition held, the projected cut lifetime (short-lived = likely false positive), and \
             the proven paths the model deliberately <b>left alone</b> — the trust evidence. \
             Read-only; no action. Tune the window with <code>?days=N</code> or <code>?hours=N</code> \
             and the short-lived threshold with <code>?short_lived_secs=N</code>. \
             &nbsp;|&nbsp; <a href=\"/\">dashboard</a> &nbsp;|&nbsp; <a href=\"/report.json\">json</a></p>\
             <h2>Shadow would-have-acted diff</h2>\
             <p class=\"muted\">no decisions yet — the decision journal is empty (no pass has \
             recorded a breach decision, or no durable journal volume is configured). Once the \
             engine judges an internet-facing workload, this report fills in over the last \
             7d.</p>\
             </body></html>";
        assert_eq!(got, want);
    }

    /// The out-of-window state (history exists, nothing in the window) is byte-stable.
    #[test]
    fn out_of_window_panel_is_byte_stable() {
        let entries = vec![breach(
            "workload/app/Pod/old",
            "exploitable — CVE-2020-0001 RCE",
            8 * 24 * 3600,
        )];
        let r = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        let got = page(&r);
        assert!(got.contains(
            "<p class=\"muted\">no breach decisions in the last 7d (the journal has older \
             history — widen the window with <code>?days=N</code>).</p>"
        ));
    }

    /// The populated diff is byte-for-byte the pre-maud `report_panel`: the headline, the
    /// would-act rows (sustained / short-lived / open, coverage-gap flag) and the left-alone
    /// rows, with the workload labels shortened and the verdict text escaped.
    #[test]
    fn populated_diff_panel_is_byte_stable() {
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
            breach("workload/app/Pod/blip", "exploitable — brief escape", 120),
            breach("workload/app/Pod/blip", "not exploitable — gone", 60),
            breach(
                "workload/app/Pod/safe",
                "not exploitable — never invoked",
                600,
            ),
        ];
        let r = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        let got = page(&r);
        // The diff headline frames both halves.
        let want_head = "<div class=\"sum\">over the last <b>7d</b> protector would have isolated \
             <b>2</b> workloads and deliberately left <b>1</b> proven-but-cleared \
             path alone. 1 short-lived (likely FP) · 1 with thin evidence \
             coverage (scrutinize first).</div>";
        assert!(got.contains(want_head), "headline byte-stable: {got}");
        // The would-act table header + the sustained/short-lived rows + coverage gap.
        assert!(got.contains(
            "<h3>Would have isolated <span class=\"muted\">(2)</span></h3>\
             <table class=\"vectors\"><thead><tr><th>Workload</th><th>Would-cut decisions</th>\
             <th>Projected cut lifetime</th><th>Evidence coverage</th><th>Latest verdict</th></tr></thead>\
             <tbody>"
        ));
        // `app/Pod/web`: sustained 2h, two decisions, CVE-backed (no gap), latest verdict.
        assert!(got.contains(
            "<tr><td><code>app/Pod/web</code></td><td>2</td>\
             <td><span class=\"sustained\">2h</span></td>\
             <td><span class=\"muted\">—</span></td>\
             <td class=\"verdict-cell\">exploitable — CVE-2021-44228 RCE</td></tr>"
        ));
        // `app/Pod/blip`: short-lived 1m, coverage gap flagged.
        assert!(
            got.contains(
                "<tr><td><code>app/Pod/blip</code></td><td>1</td>\
             <td><span class=\"shortlived\">1m (short-lived)</span></td>\
             <td><span class=\"flagged\">coverage gap</span></td>\
             <td class=\"verdict-cell\">exploitable — brief escape</td></tr>"
            ),
            "{got}"
        );
        // The left-alone trust table + `app/Pod/safe` row.
        assert!(got.contains(
            "<h3>Left alone <span class=\"muted\">(1) — proven, then cleared</span></h3>\
             <table class=\"vectors\"><thead><tr><th>Workload</th><th>Clearing verdict</th></tr></thead>\
             <tbody><tr><td><code>app/Pod/safe</code></td>\
             <td class=\"verdict-cell\">not exploitable — never invoked</td></tr></tbody></table>"
        ));
    }

    /// An open episode renders the "(open)" sustained span (never short-lived).
    #[test]
    fn open_episode_renders_open_sustained_span() {
        let entries = vec![breach(
            "workload/app/Pod/live",
            "exploitable — CVE-2023-9 active",
            30,
        )];
        let r = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        let got = page(&r);
        assert!(got.contains("<span class=\"sustained\">30s (open)</span>"));
        // An open episode is never rendered through the short-lived span (the FP tone).
        assert!(!got.contains("class=\"shortlived\""));
    }

    /// The "every proven path cleared" placeholder shows when there are no would-acts.
    #[test]
    fn no_would_acts_renders_the_cleared_placeholder() {
        let entries = vec![breach(
            "workload/app/Pod/safe",
            "not exploitable — never invoked",
            600,
        )];
        let r = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        let got = page(&r);
        assert!(got.contains(
            "<tr><td class=\"muted\" colspan=\"5\">none — every proven path was cleared</td></tr>"
        ));
        assert!(!got.contains("<td class=\"muted\" colspan=\"2\">none</td>"));
    }

    /// A hostile verdict/workload string is auto-escaped (defence in depth, ADR-0019).
    #[test]
    fn untrusted_verdict_text_is_escaped() {
        let entries = vec![breach(
            "workload/app/Pod/x",
            "exploitable — <script>alert(1)</script> & more",
            30,
        )];
        let r = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        let got = page(&r);
        assert!(
            !got.contains("<script>alert(1)</script>"),
            "raw tag escaped"
        );
        assert!(got.contains("&lt;script&gt;alert(1)&lt;/script&gt; &amp; more"));
    }

    /// JEF-176: the rendered `/report` never leaks an `ADR-`/`JEF-` ref.
    #[test]
    fn report_never_leaks_internal_refs() {
        let entries = vec![
            breach(
                "workload/app/Pod/web",
                "exploitable — CVE-2021-44228 RCE",
                60,
            ),
            breach("workload/api/Pod/svc", "not exploitable — cleared", 120),
        ];
        let r = aggregate_report(&entries, report_now(), WEEK, FIVE_MIN);
        for surface in [
            page(&r),
            page(&aggregate_report(&[], report_now(), WEEK, FIVE_MIN)),
        ] {
            assert!(!surface.contains("ADR-"), "no ADR- leak: {surface}");
            assert!(!surface.contains("JEF-"), "no JEF- leak: {surface}");
        }
    }

    /// ADR-0019 boundary guard: the report component takes only its props.
    #[test]
    fn report_imports_no_engine_domain_type() {
        let _: fn(&ReportProps) -> Markup = report;
    }
}
