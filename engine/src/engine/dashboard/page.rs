//! The v2 page composition (ADR-0019, JEF-255): assembles the pure components into ONE dense
//! page — no tabs. The four kept capabilities are layers of a single page: the status line,
//! the BREACH queue (only when >0), the dense ENDPOINTS table (rows expand to the "why"
//! detail), the compact ADMISSION strip, and the demoted ENGINE-INTERNALS disclosure.
//!
//! This file shapes the per-entry props (grouping findings by entry, deriving posture from the
//! TYPED verdict SSOT, threading each entry's raw prompt in from the judgement log) and orders
//! the rows breach-first. Every rendered child is auto-escaped maud; there is no string-concat
//! and no `PreEscaped` outside the byte-stable `chips` constants.

use std::collections::BTreeMap;
use std::time::SystemTime;

use maud::{Markup, html};

use crate::engine::dashboard::components;
use crate::engine::dashboard::components::chips;
use crate::engine::dashboard::model::{BakeStats, Finding, ReversionRecord};
use crate::engine::dashboard::view_model::admission::{AdmissionProps, admission_props};
use crate::engine::dashboard::view_model::entry::{DetailProps, RowProps, detail_props, row_props};
use crate::engine::dashboard::view_model::internals::internals_props;
use crate::engine::dashboard::view_model::posture::Posture;
use crate::engine::dashboard::view_model::readiness_data::Readiness;
use crate::engine::dashboard::view_model::status::status_props;
use crate::engine::policy_log::{DecisionTallies, PolicyDecisionRecord};

/// Everything the dynamic live region needs in one bundle, so the full page and the
/// `/fragment` poll share ONE builder (they can never drift). `prompts` maps an entry key to
/// the raw model prompt captured for it (from the judgement log), threaded into the detail.
pub(crate) struct LiveInputs<'a> {
    pub findings: &'a [Finding],
    pub last_pass: Option<SystemTime>,
    pub readiness: &'a Readiness,
    pub admission_records: &'a [PolicyDecisionRecord],
    pub admission_tallies: DecisionTallies,
    pub reversions: &'a [ReversionRecord],
    pub bake: &'a BakeStats,
    pub prompts: &'a BTreeMap<String, String>,
}

/// Group the breach-relevant findings by entry and build the ordered (row, detail) prop pairs,
/// breach-first. Posture is the loudest typed verdict across an entry's chains (the SSOT).
fn entry_pairs(
    findings: &[Finding],
    prompts: &BTreeMap<String, String>,
) -> Vec<(RowProps, DetailProps)> {
    let mut by_entry: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
    for f in findings.iter().filter(|f| f.breach_relevant) {
        by_entry.entry(f.entry.as_str()).or_default().push(f);
    }
    let mut pairs: Vec<(RowProps, DetailProps)> = by_entry
        .iter()
        .map(|(entry, fs)| {
            let prompt = prompts.get(*entry).cloned();
            (row_props(entry, fs), detail_props(entry, fs, prompt))
        })
        .collect();
    // Order breach-first, then by endpoint key for a stable total order (a view, never a
    // gate — ADR-0016). `sort_by` is stable.
    pairs.sort_by(|a, b| {
        posture_rank(b.0.posture)
            .cmp(&posture_rank(a.0.posture))
            .then_with(|| a.0.entry.cmp(&b.0.entry))
    });
    pairs
}

fn posture_rank(p: Posture) -> u8 {
    match p {
        Posture::Awaiting => 0,
        Posture::Safe => 1,
        Posture::Breach => 2,
    }
}

/// The dynamic live region (JEF-255 + the JEF-180 incremental-poll seam): the status line, the
/// breach queue, the dense endpoints table, the admission strip, and the internals disclosure.
/// The full page embeds this verbatim; `/fragment` returns just this and the poll swaps the
/// `#live` container in place.
fn live_region(input: &LiveInputs) -> Markup {
    let pairs = entry_pairs(input.findings, input.prompts);
    let breaches: Vec<(RowProps, DetailProps)> = pairs
        .iter()
        .filter(|(row, _)| row.posture.is_breach())
        .cloned()
        .collect();

    let status = status_props(input.findings, input.last_pass, input.readiness);
    let admission: AdmissionProps =
        admission_props(input.admission_records, input.admission_tallies);
    let internals = internals_props(input.readiness, input.reversions, input.bake);

    html! {
        div id="live" {
            (components::status_line::status_line(&status))
            (components::breach_queue::breach_queue(&breaches))
            section class="endpoints-section" aria-label="exposed endpoints" {
                h2 { "Endpoints" }
                (components::endpoints::endpoints_table(&pairs))
            }
            (components::admission::admission(&admission))
            (components::internals::internals(&internals))
        }
    }
}

/// Render the whole page: the `<html>` shell (self-hosted CSS + JS, zero egress) wrapping the
/// dynamic live region. No tabs, no separate "why"/report/graph surfaces — one dense page.
pub(crate) fn render_html(input: &LiveInputs) -> String {
    let live = live_region(input);
    let page = html! {
        (chips::doctype())
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "protector" }
                link rel="stylesheet" href="/assets/dashboard.css";
                script type="module" src="/assets/dashboard.js" {}
            }
            body {
                header class="page-head" { h1 { "protector" } }
                (live)
            }
        }
    };
    page.into_string()
}

/// The incremental-refresh fragment (JEF-180): JUST the live region — byte-for-byte the same
/// markup the full page embeds (both from [`live_region`]). The same-origin poll fetches this
/// and swaps the `#live` container in place. No new egress; same presentation-only data.
pub(crate) fn render_fragment(input: &LiveInputs) -> String {
    live_region(input).into_string()
}
