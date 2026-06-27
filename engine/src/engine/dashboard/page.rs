//! The dashboard "App" (ADR-0019): the page-level composition that assembles the
//! migrated maud components (nav, banner) and the not-yet-migrated legacy panels into
//! the full page (`render_html`) and the `/fragment` live region (`live_region` /
//! `render_fragment`). As tickets 3–6 migrate each panel, the `legacy::` calls below are
//! replaced by `components::` calls — this file is where the composition lives.

use std::collections::BTreeMap;
use std::time::SystemTime;

use crate::engine::dashboard::components;
use crate::engine::dashboard::components::findings::FINDINGS_COLS as COMPONENT_FINDINGS_COLS;
use crate::engine::dashboard::legacy::*;
use crate::engine::dashboard::view_model::findings::{
    Tier, endpoint_attention_rank, endpoint_props, remediation_props, tier_of_priority,
};
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
) -> String {
    let findings_region = findings_region(findings, armed, last_pass, readiness);
    // The banner + nav are now maud components fed by the view-model (ADR-0019); the
    // findings region is still the legacy string-concat builder (migrates in tickets 3–6).
    let banner = components::banner(&banner_props(
        findings,
        armed,
        last_pass,
        &relative_time(last_pass),
        readiness.model_judging,
    ))
    .into_string();
    let nav = components::nav(&nav_props("/")).into_string();
    format!(
        "<div id=\"banner-region\">{banner}</div>\
         <h1>protector</h1>\
         {nav}\
         <div id=\"findings-region\">{findings_region}</div>",
    )
}

/// The number of columns in the dense findings table (JEF-202):
/// `tier · entry → reaches · verdict · evidence · next lever · age`. The detail row's
/// `<td colspan>` spans all of them. Canonical home is `components::findings`; re-exported
/// here for the page composition and the still-legacy render tests.
pub(crate) const FINDINGS_COLS: usize = COMPONENT_FINDINGS_COLS;

/// Wrap pre-rendered endpoint rows in the dense findings `<table>` (JEF-202) — the maud
/// `components::findings::findings_table` over the already-rendered rows.
fn findings_table(rows: &str) -> String {
    components::findings::findings_table(maud::PreEscaped(rows.to_string())).into_string()
}

/// The edge-legend glossary, collapsed behind a closed `<details>` (JEF-200) — the token
/// names stay reachable on demand, but no longer crowd the findings region as inline prose.
fn edge_legend() -> &'static str {
    "<details class=\"legend-d\"><summary>edge legend</summary>\
     <p class=\"legend\">\
     <code>mounts (direct read)</code>: the secret is mounted into the pod, read with no API call (just that one secret) · \
     <code>RBAC … (API)</code>: the pod's ServiceAccount can read via the Kubernetes API (often any secret in scope) · \
     <code>network reach</code>: a NetworkPolicy- or Linkerd-authorized connection · \
     <code>runs as</code>: assumes the ServiceAccount identity · \
     <code>escapes via</code>: a container-escape primitive to the host node</p></details>"
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
) -> String {
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

    // Remediations verb (JEF-175): answer-first phrasing — "What protector would do"
    // (shadow, proposing) vs "What protector is doing" (armed, acting) — replacing the
    // old "Proposed/Active Remediations" engine label.
    let rem_title = if armed {
        "What protector is doing"
    } else {
        "What protector would do"
    };
    let rem_body = if remediations.is_empty() {
        "<p class=\"muted\">none</p>".to_string()
    } else {
        remediations
            .iter()
            .map(|f| components::findings::remediation(&remediation_props(f, armed)).into_string())
            .collect()
    };

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

    // Partition the ranked endpoints into the answer-first split, as dense table ROWS
    // (JEF-202): "Needs attention" is the Flagged tier (the model judged a real breach);
    // "Watching" holds the Watch tier directly plus the Context tier collapsed behind a
    // single summary row. The partition keys on the SAME `endpoint_attention_rank` tier the
    // rows carry, so a row's section and its tier cell can never drift; the stable, total
    // sort above is preserved within each section.
    let mut attention_rows = String::new();
    let mut watch_rows = String::new();
    let mut context_rows = String::new();
    let mut flagged_n = 0usize;
    let mut exposed_n = 0usize; // watch + context: exposed, not flagged
    for (entry, fs) in &ranked {
        let (priority, tier) = endpoint_attention_rank(fs);
        let row = components::findings::endpoint(&endpoint_props(
            entry,
            fs,
            tier_of_priority(priority),
            last_pass,
        ))
        .into_string();
        match tier {
            Tier::Flagged => {
                flagged_n += 1;
                attention_rows.push_str(&row);
            }
            Tier::Watch => {
                exposed_n += 1;
                watch_rows.push_str(&row);
            }
            Tier::Context => {
                exposed_n += 1;
                // Context detail-group rows: HIDDEN by default behind the single context
                // summary row, marked so its group toggle reveals them as a group (JEF-202).
                // (The per-row f-detail body stays behind its own row-toggle.) Attribute
                // order is irrelevant in HTML, so prepend `hidden` to the summary <tr>.
                context_rows.push_str(
                    &row.replace("<tr class=\"f-row", "<tr hidden class=\"ctx-row f-row"),
                );
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

    // The dense findings region (JEF-202) — the primary view, leading below the banner.
    // Answer-first: a "Needs attention — N flagged" table (OMITTED entirely when nothing is
    // flagged) then a "Watching — N exposed, not flagged" table. Counts live in the headers
    // (JEF-200), so the explanatory preamble sentences are gone. On first run the guided
    // checklist replaces the whole region (preserving the JEF-160 path).
    let region = if first_run {
        components::panels::first_run(&first_run_props(readiness)).into_string()
    } else {
        let attention = if attention_rows.is_empty() {
            String::new()
        } else {
            format!(
                "<h2 id=\"attack-paths\">Needs attention <span class=\"muted\">— {flagged_n} flagged</span></h2>\
                 {}",
                findings_table(&attention_rows),
            )
        };
        // The Context tier collapses to ONE summary row that expands to its rows (JEF-202).
        let context_block = if context_rows.is_empty() {
            String::new()
        } else {
            let ctx_n = context_rows.matches("ctx-row f-row").count();
            format!(
                "<tr class=\"ctx-summary\"><td colspan=\"{FINDINGS_COLS}\">\
                 <button class=\"row-toggle ctx-toggle\" aria-expanded=\"false\" \
                 data-ctx-group=\"watching\">\
                 <span class=\"chip tier-context\">context</span> \
                 <span class=\"muted\">{ctx_n} background path{} — proven-reachable, neither \
                 flagged nor seen live</span></button></td></tr>{context_rows}",
                if ctx_n == 1 { "" } else { "s" },
            )
        };
        let watching_rows = if watch_rows.is_empty() && context_block.is_empty() {
            format!(
                "<tr><td colspan=\"{FINDINGS_COLS}\" class=\"muted\">no internet-facing \
                 service can reach a target</td></tr>"
            )
        } else {
            format!("{watch_rows}{context_block}")
        };
        let watching = format!(
            "<h2 id=\"watching\">Watching <span class=\"muted\">— {exposed_n} exposed, not \
             flagged</span></h2>{}",
            findings_table(&watching_rows),
        );
        format!(
            "{attention}{watching}{edge_legend}",
            edge_legend = edge_legend()
        )
    };
    let findings_body = region;

    // The summary line + findings body + remediations section — the per-pass content the
    // poll swaps in place (JEF-180). The wrapping `#findings-region` div is added by the
    // caller ([`live_region`]).
    format!(
        "<p class=\"sum\"><b>{rem_n}</b> {rem_word} · <b>{ep_n}</b> exposed endpoint{ep_plural} with \
         possible attack paths · last pass <b>{freshness}</b> \
         &nbsp;|&nbsp; <a href=\"/findings\">json</a></p>\
         {findings_body}\
         <h2>{rem_title} <span class=\"muted\">({rem_n})</span></h2>{rem_body}",
        rem_n = remediations.len(),
        rem_word = if armed { "active" } else { "proposed" },
        ep_n = endpoints.len(),
        ep_plural = if endpoints.len() == 1 { "" } else { "s" },
    )
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
    // The diagnostics panels are now maud components fed by the view-model (ADR-0019,
    // JEF-206); `.into_string()` composes each into the page's diagnostics region.
    let vectors_body =
        components::panels::attack_vectors(&attack_vectors_props(findings)).into_string();
    let bake_body = components::panels::bake(&bake_props(bake)).into_string();
    let reversions_body =
        components::panels::reversions(&reversions_props(reversions)).into_string();
    let readiness_body = components::panels::readiness(&readiness_props(readiness)).into_string();

    // The page CSS + JS are self-hosted static assets (JEF-203): the stylesheet at
    // /assets/dashboard.css and the module at /assets/dashboard.js, both served
    // SAME-ORIGIN from the embedded `web/dist` (zero egress, no third-party CDN). The
    // graph renderer the module imports (beautiful-mermaid, ELK layout) is likewise
    // vendored + served at /assets. (Pre-JEF-203 these were inline <style>/<script>;
    // the only rendered-output change is inline -> linked delivery.)
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <title>protector</title>\
         <link rel=\"stylesheet\" href=\"/assets/dashboard.css\">\
         <script type=\"module\" src=\"/assets/dashboard.js\"></script>\
         </head><body>\
         {live}\
         <details class=\"howto\"><summary>how protector decides</summary>\
         <p class=\"sum\">It maps every real path an attacker could walk — proven from your \
         cluster's config and live traffic, it can't invent one — then a local model judges \
         whether each is actually being exploited. A flagged breach means proven path + the \
         model saw exploitation evidence.</p></details>\
         <details class=\"diag\"{readiness_open_outer}>\
         <summary><h2 class=\"diag-h\">Engine &amp; coverage</h2></summary>\
         <details id=\"coverage\"{readiness_open}>\
         <summary><h3 class=\"diag-h\">Readiness <span class=\"muted\">(decision inputs)</span></h3></summary>\
         <p class=\"sum\">Each decision input and its LIVE state; an <b>absent</b> input that \
         <b>weakens decisions</b> is called out. \
         &nbsp;|&nbsp; <a href=\"/readiness\">json</a></p>\
         {readiness_body}\
         </details>\
         <details>\
         <summary><h3 class=\"diag-h\">What an attacker could reach</h3></summary>\
         <p class=\"sum\">What an internet-facing service can reach. \
         <b>Reachable</b> = proven the service can get there; <b>model-flagged</b> = the model \
         judged it a real breach.</p>\
         {vectors_body}\
         </details>\
         <details>\
         <summary><h3 class=\"diag-h\">Live activity the sensors saw <span class=\"muted\">(shadow)</span></h3></summary>\
         <p class=\"sum\">What the behavioral agent observed last pass (shadow — only watching); \
         <b>corroborations</b> counts findings a live signal backed up.</p>\
         {bake_body}\
         </details>\
         <details>\
         <summary><h3 class=\"diag-h\">Recently lifted <span class=\"muted\">(lifted cuts)</span></h3></summary>\
         <p class=\"sum\">Cuts the engine lifted, and why. An isolation stays only while the \
         breach lasts, then lifts on its own once the path is gone or the evidence clears. \
         &nbsp;|&nbsp; <a href=\"/reversions\">json</a></p>\
         {reversions_body}\
         </details>\
         </details>\
         </body></html>",
        live = live,
        // AC #3: a degraded/absent decision-weakening input must still surface — the
        // Readiness section (and its enclosing diagnostics region) auto-open ONLY when
        // `has_unmet()`; a healthy cluster gets a one-line summary it can expand.
        readiness_open = if readiness.has_unmet() { " open" } else { "" },
        readiness_open_outer = if readiness.has_unmet() { " open" } else { "" },
    )
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
    live_region(findings, armed, last_pass, readiness)
}
