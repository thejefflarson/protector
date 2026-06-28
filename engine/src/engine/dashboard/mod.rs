//! The protector dashboard (v2, JEF-255): a single dense page that answers ONE question —
//! "is anything actually compromised right now, and if not, am I covered or blind?" The unit
//! is an exposed ENTRY with a model-decided posture (BREACH / SAFE / AWAITING).
//!
//! This is the dashboard's module root and its ONLY layer that touches engine domain state
//! (ADR-0019): it owns the axum `Router`, the route handlers, and `DashboardState`, reads the
//! shared `Findings` / journals / admission log, and re-exports the public surface other engine
//! modules import from `dashboard`. The presentation is split React-style:
//!
//! - [`model`] holds the shared domain DATA the engine writes and the dashboard reads.
//! - [`view_model`] shapes that domain state into plain `Props` (the data layer); it also hosts
//!   the readiness snapshot and the would-have-acted report aggregation the engine mirrors to
//!   OTLP per pass ([`default_window_report`]).
//! - [`components`] are pure `maud` renderers (`Props -> Markup`); they import no `engine::`
//!   domain type.
//! - [`page`] composes the components into the one dense page and the `/fragment` live region.
//!
//! The v2 rewrite (JEF-255) replaced the v1 tabbed dashboard (findings/report/policy/
//! judgements/attack-vectors, ~9.5k LOC of Rust + a 1.5 MB vendored Mermaid bundle) with this
//! single-page IA: a typed-verdict posture SSOT, the attack path as a text hop-list (Mermaid
//! retired entirely), and only the four kept capabilities as layers of one page. The served
//! routes are `/` (HTML), `/fragment` (the incremental-poll live region), and the self-hosted
//! `/assets/dashboard.{css,js}` — the JSON / report / policy / judgements tabs are gone.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::extract::State;
use axum::response::Html;
use axum::routing::get;

use crate::engine::journal::DecisionJournal;
use crate::engine::policy_log::PolicyDecisionLog;

pub mod components;
pub(crate) mod model;
mod page;
pub(crate) mod recency;
pub mod view_model;

#[cfg(test)]
mod tests;

// The public surface other engine modules import from `dashboard` (mod.rs is the only place
// engine domain state is touched). The engine-facing DATA types live in `model`; the readiness
// snapshot and report aggregation live in the `view_model` data layer. Re-exported here so the
// stable `dashboard::` paths callers use keep resolving (ADR-0019).
pub use model::{
    BakeStats, Finding, Findings, Judgement, JudgementLog, ModelHealth, ReadinessConfig,
    ReversionLog, ReversionRecord, VerdictStore,
};
// The per-entry recency / Δ types (JEF-201) the engine writes each pass.
pub use recency::{Delta, RecencyInfo, StoredPosture};
pub use view_model::readiness_data::Readiness;
pub use view_model::report_data::Report;

use page::{LiveInputs, render_fragment, render_html};
use view_model::readiness_data::derive_readiness;
use view_model::report_data::{DEFAULT_SHORT_LIVED_SECS, DEFAULT_WINDOW_HOURS, aggregate_report};

/// Shared state for the dashboard's single page: the findings handle plus the per-pass
/// auxiliary feeds the one dense page composes — the judgement log (for each entry's raw
/// model prompt), the reversions ring, and the admission-decision log. Cloned (all `Arc`) into
/// both the `/` and `/fragment` handlers so they render the identical live region.
#[derive(Clone)]
struct DashboardState {
    findings: Arc<Findings>,
    judgements: Arc<JudgementLog>,
    reversions: Arc<ReversionLog>,
    admission: Arc<PolicyDecisionLog>,
}

/// The LIVE readiness snapshot (JEF-160) from the shared findings handle — the coverage data
/// the status line and the internals disclosure read. Pure over the engine's config summary +
/// live state (model health, this pass's bake, last-pass freshness); no model call.
fn readiness_of(findings: &Findings) -> Readiness {
    derive_readiness(
        &findings.readiness_config(),
        findings.model_health(),
        &findings.bake(),
        findings.last_pass(),
    )
}

/// The most-recent raw model prompt per entry (JEF-255), from the judgement log — threaded into
/// each endpoint's detail so the "why" surface can reveal the verbatim prompt behind the
/// verdict. The log is newest-first, so the first prompt seen for an entry is the latest.
fn prompts_by_entry(journal: &JudgementLog) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for j in journal.snapshot() {
        if let Some(prompt) = j.prompt {
            map.entry(j.entry).or_insert(prompt);
        }
    }
    map
}

async fn html_view(State(state): State<DashboardState>) -> Html<String> {
    let findings = state.findings.snapshot();
    let readiness = readiness_of(&state.findings);
    let admission = state.admission.snapshot();
    let reversions = state.reversions.snapshot();
    let bake = state.findings.bake();
    let prompts = prompts_by_entry(&state.judgements);
    Html(render_html(&LiveInputs {
        findings: &findings,
        last_pass: state.findings.last_pass(),
        readiness: &readiness,
        admission_records: &admission,
        admission_tallies: state.admission.tallies(),
        reversions: &reversions,
        bake: &bake,
        prompts: &prompts,
    }))
}

/// The same-origin incremental-refresh fragment (JEF-180): the `#live` region the page poll
/// swaps in place. Read-only, presentation-only; no new egress.
async fn fragment_view(State(state): State<DashboardState>) -> Html<String> {
    let findings = state.findings.snapshot();
    let readiness = readiness_of(&state.findings);
    let admission = state.admission.snapshot();
    let reversions = state.reversions.snapshot();
    let bake = state.findings.bake();
    let prompts = prompts_by_entry(&state.judgements);
    Html(render_fragment(&LiveInputs {
        findings: &findings,
        last_pass: state.findings.last_pass(),
        readiness: &readiness,
        admission_records: &admission,
        admission_tallies: state.admission.tallies(),
        reversions: &reversions,
        bake: &bake,
        prompts: &prompts,
    }))
}

/// Aggregate the would-have-acted report over the DEFAULT window from a journal handle
/// (JEF-143), for the engine to mirror its headline counts to OTLP per pass — the in-process
/// metrics mirror like the bake counts. A disabled journal replays nothing, so this is an empty
/// report (all-zero headline). The HTML `/report` tab the v1 dashboard served was dropped in
/// the JEF-255 rewrite; this aggregation stays solely to feed the OTLP mirror in `engine::mod`.
pub fn default_window_report(journal: &DecisionJournal) -> Report {
    aggregate_report(
        &journal.replay(),
        SystemTime::now(),
        Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600),
        Duration::from_secs(DEFAULT_SHORT_LIVED_SECS),
    )
}

/// The dashboard stylesheet (JEF-203): the page CSS, embedded in the binary and served
/// same-origin at `/assets/dashboard.css` (no third-party CSS, zero egress).
pub(crate) const DASHBOARD_CSS: &str = include_str!("../../../web/dist/dashboard.css");

async fn dashboard_css() -> ([(axum::http::HeaderName, &'static str); 1], &'static str) {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8")],
        DASHBOARD_CSS,
    )
}

/// The dashboard page script (JEF-203): the row-expand / details-persist / incremental-poll
/// module, embedded in the binary and served same-origin at `/assets/dashboard.js`. The v2
/// rewrite (JEF-255) removed the Mermaid hydrate path — the attack path is text now.
pub(crate) const DASHBOARD_JS: &str = include_str!("../../../web/dist/dashboard.js");

async fn dashboard_js() -> ([(axum::http::HeaderName, &'static str); 1], &'static str) {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        DASHBOARD_JS,
    )
}

/// Serve the single-page dashboard (JEF-255): `/` (HTML), `/fragment` (the same-origin
/// incremental-poll live region), and the self-hosted `/assets/dashboard.{css,js}`. Read-only,
/// cluster-facing glue around the tested classification + aggregation; zero egress. The
/// `judgements` / `reversions` / `admission` handles back the page's prompt expander, the
/// internals lifted-cuts list, and the admission strip respectively. The `journal` argument is
/// retained for the call-site signature even though no route reads it directly (the OTLP report
/// mirror replays it in `engine::mod` via [`default_window_report`]).
pub async fn serve_dashboard(
    addr: SocketAddr,
    findings: Arc<Findings>,
    judgements: Arc<JudgementLog>,
    reversions: Arc<ReversionLog>,
    journal: Arc<DecisionJournal>,
    admission: Arc<PolicyDecisionLog>,
) -> anyhow::Result<()> {
    // The durable journal is replayed for the OTLP would-have-acted mirror in `engine::mod`,
    // not by any HTTP route here (the v1 `/report` tab was dropped in JEF-255). Bind it to `_`
    // so the public `serve_dashboard` signature other call sites use stays unchanged.
    let _ = journal;
    let state = DashboardState {
        findings,
        judgements,
        reversions,
        admission,
    };
    let app = Router::new()
        .route("/", get(html_view))
        // JEF-180: the same-origin live-region fragment the page poll swaps in place.
        .route("/fragment", get(fragment_view))
        // JEF-203: the dashboard's self-hosted CSS + JS, served same-origin from the embedded
        // `web/dist` (no inline <style>/<script>, no third-party assets, zero egress).
        .route("/assets/dashboard.css", get(dashboard_css))
        .route("/assets/dashboard.js", get(dashboard_js))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "protector dashboard listening");
    axum::serve(listener, app).await?;
    Ok(())
}
