//! The findings dashboard: a read-only view of the engine's current proven chains and
//! their disposition — built mainly to surface the **latent-foothold** case (ADR-0009),
//! the exposable front doors that are propose-only and want a human.
//!
//! This is the dashboard's module root and its ONLY layer that touches engine domain
//! state (ADR-0019): it owns the axum `Router`, the route handlers, and `DashboardState`,
//! reads the shared `Findings` / journals, and re-exports the public surface other engine
//! modules import from `dashboard`. The presentation is split React-style:
//!
//! - [`model`] holds the shared domain DATA the engine writes and the dashboard reads.
//! - [`view_model`] shapes that domain state into plain `Props` (the data layer), and hosts
//!   the readiness / report aggregation that `/readiness` + `/report.json` serialize.
//! - [`components`] are pure `maud` renderers (`Props -> Markup`); they import no
//!   `engine::` domain type.
//! - [`page`] composes components into the full page and the `/fragment` live region.
//!
//! The dashboard is now fully on the maud component split — there is no remaining
//! string-concat `legacy` module; every rendered surface is auto-escaped maud (ADR-0019).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};

use crate::engine::journal::DecisionJournal;
use crate::engine::policy_log::{PolicyDecisionLog, PolicyDecisionRecord};

pub mod components;
pub(crate) mod model;
mod page;
pub mod view_model;

#[cfg(test)]
mod tests;

// The public surface other engine modules import from `dashboard` (mod.rs is the only place
// engine domain state is touched). The engine-facing DATA types live in `model`; the
// readiness / report aggregation lives in the `view_model` data layer. Re-exported here so
// the stable `dashboard::` paths callers use keep resolving (ADR-0019).
pub use model::{
    BakeStats, Finding, Findings, Judgement, JudgementLog, ModelHealth, ReadinessConfig,
    ReversionLog, ReversionRecord, VerdictStore,
};
pub use view_model::readiness_data::Readiness;
pub use view_model::report_data::{Report, ReportQuery};

use page::{render_fragment, render_html};
use view_model::readiness_data::derive_readiness;
use view_model::report_data::{DEFAULT_SHORT_LIVED_SECS, DEFAULT_WINDOW_HOURS, aggregate_report};
use view_model::{judgements_props, policy_props, report_props};

/// Shared state for the dashboard's HTML view: the findings handle plus the reversions
/// ring (JEF-141), so the rendered page can show lifted cuts alongside the findings.
#[derive(Clone)]
struct DashboardState {
    findings: Arc<Findings>,
    reversions: Arc<ReversionLog>,
}

/// The LIVE readiness snapshot (JEF-160) from the shared findings handle — the same data
/// the HTML panel and `/readiness` render. Pure over the engine's config summary + live
/// state (model health, this pass's bake, last-pass freshness); no model call.
fn readiness_of(findings: &Findings) -> Readiness {
    derive_readiness(
        &findings.readiness_config(),
        findings.model_health(),
        &findings.bake(),
        findings.last_pass(),
    )
}

async fn html_view(State(state): State<DashboardState>) -> Html<String> {
    Html(render_html(
        &state.findings.snapshot(),
        state.findings.is_armed(),
        &state.findings.bake(),
        &state.reversions.snapshot(),
        state.findings.last_pass(),
        &readiness_of(&state.findings),
    ))
}

/// The same-origin incremental-refresh fragment (JEF-180): the banner + findings live
/// region the page poll swaps in place. Read-only, presentation-only; no new egress.
async fn fragment_view(State(findings): State<Arc<Findings>>) -> Html<String> {
    Html(render_fragment(
        &findings.snapshot(),
        findings.is_armed(),
        findings.last_pass(),
        &readiness_of(&findings),
    ))
}

/// The readiness / coverage panel as JSON (JEF-160) — the same per-input LIVE state the
/// HTML panel shows, for scripting / alerting. On its own route so the `/findings`
/// contract is unchanged. Read-only; presence/health only, no values.
async fn readiness_view(State(findings): State<Arc<Findings>>) -> Json<Readiness> {
    Json(readiness_of(&findings))
}

async fn json_view(State(findings): State<Arc<Findings>>) -> Json<Vec<Finding>> {
    Json(findings.snapshot())
}

/// The recent-reversions view as JSON (JEF-141) — the machine-readable form of the
/// lifted-cuts panel, on its own route so the `/findings` contract is unchanged.
async fn reversions_view(
    State(reversions): State<Arc<ReversionLog>>,
) -> Json<Vec<ReversionRecord>> {
    Json(reversions.snapshot())
}

/// The behavioral-bake snapshot as JSON (JEF-48) — the machine-readable form of the
/// dashboard panel, so the bake's exit criteria can be scraped/asserted, not only
/// eyeballed. Kept on its own route so the `/findings` array contract is unchanged.
async fn bake_view(State(findings): State<Arc<Findings>>) -> Json<BakeStats> {
    Json(findings.bake())
}

/// The `/judgements` HTML view (JEF-161): the human "why" — one card per recent
/// judgement, led by the posture chip + the model's prose, the raw prompt behind an
/// expander. The machine-readable form is `/judgements.json`.
async fn judgements_html_view(State(journal): State<Arc<JudgementLog>>) -> Html<String> {
    Html(components::judgements(&judgements_props(&journal.snapshot())).into_string())
}

/// The `/judgements.json` view: the diagnostic JSON (full prompt + raw reply + verdict
/// per recent judgement), unchanged from the prior `/judgements` contract — only the path
/// moved when the human HTML view took over `/judgements` (JEF-161).
async fn judgements_json_view(State(journal): State<Arc<JudgementLog>>) -> Json<Vec<Judgement>> {
    Json(journal.snapshot())
}

/// The `/policy` HTML view (JEF-226): the webhook's recent admission decisions — signature
/// / mesh / enforce-authz audit vs deny — one row per resolved decision. The machine-readable
/// form is `/policy.json`. Read-only; complements the aggregate `/metrics` counter.
async fn policy_html_view(State(log): State<Arc<PolicyDecisionLog>>) -> Html<String> {
    Html(components::policy(&policy_props(&log.snapshot())).into_string())
}

/// The `/policy.json` view (JEF-226): the recent admission decisions as machine-readable
/// JSON (policy / decision / subject / namespace / reason / timestamp per record), so the
/// per-event decision log can be scraped/asserted, not only eyeballed.
async fn policy_json_view(
    State(log): State<Arc<PolicyDecisionLog>>,
) -> Json<Vec<PolicyDecisionRecord>> {
    Json(log.snapshot())
}

/// Replay the durable decision journal and aggregate the would-have-acted report over
/// the request's window (JEF-143). Read-only; the journal is append-only, so each
/// request sees the current durable history (pre-restart on disk + this run's writes).
fn build_report(journal: &DecisionJournal, query: &ReportQuery) -> Report {
    aggregate_report(
        &journal.replay(),
        SystemTime::now(),
        query.window(),
        query.short_lived(),
    )
}

/// Aggregate the would-have-acted report over the DEFAULT window from a journal handle
/// (JEF-143), for the engine to mirror its headline counts to OTLP per pass — the same
/// figures `/report` shows by default, the in-process mirror like the bake counts. A
/// disabled journal replays nothing, so this is an empty report (all-zero headline).
pub fn default_window_report(journal: &DecisionJournal) -> Report {
    aggregate_report(
        &journal.replay(),
        SystemTime::now(),
        Duration::from_secs(DEFAULT_WINDOW_HOURS * 3600),
        Duration::from_secs(DEFAULT_SHORT_LIVED_SECS),
    )
}

/// The `/report` HTML view (JEF-143): the shadow would-have-acted diff over a rolling
/// window. Window + thresholds come from the query string (see [`ReportQuery`]).
async fn report_html_view(
    State(journal): State<Arc<DecisionJournal>>,
    Query(query): Query<ReportQuery>,
) -> Html<String> {
    Html(components::report(&report_props(&build_report(&journal, &query))).into_string())
}

/// The `/report.json` view (JEF-143): the same aggregation as machine-readable JSON, so
/// the would-have-acted diff can be scraped/asserted, not only eyeballed.
async fn report_json_view(
    State(journal): State<Arc<DecisionJournal>>,
    Query(query): Query<ReportQuery>,
) -> Json<Report> {
    Json(build_report(&journal, &query))
}

/// The vendored, self-hosted graph renderer (beautiful-mermaid + elkjs, bundled in
/// `web/dist` and embedded in the binary). Served same-origin so the dashboard never
/// loads third-party JS — see the import in [`render_html`].
const BEAUTIFUL_MERMAID_JS: &str = include_str!("../../../web/dist/beautiful-mermaid.js");

async fn beautiful_mermaid_js() -> ([(axum::http::HeaderName, &'static str); 1], &'static str) {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        BEAUTIFUL_MERMAID_JS,
    )
}

/// The dashboard stylesheet (JEF-203): the page CSS extracted from the former inline
/// `<style>` blocks into a self-hosted asset, embedded in the binary and served
/// same-origin at `/assets/dashboard.css` (no third-party CSS, zero egress).
pub(crate) const DASHBOARD_CSS: &str = include_str!("../../../web/dist/dashboard.css");

async fn dashboard_css() -> ([(axum::http::HeaderName, &'static str); 1], &'static str) {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8")],
        DASHBOARD_CSS,
    )
}

/// The dashboard page script (JEF-203): the Mermaid-hydrate / details-persist /
/// incremental-poll module extracted from the former inline `<script type="module">`
/// into a self-hosted asset, embedded in the binary and served same-origin at
/// `/assets/dashboard.js` (the import it carries resolves to the likewise self-hosted
/// `/assets/beautiful-mermaid.js`; zero egress).
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

/// Serve the findings dashboard (`/` HTML, `/findings` JSON, `/bake` JSON, `/readiness`
/// JSON) plus the human `/judgements` HTML "why" view (JEF-161) with its diagnostic
/// `/judgements.json` (full prompt + raw reply + verdict per recent judgement), the
/// `/reversions` JSON (lifted cuts + why, JEF-141), the
/// `/report` + `/report.json` shadow would-have-acted diff (JEF-143), and the
/// `/policy` HTML + `/policy.json` admission-decision log (JEF-226). Read-only;
/// cluster-facing glue around the tested classification + aggregation. The `/readiness`
/// view (JEF-160) reports each decision input's LIVE presence/health for alerting.
pub async fn serve_dashboard(
    addr: SocketAddr,
    findings: Arc<Findings>,
    judgements: Arc<JudgementLog>,
    reversions: Arc<ReversionLog>,
    journal: Arc<DecisionJournal>,
    admission: Arc<PolicyDecisionLog>,
) -> anyhow::Result<()> {
    let html_state = DashboardState {
        findings: findings.clone(),
        reversions: reversions.clone(),
    };
    let app = Router::new()
        .route("/findings", get(json_view))
        .route("/bake", get(bake_view))
        .route("/readiness", get(readiness_view))
        // JEF-180: the same-origin live-region fragment the page poll swaps in place,
        // replacing the 30s full-page meta-refresh. New route; no existing route changes.
        .route("/fragment", get(fragment_view))
        .route("/assets/beautiful-mermaid.js", get(beautiful_mermaid_js))
        // JEF-203: the dashboard's self-hosted CSS + JS, served same-origin from the
        // embedded `web/dist` (no inline <style>/<script>, no third-party assets).
        .route("/assets/dashboard.css", get(dashboard_css))
        .route("/assets/dashboard.js", get(dashboard_js))
        .with_state(findings)
        .merge(
            Router::new()
                .route("/judgements", get(judgements_html_view))
                .route("/judgements.json", get(judgements_json_view))
                .with_state(judgements),
        )
        .merge(
            Router::new()
                .route("/reversions", get(reversions_view))
                .with_state(reversions),
        )
        // JEF-226: the webhook's admission-decision log (HTML + JSON). New routes; no
        // existing route changes. Its own state handle (the shared decision ring).
        .merge(
            Router::new()
                .route("/policy", get(policy_html_view))
                .route("/policy.json", get(policy_json_view))
                .with_state(admission),
        )
        .merge(
            Router::new()
                .route("/report", get(report_html_view))
                .route("/report.json", get(report_json_view))
                .with_state(journal),
        )
        .merge(
            Router::new()
                .route("/", get(html_view))
                .with_state(html_state),
        );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "findings dashboard listening");
    axum::serve(listener, app).await?;
    Ok(())
}
