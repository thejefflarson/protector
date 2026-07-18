//! The operator dashboard (ADR-0019, cut over to Preact by ADR-0025): the presentation platform
//! for the engine's read-only output state. Zero-egress, same-origin only — the security graph and
//! evidence never leave the cluster. Presentation is a VIEW, never a decision gate (ADR-0016).
//!
//! Under the v4 cutover (ADR-0025 / JEF-398) the engine is **Preact-only**: the maud *body*
//! renderers and the per-tab flag are gone. Under JEF-408 (superseding ADR-0025 / see ADR-0027)
//! the LAST server-rendered body parts — the status strip and the tab nav — moved to the client
//! too: the server now emits a ROOT-ONLY document shell (`<head>` + the `#dash-root` mount), and the
//! bundled Preact client renders ALL body HTML (strip, nav, and every view body) reconciling from
//! the `/api/{tab}.json` snapshots.
//!
//! The module follows the retained data half of the React-like split:
//! - [`view_model`] shapes `state::` domain state into plain `Props` (the only layer touching
//!   `engine::`/`state::`) — the JSON contract the client consumes (ADR-0025); the honesty tokens
//!   (all-clear / watching / judging-state) are server-derived here and shipped decided;
//! - [`page`] composes the ROOT-ONLY document shell (head + the Preact `#dash-root` mount point);
//! - this `mod.rs` wires the axum routes, holds [`DashboardState`], and serves it
//!   ([`serve_dashboard`]) behind `PROTECTOR_DASHBOARD_ADDR`, reading the same `state::` handles
//!   the engine holds.

pub mod page;
mod security_headers;
pub mod view_model;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;

use super::journal::DecisionJournal;
use super::policy_log::PolicyDecisionLog;
use super::state::{
    Findings, JudgementLog, ModelHealth, Readiness, ReadinessConfig, ReversionLog,
    default_window_report, derive_readiness,
};
use view_model::props::{
    ActionViewProps, AdmissionViewProps, AlertsViewProps, FindingsViewProps, ReadinessViewProps,
    StatusStripProps, Tab,
};

/// The light-theme stylesheet, generated from the `docs/STYLEGUIDE.md` tokens. Served
/// same-origin via `include_str!` — no third-party CSS (the zero-egress / no-CDN rule).
const DASHBOARD_CSS: &str = include_str!("../../../web/dist/dashboard.css");

/// The bundled Preact client (ADR-0025), built from `engine/web/src/` at build time (gitignored,
/// never committed). It mounts into the server-rendered `#dash-root` and reconciles each view from
/// the same-origin `/api/{tab}.json` snapshots. Served same-origin via `include_str!` — the only
/// client network call is that same-origin fetch (CSP `connect-src 'self'`), no CDN.
const DASHBOARD_JS: &str = include_str!("../../../web/dist/dashboard.js");

/// The shared, read-only state the dashboard renders from — the SAME `Arc` handles the engine
/// writes each pass. The dashboard never mutates them; it only snapshots. Cheaply cloneable.
#[derive(Clone)]
pub struct DashboardState {
    /// The proven-chain findings snapshot (verdicts resolved at read time) + the per-pass
    /// freshness / bake / readiness-config / model-health the engine stamps.
    pub findings: Arc<Findings>,
    /// The bounded judgement ring (prompt + reply per judgement) for the verbatim "show model
    /// prompt" disclosure (Findings drill-in + the Action tab's judgement-audit section).
    pub judgements: Arc<JudgementLog>,
    /// The self-reverted-cuts ring (the audit/safety story) — read by the Action tab's proposed-cuts
    /// section (the reverted tail of the cut lifecycle).
    pub reversions: Arc<ReversionLog>,
    /// The durable decision journal — replayed read-only to build the Action tab's would-have-acted
    /// report. Named `decision_journal` (not `journal`) so it never collides with the
    /// `JudgementLog` the run-loop binds as `journal`.
    pub decision_journal: Arc<DecisionJournal>,
    /// The webhook's admission-decision log (JEF-226/237) — the bounded, deduped ring of policy
    /// decisions read by the Admission tab (the webhook floor). Read-only here.
    pub policy_log: Arc<PolicyDecisionLog>,
    /// The cluster label shown in the strip.
    pub cluster: String,
}

impl DashboardState {
    /// Build the live readiness snapshot from the findings handle's config + per-pass health.
    ///
    /// `pub` so the dev hot-reload preview example (`examples/dashboard_preview.rs`) can derive
    /// readiness exactly as production does without re-exporting the crate-private
    /// `state::derive_readiness`. Pure read of the handle's config/health/bake/last-pass — it
    /// makes no decision and mutates nothing (ADR-0016).
    pub fn readiness(&self) -> Readiness {
        let config: ReadinessConfig = self.findings.readiness_config();
        let health: ModelHealth = self.findings.model_health();
        let last_pass: Option<SystemTime> = self.findings.last_pass();
        let runtime = self.findings.runtime_coverage();
        // Overlay the cross-pass coverage-stall register (JEF-421): a covering runtime feed that has
        // gone dark past the debounce escalates the runtime row to `stalled`. Per-pass derivation
        // can't see the edge, so it's folded in here from the stall tracker's decided state.
        derive_readiness(&config, health, last_pass, &runtime)
            .with_coverage_stall(&self.findings.coverage_state())
    }

    /// Build the persistent status strip carrying the TRUE findings counts (brief §3/§4). The
    /// strip is shown on EVERY tab, so its honesty reading reflects the real cluster posture even
    /// on a secondary view — a breach in Findings keeps the strip non-green on Action/Readiness/
    /// Admission too. Pure read of the live handles.
    fn status_strip(&self) -> StatusStripProps {
        let findings = self.findings.snapshot();
        let judgements = self.judgements.snapshot();
        let readiness = self.readiness();
        let strip = view_model::build_status_strip(
            self.cluster.clone(),
            &findings,
            &judgements,
            &readiness,
            self.findings.last_pass(),
        );
        let (breach, uncertain) = self.signing_regression_counts();
        // Overlay the cross-pass coverage-stall register (JEF-421) so a stalled runtime feed reads
        // loud (and forbids green) on EVERY tab, exactly like a standing signing regression.
        let alert = view_model::coverage_stall_alert(&self.findings.coverage_state());
        strip
            .with_signing_regressions(breach, uncertain)
            .with_coverage_stall(alert)
    }

    /// The standing signing-regression counts `(established, cold)` from the admission-decision log
    /// (JEF-264) — folded into the persistent strip so a standing regression keeps it non-green on
    /// EVERY tab, without routing through the reachability findings pipeline.
    fn signing_regression_counts(&self) -> (usize, usize) {
        view_model::signing_regression_counts(&self.policy_log.snapshot())
    }

    /// Build the whole Findings view props from the live state.
    fn findings_view(&self) -> FindingsViewProps {
        let findings = self.findings.snapshot();
        let judgements = self.judgements.snapshot();
        let readiness = self.readiness();
        let mut view = view_model::build_findings_view(
            self.cluster.clone(),
            &findings,
            &judgements,
            &readiness,
            self.findings.last_pass(),
        );
        // The findings-derived strip carries no signing regressions of its own; fold in the
        // admission-decision log's counts so the Findings strip is non-green when a regression
        // stands too (the honesty invariant holds on every tab).
        let (breach, uncertain) = self.signing_regression_counts();
        let alert = view_model::coverage_stall_alert(&self.findings.coverage_state());
        view.strip = view
            .strip
            .with_signing_regressions(breach, uncertain)
            .with_coverage_stall(alert);
        view
    }

    /// Build the Alerts view props (JEF-323): the persistent strip + the live "alarming-now"
    /// activity events derived from the SAME per-pass findings snapshot the Findings view
    /// reads (a current-window view — runtime signals live one pass — not a persisted log) + the
    /// calm blind-node caveat for the quiet state. The strip carries the real findings counts (and
    /// the folded-in signing regressions) so its honesty reading holds on this tab too.
    fn alerts_view(&self) -> AlertsViewProps {
        let findings = self.findings.snapshot();
        let readiness = self.readiness();
        // `status_strip()` already folds in the signing-regression counts, so the Alerts strip
        // reads honestly (non-green under a standing regression) on this tab too.
        view_model::build_alerts_view(self.status_strip(), &findings, &readiness)
    }

    /// Build the Action view props (the merged Trust + Activity story): the persistent strip + the
    /// proposed cuts (the would-cut / left-alone diff aggregated read-only over the default window
    /// from the decision journal, plus the self-reverted-cuts ring) + the judgement audit (both
    /// rings newest-first).
    fn action_view(&self) -> ActionViewProps {
        let report = default_window_report(&self.decision_journal);
        let reversions = self.reversions.snapshot();
        let judgements = self.judgements.snapshot();
        view_model::build_action_view(self.status_strip(), &report, &reversions, &judgements)
    }

    /// Build the Readiness (coverage) view props: the persistent strip + one row per decision
    /// input, weakening-when-absent inputs first.
    fn readiness_view(&self) -> ReadinessViewProps {
        let readiness = self.readiness();
        view_model::build_readiness_view(self.status_strip(), &readiness)
    }

    /// Build the Admission/policy (webhook floor) view props: the persistent strip + the decision
    /// tallies header (so a healthy view is never blank) + the per-image signing inventory + the
    /// deduped decision rows (newest-first). The tallies are derived from the decision rows (the
    /// signing sweep's observation rows feed only the inventory), so the view_model shapes the whole
    /// snapshot on its own.
    fn admission_view(&self) -> AdmissionViewProps {
        let rows = self.policy_log.snapshot();
        view_model::build_admission_view(self.status_strip(), &rows)
    }
}

/// The tab query parameter (`?tab=action`). Defaults to Findings. The legacy `trust`/`activity`
/// words are kept as soft-aliases that resolve to the merged `Action` tab, so old deep-links (and a
/// Findings "show model prompt" link that still says `activity`) don't 404.
#[derive(serde::Deserialize, Default)]
struct TabQuery {
    tab: Option<String>,
}

impl TabQuery {
    fn resolve(&self) -> Tab {
        match self.tab.as_deref() {
            Some("alerts") => Tab::Alerts,
            // The merged Action tab + its legacy soft-aliases.
            Some("action") | Some("trust") | Some("activity") => Tab::Action,
            Some("readiness") => Tab::Readiness,
            Some("admission") => Tab::Admission,
            _ => Tab::Findings,
        }
    }
}

/// `GET /` — the ROOT-ONLY document shell for the requested tab (default Findings): the `<head>`
/// (cluster-labelled title + css) + the Preact `#dash-root` mount point (JEF-408, superseding
/// ADR-0025's server-rendered strip/nav). The client renders ALL body HTML — the status strip, the
/// tab nav, and the view body — reconciling from `/api/{tab}.json`. The honesty tokens (all-clear /
/// watching / judging-state) stay server-derived in that JSON; a blank before the first fetch is
/// honest (absent ≠ green). Only the cluster label (for the `<title>`) is needed here.
async fn index(State(state): State<DashboardState>, Query(q): Query<TabQuery>) -> Html<String> {
    let markup = page::page(&state.cluster, q.resolve());
    Html(markup.into_string())
}

/// Serialize a view-model's props as a `no-store` JSON response — the read-only snapshot the
/// Preact client reconciles from (ADR-0025).
///
/// This is a THIN serializer over the SAME `*ViewProps` the maud path renders — there is no
/// second DTO and NO new mapping (ADR-0025 decision (a): serde-props-as-contract), so the JSON
/// can never drift from the maud render or smuggle a decision the render doesn't make. The
/// server-derived honesty tokens (`all-clear`/`watching`, per-row `posture`, `is-cleared`, the
/// blind caveat) are already decided in the props and serialize as decided values — the client
/// performs zero honesty derivation. `Cache-Control: no-store` mirrors the CSS/JS routes: this is
/// a per-session-gated, zero-egress snapshot that must never sit in a shared edge cache (JEF-283).
fn view_json<T: Serialize>(view: T) -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Json(view)).into_response()
}

/// `GET /api/findings.json` — the read-only Findings view-model snapshot (ADR-0025). The SAME
/// props the Findings tab renders; GET-only, `no-store`, no gating field.
async fn findings_json(State(state): State<DashboardState>) -> Response {
    view_json(state.findings_view())
}

/// `GET /api/alerts.json` — the read-only Alerts view-model snapshot (ADR-0025).
async fn alerts_json(State(state): State<DashboardState>) -> Response {
    view_json(state.alerts_view())
}

/// `GET /api/action.json` — the read-only Action view-model snapshot (ADR-0025).
async fn action_json(State(state): State<DashboardState>) -> Response {
    view_json(state.action_view())
}

/// `GET /api/readiness.json` — the read-only Readiness view-model snapshot (ADR-0025).
async fn readiness_json(State(state): State<DashboardState>) -> Response {
    view_json(state.readiness_view())
}

/// `GET /api/admission.json` — the read-only Admission view-model snapshot (ADR-0025).
async fn admission_json(State(state): State<DashboardState>) -> Response {
    view_json(state.admission_view())
}

/// `GET /assets/dashboard.css` — the light-theme stylesheet, same-origin.
///
/// `Cache-Control: no-store` is load-bearing behind Cloudflare Access (JEF-283): Cloudflare
/// caches `.css`/`.js` by file extension even with no origin directive, and it caches 302s —
/// so an unauthenticated edge hit gets Access's 302→login cached against this URL and then
/// served (as HTML) to authenticated users, leaving the dashboard unstyled. no-store keeps this
/// per-session-gated asset out of the shared edge cache. (Bypasses CACHE, never AUTH.)
async fn dashboard_css() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        DASHBOARD_CSS,
    )
        .into_response()
}

/// `GET /assets/dashboard.js` — the zero-dep client script, same-origin.
/// `Cache-Control: no-store` for the same Access/edge-cache reason as the stylesheet (JEF-283).
async fn dashboard_js() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        DASHBOARD_JS,
    )
        .into_response()
}

/// Build the dashboard router with the read-only state.
///
/// Every response carries the strict same-origin CSP (ADR-0025) via a single
/// [`security_headers::set_csp`] layer — the layer covers all routes, so a route added
/// later (e.g. a `/api/*.json` snapshot) inherits it without a per-route edit.
pub fn router(state: DashboardState) -> Router {
    Router::new()
        .route("/", get(index))
        // The read-only per-view JSON snapshots the Preact client reconciles from (ADR-0025).
        // GET-only, same router state/authz as the page routes, `no-store`; each returns the
        // SAME view-model its tab renders — no write route, no new mapping, no decision field.
        .route("/api/findings.json", get(findings_json))
        .route("/api/alerts.json", get(alerts_json))
        .route("/api/action.json", get(action_json))
        .route("/api/readiness.json", get(readiness_json))
        .route("/api/admission.json", get(admission_json))
        .route("/assets/dashboard.css", get(dashboard_css))
        .route("/assets/dashboard.js", get(dashboard_js))
        .layer(axum::middleware::from_fn(security_headers::set_csp))
        .with_state(state)
}

/// Serve the dashboard over plain HTTP on `addr` until the process exits. The dashboard is an
/// in-cluster, read-only view of state the engine already holds (zero-egress); it is meant to
/// sit behind the cluster's own ingress/mesh, not face the internet directly, so it terminates
/// no TLS of its own. A bind failure is logged and the task exits — the engine loop is
/// unaffected (the dashboard is strictly observational).
pub async fn serve_dashboard(addr: SocketAddr, state: DashboardState) {
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(error) => {
            tracing::error!(%error, %addr, "dashboard: failed to bind; dashboard disabled");
            return;
        }
    };
    tracing::info!(%addr, "dashboard listening (read-only, zero-egress)");
    if let Err(error) = axum::serve(listener, router(state).into_make_service()).await {
        tracing::error!(%error, "dashboard server stopped");
    }
}

// JEF-395: HTTP-level tests for the read-only per-view JSON endpoints (ADR-0025) — same-view-model,
// GET-only, no-store, strict CSP, and the never-a-false-green honesty guard at the JSON boundary.
// These are the retained honesty proof after the v4 cutover (JEF-398): the maud-render honesty
// tests are gone because their view-model is unchanged and its guarantee is now asserted here (the
// serialized props the client consumes) + in the client `vitest` suite.
#[cfg(test)]
mod api_json_tests;

// JEF-398: page-shell tests — the Preact-only page emits, for every tab, the server-rendered strip
// + nav + the `#dash-root` mount point (calm-when-blind first paint stays server-side).
#[cfg(test)]
mod page_tests;
