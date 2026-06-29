//! The server-rendered operator dashboard (ADR-0019): the presentation platform for the
//! engine's read-only output state. Zero-egress, same-origin only — the security graph and
//! evidence never leave the cluster. Presentation is a VIEW, never a decision gate (ADR-0016).
//!
//! The module follows the React-like split the repo conventions mandate:
//! - [`view_model`] shapes `state::` domain state into plain `Props` (the only layer touching
//!   `engine::`/`state::`);
//! - [`components`] are pure `maud` renderers (`Props -> Markup`) importing no domain type;
//! - [`page`] composes components into pages/fragments + the persistent status strip + the
//!   4-tab nav shell;
//! - this `mod.rs` wires the axum routes, holds [`DashboardState`], and serves it
//!   ([`serve_dashboard`]) behind `PROTECTOR_DASHBOARD_ADDR`, reading the same `state::` handles
//!   the engine holds.

mod components;
pub mod page;
pub mod view_model;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;

use super::journal::DecisionJournal;
use super::policy_log::PolicyDecisionLog;
use super::state::{
    BakeStats, Findings, JudgementLog, ModelHealth, Readiness, ReadinessConfig, ReversionLog,
    default_window_report, derive_readiness,
};
use view_model::props::{
    ActionViewProps, AdmissionViewProps, FindingsViewProps, ReadinessViewProps, StatusStripProps,
    Tab,
};

/// The light-theme stylesheet, generated from the `docs/STYLEGUIDE.md` tokens. Served
/// same-origin via `include_str!` — no third-party CSS (the zero-egress / no-CDN rule).
const DASHBOARD_CSS: &str = include_str!("../../../web/dist/dashboard.css");

/// The zero-dependency client script: `<details>` expand persistence + `/fragment` polling
/// that preserves scroll/expansion. Served same-origin.
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
        let bake: BakeStats = self.findings.bake();
        let last_pass: Option<SystemTime> = self.findings.last_pass();
        derive_readiness(&config, health, &bake, last_pass)
    }

    /// Build the persistent status strip carrying the TRUE findings counts (brief §3/§4). The
    /// strip is shown on EVERY tab, so its honesty reading reflects the real cluster posture even
    /// on a secondary view — a breach in Findings keeps the strip non-green on Action/Readiness/
    /// Admission too. Pure read of the live handles.
    fn status_strip(&self) -> StatusStripProps {
        let findings = self.findings.snapshot();
        let judgements = self.judgements.snapshot();
        let readiness = self.readiness();
        view_model::build_status_strip(
            self.cluster.clone(),
            &findings,
            &judgements,
            &readiness,
            self.findings.last_pass(),
        )
    }

    /// Build the whole Findings view props from the live state.
    fn findings_view(&self) -> FindingsViewProps {
        let findings = self.findings.snapshot();
        let judgements = self.judgements.snapshot();
        let readiness = self.readiness();
        view_model::build_findings_view(
            self.cluster.clone(),
            &findings,
            &judgements,
            &readiness,
            self.findings.last_pass(),
        )
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
    /// tallies header (so a healthy view is never blank) + the deduped decision rows (newest-first).
    fn admission_view(&self) -> AdmissionViewProps {
        let tallies = self.policy_log.tallies();
        let rows = self.policy_log.snapshot();
        view_model::build_admission_view(self.status_strip(), tallies, &rows)
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
            // The merged Action tab + its legacy soft-aliases.
            Some("action") | Some("trust") | Some("activity") => Tab::Action,
            Some("readiness") => Tab::Readiness,
            Some("admission") => Tab::Admission,
            _ => Tab::Findings,
        }
    }
}

/// `GET /` — the full page for the requested tab (default Findings).
async fn index(State(state): State<DashboardState>, Query(q): Query<TabQuery>) -> Html<String> {
    let markup = match q.resolve() {
        Tab::Findings => page::findings_page(&state.findings_view()),
        Tab::Action => page::action_page(&state.action_view()),
        Tab::Readiness => page::readiness_page(&state.readiness_view()),
        Tab::Admission => page::admission_page(&state.admission_view()),
    };
    Html(markup.into_string())
}

/// `GET /fragment` — only the live-region inner content, for the JS to swap in place
/// (preserving scroll/expansion). Re-pulls readiness so a model that just went down flips the
/// banner immediately (brief §7).
async fn fragment(State(state): State<DashboardState>, Query(q): Query<TabQuery>) -> Html<String> {
    let markup = match q.resolve() {
        Tab::Findings => page::findings_fragment(&state.findings_view()),
        Tab::Action => page::action_fragment(&state.action_view()),
        Tab::Readiness => page::readiness_fragment(&state.readiness_view()),
        Tab::Admission => page::admission_fragment(&state.admission_view()),
    };
    Html(markup.into_string())
}

/// `GET /assets/dashboard.css` — the light-theme stylesheet, same-origin.
async fn dashboard_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        DASHBOARD_CSS,
    )
        .into_response()
}

/// `GET /assets/dashboard.js` — the zero-dep client script, same-origin.
async fn dashboard_js() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        DASHBOARD_JS,
    )
        .into_response()
}

/// Build the dashboard router with the read-only state.
pub fn router(state: DashboardState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/fragment", get(fragment))
        .route("/assets/dashboard.css", get(dashboard_css))
        .route("/assets/dashboard.js", get(dashboard_js))
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

#[cfg(test)]
mod tests;

#[cfg(test)]
mod admission_tests;
