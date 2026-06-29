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

use super::state::{
    BakeStats, Findings, JudgementLog, ModelHealth, Readiness, ReadinessConfig, ReversionLog,
    derive_readiness,
};
use view_model::props::{StatusStripProps, Tab};

/// The light-theme stylesheet, generated from the `docs/STYLEGUIDE.md` tokens. Served
/// same-origin via `include_str!` — no third-party CSS (the zero-egress / no-CDN rule).
const DASHBOARD_CSS: &str = include_str!("../../../web/dist/dashboard.css");

/// The zero-dependency client script: `<details>` expand persistence + `/fragment` polling
/// that preserves scroll/expansion. Served same-origin.
const DASHBOARD_JS: &str = include_str!("../../../web/dist/dashboard.js");

/// The blurb shown on each phase-2 stub tab, so the nav is honest about what is coming.
const TRUST_BLURB: &str = "Would-have-acted: the arm/don't-arm evidence \u{2014} would-cut (sustained-first, short-lived \
     = likely FP, coverage-gap = scrutinise) vs left-alone (the trust half).";
const READINESS_BLURB: &str = "Coverage detail: one row per decision input (model / KEV / EPSS / Falco / eBPF / journal / \
     arm-state) with state, why it matters, and the env var to enable it.";
const ACTIVITY_BLURB: &str = "Audit: the self-reverted cuts (the safety story) plus the judgement ring (prompt/reply per \
     judgement, for debugging the model).";

/// The shared, read-only state the dashboard renders from — the SAME `Arc` handles the engine
/// writes each pass. The dashboard never mutates them; it only snapshots. Cheaply cloneable.
#[derive(Clone)]
pub struct DashboardState {
    /// The proven-chain findings snapshot (verdicts resolved at read time) + the per-pass
    /// freshness / bake / readiness-config / model-health the engine stamps.
    pub findings: Arc<Findings>,
    /// The bounded judgement ring (prompt + reply per judgement) for the verbatim "show model
    /// prompt" disclosure.
    pub judgements: Arc<JudgementLog>,
    /// The self-reverted-cuts ring (the audit/safety story) — read by the phase-2 Activity tab.
    #[allow(dead_code)]
    pub reversions: Arc<ReversionLog>,
    /// The cluster label shown in the strip.
    pub cluster: String,
}

impl DashboardState {
    /// Build the live readiness snapshot from the findings handle's config + per-pass health.
    fn readiness(&self) -> Readiness {
        let config: ReadinessConfig = self.findings.readiness_config();
        let health: ModelHealth = self.findings.model_health();
        let bake: BakeStats = self.findings.bake();
        let last_pass: Option<SystemTime> = self.findings.last_pass();
        derive_readiness(&config, health, &bake, last_pass)
    }

    /// Build the whole Findings view props from the live state.
    fn findings_view(&self) -> view_model::props::FindingsViewProps {
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

    /// Build the persistent status strip alone (for the phase-2 stub tabs).
    fn status_strip(&self) -> StatusStripProps {
        let readiness = self.readiness();
        view_model::build_status_strip(self.cluster.clone(), &readiness, self.findings.last_pass())
    }
}

/// The tab query parameter (`?tab=trust`). Defaults to Findings.
#[derive(serde::Deserialize, Default)]
struct TabQuery {
    tab: Option<String>,
}

impl TabQuery {
    fn resolve(&self) -> Tab {
        match self.tab.as_deref() {
            Some("trust") => Tab::Trust,
            Some("readiness") => Tab::Readiness,
            Some("activity") => Tab::Activity,
            _ => Tab::Findings,
        }
    }
}

/// The blurb for a stub tab.
fn stub_blurb(tab: Tab) -> &'static str {
    match tab {
        Tab::Trust => TRUST_BLURB,
        Tab::Readiness => READINESS_BLURB,
        Tab::Activity => ACTIVITY_BLURB,
        Tab::Findings => "",
    }
}

/// `GET /` — the full page for the requested tab (default Findings).
async fn index(State(state): State<DashboardState>, Query(q): Query<TabQuery>) -> Html<String> {
    let tab = q.resolve();
    let markup = match tab {
        Tab::Findings => page::findings_page(&state.findings_view()),
        other => page::stub_page(&state.status_strip(), other, stub_blurb(other)),
    };
    Html(markup.into_string())
}

/// `GET /fragment` — only the live-region inner content, for the JS to swap in place
/// (preserving scroll/expansion). Re-pulls readiness so a model that just went down flips the
/// banner immediately (brief §7).
async fn fragment(State(state): State<DashboardState>, Query(q): Query<TabQuery>) -> Html<String> {
    let tab = q.resolve();
    let markup = match tab {
        Tab::Findings => page::findings_fragment(&state.findings_view()),
        other => page::stub_fragment(&state.status_strip(), other, stub_blurb(other)),
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
