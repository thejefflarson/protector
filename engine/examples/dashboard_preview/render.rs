//! The public dashboard render path, called exactly as `serve_dashboard` calls it, so this
//! preview can't drift from production rendering.

use protector::engine::dashboard::view_model::props::Tab;
use protector::engine::dashboard::{DashboardState, page, view_model};

/// Resolve the `?tab=` query into a [`Tab`]. Unknown/absent falls back to Findings.
pub(crate) fn resolve_tab(tab: Option<&str>) -> Tab {
    match tab {
        Some("alerts") => Tab::Alerts,
        // The merged Action tab + its legacy soft-aliases (trust/activity), matching production.
        Some("action") | Some("trust") | Some("activity") => Tab::Action,
        Some("readiness") => Tab::Readiness,
        Some("admission") => Tab::Admission,
        Some("access") => Tab::Access,
        _ => Tab::Findings,
    }
}

/// Build the persistent status strip the same way production does — from the live findings +
/// judgement snapshots, so its honesty reading reflects the real cluster posture on every tab.
fn preview_strip(state: &DashboardState) -> view_model::props::StatusStripProps {
    view_model::build_status_strip(
        state.cluster.clone(),
        &state.findings.snapshot(),
        &state.judgements.snapshot(),
        &state.readiness(),
        state.findings.last_pass(),
    )
}

/// Build the Findings view props through the public render path.
fn preview_findings(state: &DashboardState) -> view_model::props::FindingsViewProps {
    view_model::build_findings_view(
        state.cluster.clone(),
        &state.findings.snapshot(),
        &state.judgements.snapshot(),
        &state.readiness(),
        state.findings.last_pass(),
    )
}

/// Build the merged Action view props through the public render path (the would-have-acted report
/// from the decision journal + the self-reverted-cuts ring + the judgement ring).
fn preview_action(state: &DashboardState) -> view_model::props::ActionViewProps {
    use protector::engine::state::default_window_report;
    let report = default_window_report(&state.decision_journal);
    view_model::build_action_view(
        preview_strip(state),
        &report,
        &state.reversions.snapshot(),
        &state.judgements.snapshot(),
    )
}

/// Build the live Alerts (alarming-now corroboration) view props through the public render path.
fn preview_alerts(state: &DashboardState) -> view_model::props::AlertsViewProps {
    view_model::build_alerts_view(
        preview_strip(state),
        &state.findings.snapshot(),
        &state.readiness(),
    )
}

/// Build the Readiness view props through the public render path.
fn preview_readiness(state: &DashboardState) -> view_model::props::ReadinessViewProps {
    view_model::build_readiness_view(preview_strip(state), &state.readiness())
}

/// Build the Admission view props through the public render path.
fn preview_admission(state: &DashboardState) -> view_model::props::AdmissionViewProps {
    view_model::build_admission_view(preview_strip(state), &state.policy_log.snapshot())
}

/// Build the "Access" view props through the public render path — a raw-tier preview
/// caller over the scenario's (empty) audit sink, so the preview exercises the same builder
/// production serves.
fn preview_access(state: &DashboardState) -> view_model::props::AccessViewProps {
    view_model::build_access_view(
        preview_strip(state),
        protector::engine::dashboard::auth::claims::Tier::Raw,
        &state.mcp_audit.records(),
        state.mcp_audit.is_durable(),
    )
}

/// Render the ROOT-ONLY document shell for a tab through the dashboard's PUBLIC render path (
/// superseding ADR-0025's server-rendered strip/nav): the `<head>` + the Preact `#dash-root` mount.
/// ALL body HTML — the status strip, the tab nav, and the view body — is client-rendered from the
/// `/api/{tab}.json` snapshot (served below), so this preview exercises the SAME path production serves.
pub(crate) fn render_page(state: &DashboardState, tab: Tab) -> String {
    page::page(&state.cluster, tab).into_string()
}

/// Serialize a scenario's per-view props as the `/api/{tab}.json` snapshot the Preact client
/// reconciles from — the same view-model builders production serves, so the preview can't drift.
pub(crate) fn render_json(state: &DashboardState, tab: Tab) -> String {
    match tab {
        Tab::Findings => serde_json::to_string(&preview_findings(state)),
        Tab::Alerts => serde_json::to_string(&preview_alerts(state)),
        Tab::Action => serde_json::to_string(&preview_action(state)),
        Tab::Readiness => serde_json::to_string(&preview_readiness(state)),
        Tab::Admission => serde_json::to_string(&preview_admission(state)),
        Tab::Access => serde_json::to_string(&preview_access(state)),
    }
    .unwrap_or_else(|e| format!("{{\"error\":\"preview serialize failed: {e}\"}}"))
}
