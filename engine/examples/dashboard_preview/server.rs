//! The example's own axum router: disk-served assets + public render path + dev livereload.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::Query;
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};

use crate::render::{render_json, render_page, resolve_tab};
use crate::samples::DEV_LIVERELOAD_JS;
use crate::scenarios::Scenario;

/// Process-start nonce: a fresh value each launch, so a cargo-watch restart (new process)
/// changes the `/dev/reload` token and the browser refreshes onto the rebuilt binary.
static START_NONCE: std::sync::OnceLock<u128> = std::sync::OnceLock::new();

fn start_nonce() -> u128 {
    *START_NONCE.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    })
}

/// Absolute path to a `web/dist/<name>` asset, resolved from `CARGO_MANIFEST_DIR` so it works
/// from `cargo run` regardless of the shell's cwd.
pub(crate) fn dist_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("web")
        .join("dist")
        .join(name)
}

/// Read an asset from disk per request. On a read error, return the error text so a missing
/// file is obvious in the browser rather than silently empty.
fn read_asset(name: &str) -> String {
    let path = dist_path(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| format!("/* dashboard_preview: failed to read {path:?}: {e} */"))
}

/// The `?scenario=` query.
#[derive(serde::Deserialize, Default)]
pub(crate) struct PreviewQuery {
    scenario: Option<String>,
    tab: Option<String>,
}

/// The asset's mtime as nanos-since-epoch, or 0 if it can't be read.
fn asset_mtime(name: &str) -> u128 {
    std::fs::metadata(dist_path(name))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

pub(crate) async fn index(Query(q): Query<PreviewQuery>) -> Html<String> {
    let state = Scenario::parse(q.scenario.as_deref()).build();
    Html(render_page(&state, resolve_tab(q.tab.as_deref())))
}

/// `GET /api/{tab}.json` — the scenario's read-only view-model snapshot, so the Preact client the
/// preview serves renders the same body production does. The tab is taken from the path segment.
pub(crate) async fn api_json(
    axum::extract::Path(file): axum::extract::Path<String>,
    Query(q): Query<PreviewQuery>,
) -> Response {
    let state = Scenario::parse(q.scenario.as_deref()).build();
    let tab = resolve_tab(file.strip_suffix(".json"));
    (
        [(header::CONTENT_TYPE, "application/json")],
        render_json(&state, tab),
    )
        .into_response()
}

/// `GET /assets/dashboard.css` — read from disk, per request (the hot-reload point).
pub(crate) async fn dashboard_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        read_asset("dashboard.css"),
    )
        .into_response()
}

/// `GET /assets/dashboard.js` — read from disk, per request, with the dev-livereload IIFE
/// APPENDED. The IIFE is kept ONLY here; it is never written to the repo's `dashboard.js`.
pub(crate) async fn dashboard_js() -> Response {
    let body = format!("{}\n{}", read_asset("dashboard.js"), DEV_LIVERELOAD_JS);
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        body,
    )
        .into_response()
}

/// `GET /dev/reload` — a token = the process-start nonce combined with the mtimes of the two
/// assets. Changes on a CSS/JS save (mtime) OR a cargo-watch restart (nonce).
pub(crate) async fn dev_reload() -> Response {
    let token = format!(
        "{}-{}-{}",
        start_nonce(),
        asset_mtime("dashboard.css"),
        asset_mtime("dashboard.js"),
    );
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], token).into_response()
}
