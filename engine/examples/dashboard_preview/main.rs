//! DEV-ONLY hot-reload preview of the v4 (Preact-only) dashboard — a dev artifact, NOT part of the
//! product.
//!
//! Unlike the shipped `serve_dashboard` (which bakes the CSS/JS into the binary via
//! `include_str!`, so every visual tweak forces a full Rust rebuild), this example mounts its
//! OWN axum router that:
//!
//! - serves `/assets/dashboard.css` and `/assets/dashboard.js` by reading
//!   `engine/web/dist/*` FROM DISK on every request (path resolved relative to
//!   `CARGO_MANIFEST_DIR`), so a CSS/JS edit shows on the next browser refresh — no rebuild;
//! - renders `/` (the server SHELL: strip + nav + the Preact `#dash-root` mount) and serves the
//!   per-view `/api/{tab}.json` snapshots through the dashboard's PUBLIC render path
//!   (`view_model::build_*` + `page::page`), over the real `state::` handles, exactly as
//!   `serve_dashboard` does — so the Preact-only preview can't drift from production rendering;
//! - selects which sample state to build via `?scenario=clear|watching|breach|blind`, so every
//!   honesty state is one URL away with no code edit (default `breach`);
//! - appends a tiny dev-livereload IIFE to the served JS (kept ONLY here, never written to the
//!   repo's `dashboard.js`) that polls `/dev/reload` and calls `location.reload()` when the
//!   token changes — so a CSS/JS save (mtime change) OR a cargo-watch restart (nonce change)
//!   auto-refreshes the browser.
//!
//! Run it under cargo-watch for the full loop:
//!   `cargo watch -x 'run --example dashboard_preview'`
//! or once:
//!   `cargo run --example dashboard_preview`
//! then open http://127.0.0.1:8787/ (try `?scenario=clear|watching|breach|blind`).
//!
//! This changes NOTHING about the shipped `serve_dashboard` or the repo's `dashboard.js`.
//!
//! Split into a module directory per the CLAUDE.md 1,000-line file cap (JEF-562), decomposed by
//! preview scenario/section: [`fixtures`] (shared finding skeletons), [`sample_data`] (shared
//! journal/policy-log/bake/readiness fixtures), [`scenarios`] (one submodule per honesty state),
//! [`render`] (the public render-path calls), [`server`] (the axum handlers), and [`samples`]
//! (the sample prompt/reply + dev-livereload client).

mod fixtures;
mod render;
mod sample_data;
mod samples;
mod scenarios;
mod server;

use axum::Router;
use axum::routing::get;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(server::index))
        // The read-only per-view JSON snapshots the Preact client reconciles from (ADR-0025) — the
        // preview serves them per scenario so the client renders the same body production does.
        .route("/api/{file}", get(server::api_json))
        .route("/assets/dashboard.css", get(server::dashboard_css))
        .route("/assets/dashboard.js", get(server::dashboard_js))
        .route("/dev/reload", get(server::dev_reload));

    let addr = "127.0.0.1:8787";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("dashboard preview (Preact-only, hot-reload) on http://{addr}/  (Ctrl-C to stop)");
    println!("  scenarios: /?scenario=clear | watching | breach | blind  (default: breach)");
    println!(
        "  tabs:      /?tab=findings | alerts | action | readiness | admission  (default: findings)"
    );
    println!(
        "  assets served from disk: {:?}",
        server::dist_path("dashboard.css")
    );
    axum::serve(listener, app).await.unwrap();
}
