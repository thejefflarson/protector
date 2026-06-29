//! Dashboard honesty / boundary guards (ADR-0019, design brief §9). These are SOURCE-level
//! guards that complement the render-level invariant tests in the dashboard module:
//!
//! - **#4 component boundary** — a file under `dashboard/components/` must import NO
//!   `engine::`/`state::`/`graph::`/`reason::` domain type. Components receive only their
//!   `Props` (the view_model/component split). They may import `crate::engine::dashboard::
//!   view_model::props` (the props ARE the contract) and `maud`.
//! - **#5 no inline style** — no component (or any served asset/markup source) emits an inline
//!   `style=`/`<style>`; every visual is a class mapped to a token in `docs/STYLEGUIDE.md`.
//!
//! The file-size cap (#7) is guarded by `file_size_guard.rs`. The remaining invariants
//! (#1 honest-calm, #2 uncertain/awaiting-not-green, #3 no-blank-evidence, #6 escaping) are
//! asserted at render in `engine/src/engine/dashboard/tests.rs`.

use std::path::{Path, PathBuf};

/// The repo root: the parent of the engine crate's manifest dir.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("engine crate has a parent (the repo root)")
        .to_path_buf()
}

/// Read a first-party dashboard source file, relative to the engine crate's `src`.
fn read_engine_src(rel: &str) -> String {
    let path = repo_root().join("engine/src").join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path:?}: {e}"))
}

/// Collect every `.rs` file directly under `dashboard/components/`.
fn component_files() -> Vec<PathBuf> {
    let dir = repo_root().join("engine/src/engine/dashboard/components");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading {dir:?}: {e}"))
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    assert!(
        !out.is_empty(),
        "found no component files under {dir:?} — the guard would pass vacuously"
    );
    out
}

/// Strip `//`-line comments from a source line, so an explanatory comment that names a domain
/// type doesn't trip the import guard. Block comments are not used for domain references here.
fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

#[test]
fn components_import_no_domain_types() {
    // The forbidden module roots. A component must not reach into the engine's domain — only
    // the props contract (which lives under `view_model::props`).
    let forbidden = [
        "engine::graph",
        "engine::reason",
        "engine::state",
        "engine::respond",
        "engine::observe",
        "engine::journal",
        "crate::engine::graph",
        "crate::engine::reason",
        "crate::engine::state",
        "super::super::state",
        "super::super::graph",
        // a bare `state::` / `graph::` path
        "use crate::engine::state",
        "use crate::engine::graph",
    ];
    let mut offenders: Vec<String> = Vec::new();
    for file in component_files() {
        let src = std::fs::read_to_string(&file).unwrap();
        for (n, raw) in src.lines().enumerate() {
            let line = strip_line_comment(raw);
            // The one allowed engine path: the props contract.
            if line.contains("view_model::props") {
                continue;
            }
            for needle in forbidden {
                if line.contains(needle) {
                    offenders.push(format!("{}:{}  {}", file.display(), n + 1, raw.trim()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "components must import no engine/state domain type (ADR-0019 invariant #4) — only \
         `view_model::props`:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn components_emit_no_inline_style() {
    let mut offenders: Vec<String> = Vec::new();
    for file in component_files() {
        let src = std::fs::read_to_string(&file).unwrap();
        for (n, raw) in src.lines().enumerate() {
            let line = strip_line_comment(raw);
            // maud inline-style would appear as a `style=` attribute or a literal `<style>`.
            if line.contains("style=") || line.contains("<style") {
                offenders.push(format!("{}:{}  {}", file.display(), n + 1, raw.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "components must not emit inline `style=`/`<style>` (invariant #5) — use a class mapped \
         to a STYLEGUIDE token:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn page_composition_emits_no_inline_style() {
    // The page shell composes components; it must also stay token-driven (no inline style).
    let page = read_engine_src("engine/dashboard/page.rs");
    assert!(
        !page.contains("style="),
        "page.rs must not emit inline style"
    );
    assert!(
        !page.contains("<style"),
        "page.rs must not embed a <style> block"
    );
    // It must link the same-origin stylesheet (no third-party CSS — zero egress).
    assert!(
        page.contains("/assets/dashboard.css"),
        "page links the same-origin stylesheet"
    );
    assert!(
        !page.contains("http://") && !page.contains("https://"),
        "page links nothing off-origin (zero-egress)"
    );
}

#[test]
fn served_assets_exist_and_are_same_origin() {
    // The CSS/JS are served via include_str! from web/dist — they must exist and carry no
    // off-origin reference (no CDN, no external fetch beyond the same-origin /fragment).
    let css = repo_root().join("engine/web/dist/dashboard.css");
    let js = repo_root().join("engine/web/dist/dashboard.js");
    let css_src = std::fs::read_to_string(&css).unwrap_or_else(|e| panic!("reading {css:?}: {e}"));
    let js_src = std::fs::read_to_string(&js).unwrap_or_else(|e| panic!("reading {js:?}: {e}"));
    assert!(
        !css_src.contains("@import url(http") && !css_src.contains("//fonts."),
        "the stylesheet imports no third-party CSS (zero-egress)"
    );
    // The JS only talks to its own origin's /fragment.
    assert!(
        !js_src.contains("http://") && !js_src.contains("https://"),
        "the client script makes no off-origin request (zero-egress)"
    );
    assert!(
        js_src.contains("/fragment"),
        "the client script polls the same-origin /fragment"
    );
}
