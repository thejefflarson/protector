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
//! (#1 honest-calm, #2 uncertain/awaiting-not-green, #6 escaping) are asserted at render in
//! `engine/src/engine/dashboard/tests.rs`. (The former per-finding "no-blank-evidence" rule was
//! dropped — a finding with no evidence now renders nothing rather than an implied-absent marker;
//! the model-judging / coverage honesty invariants are unaffected.)

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

/// Guard against the scan silently missing a component: every component the boundary checks must
/// be present in the scanned set. Extended for the phase-2 views (Trust / Readiness / Activity) and
/// the Admission/policy view (the webhook floor) so a new view can never slip past the
/// no-domain-import + no-inline-style scans.
#[test]
fn the_scan_covers_every_component_including_the_phase2_views() {
    let names: Vec<String> = component_files()
        .iter()
        .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(String::from))
        .collect();
    for required in [
        "findings_view.rs",
        "finding_row.rs",
        "finding_detail.rs",
        "evidence.rs",
        "status_strip.rs",
        "nav.rs",
        // phase 2:
        "trust_view.rs",
        "readiness_view.rs",
        "activity_view.rs",
        // the webhook floor:
        "admission_view.rs",
    ] {
        assert!(
            names.iter().any(|n| n == required),
            "the component boundary scan must include {required} (found: {names:?})"
        );
    }
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

/// Replace the contents of every `/* … */` block comment with spaces, preserving newlines (so
/// line numbers are unchanged). CSS has only block comments, so this is sufficient.
fn strip_block_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut in_comment = false;
    while i < bytes.len() {
        if !in_comment && i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            in_comment = true;
            out.push(' ');
            out.push(' ');
            i += 2;
        } else if in_comment && i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
            in_comment = false;
            out.push(' ');
            out.push(' ');
            i += 2;
        } else {
            let c = bytes[i] as char;
            out.push(if in_comment && c != '\n' { ' ' } else { c });
            i += 1;
        }
    }
    out
}

#[test]
fn stylesheet_uses_tokens_not_stray_raw_px() {
    // JEF-256: sizing/spacing must come from tokens (--space-*, --fs/--lh-*, geometry), not
    // ad-hoc raw px values scattered through the rules. Mirrors the no-raw-hex spirit: raw `px`
    // is allowed ONLY inside the `:root { … }` token-definition block (where the tokens are
    // declared); anywhere else it is a stray one-off and fails the build.
    let css = repo_root().join("engine/web/dist/dashboard.css");
    let raw = std::fs::read_to_string(&css).unwrap_or_else(|e| panic!("reading {css:?}: {e}"));
    // Blank out `/* … */` comments (CSS comments are always block form), preserving newlines so
    // line numbers stay accurate — a comment that mentions "4px" must not trip the guard.
    let src = strip_block_comments(&raw);

    // Find the `:root { … }` token block span so we can exempt it.
    let root_open = src
        .find(":root")
        .and_then(|i| src[i..].find('{').map(|j| i + j));
    let (root_start, root_end) = match root_open {
        Some(open) => {
            let close = src[open..]
                .find('}')
                .map(|j| open + j)
                .expect(":root block is closed");
            (open, close)
        }
        None => (0, 0),
    };

    let mut offenders: Vec<String> = Vec::new();
    let mut offset = 0usize;
    for (n, line) in src.lines().enumerate() {
        let line_start = offset;
        offset += line.len() + 1; // +1 for the stripped '\n'
        // Skip lines that fall inside the :root token block.
        if line_start >= root_start && line_start <= root_end {
            continue;
        }
        // A stray raw px is a digit immediately followed by `px` (e.g. `12px`). Token references
        // (`var(--space-2)`) and unitless / rem / % / ch values are fine. Comments are already
        // blanked out above.
        let bytes = line.as_bytes();
        for (k, w) in bytes.windows(2).enumerate() {
            if w == b"px" && k > 0 && bytes[k - 1].is_ascii_digit() {
                offenders.push(format!("{}:{}  {}", css.display(), n + 1, line.trim()));
                break;
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the stylesheet must size everything from tokens — no stray raw px outside :root \
         (JEF-256):\n{}",
        offenders.join("\n")
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
