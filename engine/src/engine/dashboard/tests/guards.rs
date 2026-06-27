//! Structural guard tests for the dashboard (JEF-208) — cheap grep-style invariants over the
//! dashboard's own source + asset files, SCOPED to the dashboard (they never walk the rest of
//! the repo). They fail the build the moment the ADR-0019 boundaries regress:
//!
//! 1. a raw hex color outside the `:root{…}` token block in `dashboard.css`;
//! 2. an inline `<style>` reappearing in any dashboard render path; or
//! 3. a presentational `components/*` module *importing* an `engine::` domain type.
//!
//! These are the "do not let it drift back" rails for the maud migration: the token system,
//! the zero-inline-CSS asset delivery (JEF-203), and the renderer/domain boundary.

use std::path::{Path, PathBuf};

use crate::engine::dashboard::DASHBOARD_CSS;

/// The dashboard source directory (`engine/src/engine/dashboard`), resolved from the crate
/// manifest dir so the test runs from any working directory.
fn dashboard_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/engine/dashboard")
}

/// Every `.rs` file under a directory, recursively.
fn rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("dashboard dir readable") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            out.extend(rs_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

/// The production (non-test) half of a source file: everything before the first
/// `#[cfg(test)]` marker. The dashboard's components each keep their tests in a single
/// bottom `#[cfg(test)] mod tests`, so this cleanly excludes the test-only imports (which DO
/// legitimately name engine domain types to build fixtures).
fn production_source(src: &str) -> &str {
    match src.find("#[cfg(test)]") {
        Some(i) => &src[..i],
        None => src,
    }
}

/// (a) No raw hex color (`#abc` / `#aabbcc`) appears in `dashboard.css` outside the single
/// `:root{ … }` token block. The token block is the palette's one source of truth; every
/// rule body must consume a `var(--…)`, never a literal — see docs/STYLEGUIDE.md.
#[test]
fn no_raw_hex_outside_root_in_dashboard_css() {
    let css = DASHBOARD_CSS;
    let root_open = css.find(":root").expect(":root token block present");
    // The `:root` block runs from `:root` to its closing brace (the first `}` after `{`).
    let brace = css[root_open..]
        .find('{')
        .map(|o| root_open + o)
        .expect(":root has an opening brace");
    let root_end = css[brace..]
        .find('}')
        .map(|c| brace + c)
        .expect(":root has a closing brace");

    let hex = regex_lite_hex;
    for (lineno, line) in css.lines().enumerate() {
        // Byte offset of this line's start, to tell whether it sits inside the :root block.
        let line_start = line.as_ptr() as usize - css.as_ptr() as usize;
        let inside_root = line_start > root_open && line_start < root_end;
        if inside_root {
            continue;
        }
        assert!(
            !hex(line),
            "raw hex color outside :root in dashboard.css (line {}): {line}\n\
             Add a primitive token in :root and consume it via var(--…).",
            lineno + 1
        );
    }
}

/// A tiny hand-rolled scan for `#` followed by 3 or 6 hex digits — avoids a regex dep.
fn regex_lite_hex(line: &str) -> bool {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'#' {
            continue;
        }
        let run = bytes[i + 1..]
            .iter()
            .take_while(|c| c.is_ascii_hexdigit())
            .count();
        if run >= 3 {
            return true;
        }
    }
    false
}

/// (b) No inline `<style>` reappears in any dashboard render path. The CSS is delivered as a
/// self-hosted, same-origin asset (JEF-203); an inline `<style>` would regress that (and the
/// zero-egress / CSP posture). We scan every dashboard `.rs` source for the literal tag.
#[test]
fn no_inline_style_in_any_dashboard_render_path() {
    for path in rs_files(&dashboard_dir()) {
        // Scope to RENDER paths: skip the `tests/` tree (whose assertions name the tag as a
        // string literal). Only the production half of each render file is checked.
        if path.components().any(|c| c.as_os_str() == "tests") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("source readable");
        let prod = production_source(&src);
        for (lineno, line) in prod.lines().enumerate() {
            // Doc/line comments legitimately MENTION `<style>` to describe its absence; the
            // guard targets EMITTED markup, so strip the comment tail before scanning.
            let code = strip_line_comment(line);
            assert!(
                !code.contains("<style>") && !code.contains("<style "),
                "inline <style> reappeared in a dashboard render path: {} (line {})",
                path.display(),
                lineno + 1
            );
        }
    }
}

/// Drop a `//` line/doc comment from a source line (whatever follows the first `//`). Good
/// enough for the guard: the dashboard never embeds `//` inside a string the renderer emits.
fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

/// (c) A presentational `components/*` module must not IMPORT an `engine::` domain type
/// (ADR-0019): a component receives only its `Props`. We flag any production `use
/// crate::engine::{graph,journal,reason,respond,...}` in a component file — the domain layer
/// belongs in `view_model`/`mod.rs`, never the renderer. (Pure string helpers that call a
/// fully-qualified static like `crate::engine::graph::NodeKey::short_of(&str) -> &str` import
/// no type and are out of scope; the boundary is about a domain TYPE entering the view.)
#[test]
fn no_component_imports_an_engine_domain_type() {
    // The `engine::` submodules that hold domain types the renderer must never import. The
    // dashboard's own `crate::engine::dashboard::{components,view_model,model}` paths are the
    // presentation/data layers, not domain types, so they are explicitly allowed.
    const DOMAIN_MODS: [&str; 6] = [
        "crate::engine::graph",
        "crate::engine::journal",
        "crate::engine::reason",
        "crate::engine::respond",
        "crate::engine::actuator",
        "crate::engine::detect",
    ];

    let components = dashboard_dir().join("components");
    for path in rs_files(&components) {
        let src = std::fs::read_to_string(&path).expect("component source readable");
        let prod = production_source(&src);
        for line in prod.lines() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with("use ") {
                continue;
            }
            for domain in DOMAIN_MODS {
                assert!(
                    !trimmed.contains(domain),
                    "presentational component imports an engine domain type: {} -> `{}`.\n\
                     Move the domain dependency to view_model; the renderer takes only its Props.",
                    path.display(),
                    trimmed.trim()
                );
            }
        }
    }
}
