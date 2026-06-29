//! Structural guard tests for the v2 dashboard (ported from JEF-208, extended for JEF-255) —
//! cheap grep-style invariants over the dashboard's own source + asset files, SCOPED to the
//! dashboard (they never walk the rest of the repo). They fail the build the moment the
//! ADR-0019 boundaries regress:
//!
//! 1. a raw hex color outside the `:root{…}` token block in `dashboard.css`;
//! 2. an inline `<style>` reappearing in any dashboard render path;
//! 3. a presentational `components/*` module *importing* an `engine::` domain type; and
//! 4. (JEF-255) a `PreEscaped` outside the `chips` allowlist — the rewrite targets zero
//!    unescaped HTML, with only the byte-stable structural/entity constants in `chips`.

use std::path::{Path, PathBuf};

use crate::engine::dashboard::DASHBOARD_CSS;

/// The dashboard source directory, resolved from the crate manifest dir so the test runs from
/// any working directory.
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

/// The production (non-test) half of a source file: everything before the first `#[cfg(test)]`.
fn production_source(src: &str) -> &str {
    match src.find("#[cfg(test)]") {
        Some(i) => &src[..i],
        None => src,
    }
}

/// (a) No raw hex color appears in `dashboard.css` outside the single `:root{ … }` token block.
#[test]
fn no_raw_hex_outside_root_in_dashboard_css() {
    let css = DASHBOARD_CSS;
    let root_open = css.find(":root").expect(":root token block present");
    let brace = css[root_open..]
        .find('{')
        .map(|o| root_open + o)
        .expect(":root has an opening brace");
    let root_end = css[brace..]
        .find('}')
        .map(|c| brace + c)
        .expect(":root has a closing brace");

    for (lineno, line) in css.lines().enumerate() {
        let line_start = line.as_ptr() as usize - css.as_ptr() as usize;
        let inside_root = line_start > root_open && line_start < root_end;
        if inside_root {
            continue;
        }
        assert!(
            !regex_lite_hex(line),
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

/// (b) No inline `<style>` reappears in any dashboard render path.
#[test]
fn no_inline_style_in_any_dashboard_render_path() {
    for path in rs_files(&dashboard_dir()) {
        if path.components().any(|c| c.as_os_str() == "tests") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("source readable");
        let prod = production_source(&src);
        for (lineno, line) in prod.lines().enumerate() {
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

/// Drop a `//` line/doc comment from a source line.
fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

/// (c) A presentational `components/*` module must not IMPORT an `engine::` domain type
/// (ADR-0019): a component receives only its `Props`.
#[test]
fn no_component_imports_an_engine_domain_type() {
    const DOMAIN_MODS: [&str; 7] = [
        "crate::engine::graph",
        "crate::engine::journal",
        "crate::engine::reason",
        "crate::engine::respond",
        "crate::engine::actuator",
        "crate::engine::detect",
        "crate::engine::policy_log",
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

/// (d) JEF-255: no `PreEscaped` (unescaped HTML) outside the `chips` allowlist. The rewrite
/// targets zero unescaped HTML; only the byte-stable structural/entity constants in
/// `components/chips.rs` (`<!doctype html>`, `&nbsp;`) may use it.
#[test]
fn no_preescaped_outside_chips_allowlist() {
    for path in rs_files(&dashboard_dir()) {
        if path.components().any(|c| c.as_os_str() == "tests") {
            continue;
        }
        // The single allowlisted home for the structural/entity constants.
        if path.file_name().is_some_and(|f| f == "chips.rs")
            && path.components().any(|c| c.as_os_str() == "components")
        {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("source readable");
        let prod = production_source(&src);
        for (lineno, line) in prod.lines().enumerate() {
            let code = strip_line_comment(line);
            assert!(
                !code.contains("PreEscaped"),
                "PreEscaped (unescaped HTML) outside the chips allowlist: {} (line {}).\n\
                 Render through a maud `{{ }}` brace so the value is auto-escaped.",
                path.display(),
                lineno + 1
            );
        }
    }
}
