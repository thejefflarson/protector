//! Dashboard honesty / boundary guards (ADR-0019, cut over to Preact by ADR-0025). These are
//! SOURCE-level guards over the SERVER-RENDERED shell that survives the v4 cutover (JEF-398):
//! the persistent status strip + the tab nav (the maud view *body* renderers are deleted; the
//! client renders every body from `/api/*.json`).
//!
//! - **#4 component boundary** — a file under `dashboard/components/` must import NO
//!   `engine::`/`state::`/`graph::`/`reason::` domain type. Components receive only their
//!   `Props` (the view_model/component split). They may import `crate::engine::dashboard::
//!   view_model::props` (the props ARE the contract) and `maud`.
//! - **#5 no inline style** — no component (or the page shell) emits an inline `style=`/`<style>`;
//!   every visual is a class mapped to a token in `docs/STYLEGUIDE.md`.
//!
//! The file-size cap (#7) is guarded by `file_size_guard.rs`. The honesty invariants (#1 honest-
//! calm, #2 uncertain/awaiting-not-green, #6 escaping) are asserted at the JSON-props boundary
//! (`engine/src/engine/dashboard/view_model/props/serialize_tests.rs`, `dashboard/api_json_tests.rs`)
//! and in the client `vitest` suite — the seam the Preact client consumes.

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

/// Guard against the scan silently missing a component: every SERVER-RENDERED shell component the
/// boundary checks must be present in the scanned set. After the v4 cutover (JEF-398) the only
/// server-rendered components are the persistent status strip and the tab nav — the maud view
/// *body* renderers are deleted (the client renders every body from `/api/*.json`). This still
/// guards that neither shell component can slip past the no-domain-import + no-inline-style scans.
#[test]
fn the_scan_covers_every_server_rendered_shell_component() {
    let names: Vec<String> = component_files()
        .iter()
        .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(String::from))
        .collect();
    for required in [
        // the calm-when-blind first-paint strip:
        "status_strip.rs",
        // the tab nav:
        "nav.rs",
    ] {
        assert!(
            names.iter().any(|n| n == required),
            "the component boundary scan must include {required} (found: {names:?})"
        );
    }
    // The maud view-body renderers were deleted in the cutover — assert they are GONE so the shell
    // never silently regrows a server-rendered body (the client owns bodies now).
    for gone in [
        "findings_view.rs",
        "finding_row.rs",
        "finding_detail.rs",
        "evidence.rs",
        "alerts_view.rs",
        "action_view.rs",
        "readiness_view.rs",
        "admission_view.rs",
    ] {
        assert!(
            !names.iter().any(|n| n == gone),
            "the maud view-body renderer {gone} must stay deleted (ADR-0025 / JEF-398) — the client \
             renders every body from /api/*.json; found: {names:?}"
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

#[test]
fn page_serves_the_preact_bundle_same_origin_with_a_mount_point() {
    // ADR-0025: the maud shell carries the v4 client mount (`dash-root`) and loads the built
    // bundle same-origin (no CDN). The server-rendered page stays intact behind it (the
    // status strip still paints before JS runs).
    let page = read_engine_src("engine/dashboard/page.rs");
    assert!(
        page.contains("dash-root"),
        "page renders the Preact client mount point (#dash-root)"
    );
    assert!(
        page.contains("/assets/dashboard.js"),
        "page loads the built bundle from its own origin (no CDN — zero-egress)"
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
fn served_stylesheet_exists_and_is_same_origin() {
    // The CSS is served via include_str! from web/dist — it must exist and carry no off-origin
    // reference (no CDN, zero-egress). The JS bundle's same-origin guard lives in
    // `dashboard_web_guards.rs`, which allowlists the W3C XML-namespace URIs the Preact
    // reconciler embeds (namespace constants, not fetches) — ADR-0025.
    let css = repo_root().join("engine/web/dist/dashboard.css");
    let css_src = std::fs::read_to_string(&css).unwrap_or_else(|e| panic!("reading {css:?}: {e}"));
    assert!(
        !css_src.contains("@import url(http") && !css_src.contains("//fonts."),
        "the stylesheet imports no third-party CSS (zero-egress)"
    );
}

#[test]
fn active_tab_has_a_raised_filled_highlight_not_colour_alone() {
    // Item 3: the active tab is clearly highlighted — a raised surface fill + a stronger accent
    // rail + bold weight, so it reads in greyscale too (meaning not by colour alone). Tokens only.
    let css = repo_root().join("engine/web/dist/dashboard.css");
    let raw = std::fs::read_to_string(&css).unwrap_or_else(|e| panic!("reading {css:?}: {e}"));
    let src = strip_block_comments(&raw);
    let active = src
        .find(".tab-active {")
        .map(|i| {
            let rest = &src[i..];
            &rest[..rest.find('}').unwrap()]
        })
        .expect(".tab-active block exists");
    assert!(
        active.contains("background: var(--surface-raised)"),
        "the active tab carries a raised/filled surface (item 3)"
    );
    assert!(
        active.contains("font-weight: var(--fw-bold)"),
        "weight stays — meaning not by colour alone"
    );
    assert!(
        active.contains("var(--mode-enforce)"),
        "the accent rail stays"
    );
}

#[test]
fn brand_and_nav_align_to_the_table_expander_glyph() {
    // Item 4: the strip brand and the nav-tab row left-align with the table's `+` expander glyph
    // (NOT the page edge). A shared --brand-indent token reproduces the `+`'s x (the view gutter +
    // the .cell-expand left pad + the .expander pad) and is applied to BOTH .strip and .tabs.
    let css = repo_root().join("engine/web/dist/dashboard.css");
    let raw = std::fs::read_to_string(&css).unwrap_or_else(|e| panic!("reading {css:?}: {e}"));
    let src = strip_block_comments(&raw);
    assert!(
        src.contains("--brand-indent:"),
        "the shared brand-indent token is defined"
    );
    let strip = src
        .find(".strip {")
        .map(|i| {
            let rest = &src[i..];
            &rest[..rest.find('}').unwrap()]
        })
        .expect(".strip block exists");
    assert!(
        strip.contains("var(--brand-indent)"),
        "the strip's left pad uses the brand indent (item 4)"
    );
    let tabs = src
        .find(".tabs {")
        .map(|i| {
            let rest = &src[i..];
            &rest[..rest.find('}').unwrap()]
        })
        .expect(".tabs block exists");
    assert!(
        tabs.contains("var(--brand-indent)"),
        "the tab row's left pad uses the brand indent (item 4)"
    );
}

/// Extract the declaration block for a selector `sel` (matched as `sel {`) from the
/// comment-stripped CSS, or panic if the selector is missing.
fn block<'a>(src: &'a str, sel: &str) -> &'a str {
    let needle = format!("{sel} {{");
    let i = src
        .find(&needle)
        .unwrap_or_else(|| panic!("`{sel}` block exists"));
    let rest = &src[i..];
    &rest[..rest.find('}').unwrap()]
}

#[test]
fn v4_transitional_states_are_tokenized_and_honest() {
    // JEF-401: the Preact client (ADR-0025) added states maud never had — a first-load "connecting…",
    // the load-bearing "not updating" stale banner, and the one-shot cleared-row tombstone. After the
    // JEF-398 cutover their classes carried NO CSS (off colour, no padding). This pins them to the
    // token system and to the honesty register: the stale banner is a distinct NON-GREEN warning, and
    // the calm states never borrow the cleared/green token.
    let css = repo_root().join("engine/web/dist/dashboard.css");
    let raw = std::fs::read_to_string(&css).unwrap_or_else(|e| panic!("reading {css:?}: {e}"));
    let src = strip_block_comments(&raw);

    // Every v4 transitional class the client emits must be styled (not a dangling, unstyled class).
    for sel in [
        ".dash-conn",
        ".dash-conn-msg",
        ".dash-conn-connecting",
        ".dash-conn-stale",
        ".row-tombstone",
        ".tombstone",
    ] {
        assert!(
            src.contains(&format!("{sel} {{")) || src.contains(&format!("{sel}::")),
            "the v4 transitional class `{sel}` must be styled (JEF-401)"
        );
    }

    // The stale banner is the load-bearing honesty case (ADR-0016 / invariant #1): it must register
    // as a distinct NON-GREEN warning — an amber keyline + tint + amber ink — never the cleared green
    // and never plain calm body text. Assert the warning tokens are present and green is absent.
    let stale = block(&src, ".dash-conn-stale");
    assert!(
        stale.contains("var(--posture-uncertain)"),
        "the stale banner uses the amber warning colour (non-green)"
    );
    assert!(
        stale.contains("border-left") && stale.contains("padding"),
        "the stale banner has a keyline + padding so it reads as a deliberate warning, not body text"
    );
    assert!(
        !stale.contains("--posture-cleared") && !stale.contains("--cov-present"),
        "the stale banner must NEVER be the cleared/green token (invariant #1)"
    );

    // The connecting message is calm/muted — and likewise never the cleared green.
    let connecting = block(&src, ".dash-conn-connecting");
    assert!(
        !connecting.contains("--posture-cleared"),
        "the connecting message is calm, never a false all-clear green"
    );
}
