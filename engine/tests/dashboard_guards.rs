//! Dashboard honesty / boundary guards (ADR-0019, cut over to Preact by ADR-0025, and to a
//! ROOT-ONLY body by JEF-408). These are SOURCE-level guards over the server-emitted document shell.
//!
//! Under JEF-408 the LAST server-rendered body parts — the status strip + the tab nav — moved to the
//! client, so the `dashboard/components/` module (the pure `Props -> Markup` shell renderers) is
//! deleted: the server now emits a ROOT-ONLY body (`<head>` + the `#dash-root` mount). These guards
//! therefore pin the SHELL contract:
//!
//! - **#5 no inline style** — the page shell emits no inline `style=`/`<style>`; every visual is a
//!   class mapped to a token in `docs/STYLEGUIDE.md` (the strip's classes now live in `strip.jsx`).
//! - the body is ROOT-ONLY — no server-rendered strip / nav leaks in (they are client-rendered).
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

#[test]
fn the_server_rendered_components_stay_retired() {
    // JEF-408: the `dashboard/components/` module (the server-rendered status strip + tab nav) is
    // deleted — the client renders ALL body HTML now. Guard that neither the module nor its renderers
    // silently regrow a server-rendered body.
    let dir = repo_root().join("engine/src/engine/dashboard/components");
    assert!(
        !dir.exists(),
        "the dashboard/components module must stay deleted (JEF-408) — the strip + nav are \
         client-rendered ({dir:?} exists)"
    );
    let page = read_engine_src("engine/dashboard/page.rs");
    for gone in ["status_strip", "nav_bar", "components::"] {
        assert!(
            !page.contains(gone),
            "page.rs must not reference the retired server-rendered component `{gone}` (JEF-408)"
        );
    }
}

#[test]
fn the_body_is_root_only_no_server_strip_or_nav() {
    // JEF-408: the server body is ROOT-ONLY — no `.strip` header and no `.tabs` nav markup. Those
    // moved to the client (`strip.jsx` / `app.jsx`); the server must not re-emit them.
    let page = read_engine_src("engine/dashboard/page.rs");
    assert!(
        !page.contains("header.strip") && !page.contains("class=\"strip\""),
        "the status strip must not be server-rendered — it is client-only now (JEF-408)"
    );
    assert!(
        !page.contains("nav.tabs") && !page.contains("nav_bar"),
        "the tab nav must not be server-rendered — it is client-only now (JEF-408)"
    );
    // The mount is present so the client has somewhere to render the strip + nav + body.
    assert!(
        page.contains("dash-root"),
        "the shell still carries the Preact `#dash-root` mount point"
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
    // JEF-408: the ROOT-ONLY shell carries the client mount (`dash-root`) and loads the built bundle
    // same-origin (no CDN). The client renders ALL body HTML (strip, nav, view) into the mount.
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
