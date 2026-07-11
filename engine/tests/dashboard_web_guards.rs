//! Source + built-bundle guards for the v4 Preact dashboard client (ADR-0025). These are the
//! JS-side analogues of the Rust dashboard guards, run as engine integration tests so they
//! gate every `cargo nextest` the same way:
//!
//! - **no raw-HTML escape hatch** — `dangerouslySetInnerHTML` is BANNED anywhere under
//!   `engine/web/src/` (ADR-0025), the direct analogue of the maud "never `PreEscaped` for
//!   untrusted text" rule. Preact auto-escapes interpolated text; the escape hatch would
//!   reopen the XSS hole the auto-escape closes.
//! - **no off-origin fetch in the built bundle** — the bundle references no `http(s)` origin
//!   except the well-known W3C XML-namespace URIs Preact embeds as SVG/MathML namespace
//!   constants (never fetched). Any other absolute URL is a CDN/third-party leak (zero-egress).
//! - **file-size cap** — the 1,000-line CLAUDE.md cap (ADR-0025 (c)) extends to
//!   `engine/web/src/`; the client is written as small, single-purpose modules.
//!
//! The built bundle (`engine/web/dist/dashboard.js`) is gitignored and produced by the node
//! build (Docker stage + CI step) BEFORE the engine compiles; these tests read it in place.

use std::path::{Path, PathBuf};

/// The repo root: the parent of the engine crate's manifest dir.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("engine crate has a parent (the repo root)")
        .to_path_buf()
}

/// The client source directory (`engine/web/src`).
fn web_src_dir() -> PathBuf {
    repo_root().join("engine/web/src")
}

/// Collect every source file (`.js`/`.jsx`/`.ts`/`.tsx`) under `engine/web/src`.
fn web_src_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect(&web_src_dir(), &mut out);
    assert!(
        !out.is_empty(),
        "found no client source under {:?} — the guard would pass vacuously",
        web_src_dir()
    );
    out
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("js" | "jsx" | "ts" | "tsx")
        ) {
            out.push(path);
        }
    }
}

#[test]
fn client_source_never_uses_the_raw_html_escape_hatch() {
    // `dangerouslySetInnerHTML` bypasses Preact's auto-escape and would let untrusted text
    // (CVE titles, verdict prose, model prompts) render as live HTML — the exact XSS hole the
    // maud "escape everything" rule closed. Banned outright in the client source (ADR-0025).
    let mut offenders: Vec<String> = Vec::new();
    for file in web_src_files() {
        let src = std::fs::read_to_string(&file).unwrap();
        for (n, line) in src.lines().enumerate() {
            if line.contains("dangerouslySetInnerHTML") {
                offenders.push(format!("{}:{}  {}", file.display(), n + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the client must never use `dangerouslySetInnerHTML` (ADR-0025) — Preact auto-escapes; \
         the escape hatch reopens the XSS hole:\n{}",
        offenders.join("\n")
    );
}

/// The only absolute `http(s)` origins the built bundle may legitimately contain: the W3C XML
/// namespace URIs Preact embeds as SVG/MathML/XHTML namespace constants. These are string
/// identifiers passed to `createElementNS` — never fetched — so they are not an egress path.
const ALLOWED_NAMESPACE_ORIGINS: &[&str] = &["http://www.w3.org/"];

#[test]
fn built_bundle_references_no_off_origin() {
    // The bundle is served same-origin via include_str!; the ONLY runtime network call is a
    // same-origin fetch of the JSON snapshot. Any absolute URL other than the W3C namespace
    // constants is a CDN/third-party leak and breaks zero-egress (ADR-0025).
    let js = repo_root().join("engine/web/dist/dashboard.js");
    let src = std::fs::read_to_string(&js).unwrap_or_else(|e| {
        panic!(
            "reading {js:?}: {e} — the bundle is built from source (gitignored); run \
             `npm --prefix engine/web ci --ignore-scripts && npm --prefix engine/web run build` \
             first (CI and the Docker node stage do this automatically)"
        )
    });

    let mut offenders: Vec<String> = Vec::new();
    for (start, _) in src.match_indices("://") {
        // Walk back to the scheme start; only `http`/`https` are URLs we care about.
        let rest = match src[..start].rsplit_once(|c: char| !c.is_ascii_alphanumeric()) {
            Some((_, scheme)) => scheme,
            None => &src[..start],
        };
        if rest != "http" && rest != "https" {
            continue;
        }
        // The URL runs from the scheme to the first delimiter (quote, whitespace, paren, comma).
        let url_start = start - rest.len();
        let tail = &src[url_start..];
        let end = tail
            .find(|c: char| c == '"' || c == '\'' || c == ')' || c == ',' || c.is_whitespace())
            .unwrap_or(tail.len());
        let url = &tail[..end];
        if !ALLOWED_NAMESPACE_ORIGINS
            .iter()
            .any(|origin| url.starts_with(origin))
        {
            offenders.push(url.to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "the built bundle references off-origin URLs (zero-egress / no-CDN, ADR-0025) — only the \
         W3C namespace constants are allowed:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn client_source_files_obey_the_line_cap() {
    // The CLAUDE.md 1,000-line hard cap extends to engine/web/src (ADR-0025 (c)).
    const MAX_LINES: usize = 1000;
    let mut offenders: Vec<(PathBuf, usize)> = Vec::new();
    for file in web_src_files() {
        let lines = std::fs::read_to_string(&file).unwrap().lines().count();
        if lines > MAX_LINES {
            offenders.push((file, lines));
        }
    }
    assert!(
        offenders.is_empty(),
        "client source files exceed the {MAX_LINES}-line cap (ADR-0025 (c)) — split into \
         cohesive modules:\n{}",
        offenders
            .iter()
            .map(|(p, n)| format!("  {n} lines  {}", p.display()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
