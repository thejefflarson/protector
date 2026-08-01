//! Repo-wide self-containment guard (CLAUDE.md "Committed content is self-contained — no
//! external ticket IDs"). Committed source comments/docstrings and docs must be readable by
//! someone with no access to the issue tracker, so this test fails the build the moment a
//! `JEF-nnn` ticket reference or a `linear.app` URL lands in tracked, human-authored source or
//! docs — forcing the *why* to be captured in-repo instead (an ADR, a file/module path, or
//! inline reasoning).
//!
//! Scope mirrors the CLAUDE.md guardrail's own list — ADRs/docs, source comments/docstrings
//! (Rust, JS/JSX, Python, shell), `CLAUDE.md`, `README.md`, chart templates, and CI scripts —
//! walked directly (no `git` invocation, matching `file_size_guard.rs`'s approach). It does
//! NOT scope git history, branch names, or PR bodies (CLAUDE.md's documented boundary): those
//! never reach this filesystem walk.

use std::path::{Path, PathBuf};

/// The repo root: the parent of the engine crate's manifest dir.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("engine crate has a parent (the repo root)")
        .to_path_buf()
}

/// Whether a directory should be skipped entirely while walking the tree.
fn is_skipped_dir(name: &str) -> bool {
    matches!(
        name,
        "target" | ".git" | ".claude" | "node_modules" | "dist"
    )
}

/// File extensions the guardrail applies to: first-party source + docs, never build output.
fn is_checked_extension(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("rs" | "md" | "py" | "sh" | "tpl" | "yaml" | "yml" | "jsx" | "js" | "css")
    )
}

/// The one structural file-level exemption: this test's own file names the `JEF-` prefix and
/// the `linear.app` string literally to implement the check — the same self-reference
/// CLAUDE.md's guardrail text is allowed. No ticket-ID exemptions exist (that would be the
/// exact thing this guard forbids elsewhere).
const EXEMPT_FILES: &[&str] = &["engine/tests/self_containment_guard.rs"];

/// The one line allowed to contain the otherwise-forbidden `linear.app` substring, because it
/// NAMES the pattern this guard enforces (CLAUDE.md's own guardrail text) rather than citing a
/// real link. Matched by substring so reformatting the surrounding prose doesn't break it.
const EXEMPT_LINE_SUBSTRING: &str = "a `linear.app` URL";

/// Collect every checked file under `dir` (recursively), skipping build/VCS/dependency dirs.
fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !is_skipped_dir(name) {
                collect_files(&path, out);
            }
        } else if is_checked_extension(&path) {
            out.push(path);
        }
    }
}

/// Whether `line` contains a `JEF-` ticket reference (the literal prefix followed by a digit —
/// `JEF-nnn` placeholder prose, as CLAUDE.md's own guardrail text uses, does NOT match).
fn contains_jef_reference(line: &str) -> bool {
    let bytes = line.as_bytes();
    line.match_indices("JEF-")
        .any(|(i, _)| bytes.get(i + 4).is_some_and(|b| b.is_ascii_digit()))
}

#[test]
fn no_ticket_breadcrumbs_in_tracked_source_or_docs() {
    let root = repo_root();
    // First-party source trees + docs the guardrail covers (mirrors CLAUDE.md's own list:
    // ADRs, source comments/docstrings, CLAUDE.md, VISION.md, scripts, chart templates) plus
    // the workflow scripts that carry the same kind of human-authored, tracker-blind prose.
    let scoped_dirs = [
        "docs",
        "scripts",
        "charts",
        "engine/src",
        "engine/examples",
        "engine/tests",
        "engine/web/src",
        "engine/web/test",
        "behavior/src",
        "agent",
        ".github/workflows",
    ];
    let scoped_files = [
        "CLAUDE.md",
        "README.md",
        "Dockerfile",
        "agent/Dockerfile",
        "engine/web/eslint.config.js",
        "engine/web/vitest.config.js",
        "engine/web/dist/dashboard.css",
    ];

    let mut files = Vec::new();
    for dir in scoped_dirs {
        let path = root.join(dir);
        if path.exists() {
            collect_files(&path, &mut files);
        }
    }
    for f in scoped_files {
        let path = root.join(f);
        if path.exists() {
            files.push(path);
        }
    }
    assert!(
        !files.is_empty(),
        "found no files to check under {root:?} — the guard would pass vacuously"
    );

    let mut offenders: Vec<String> = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        if EXEMPT_FILES.contains(&rel.as_str()) {
            continue;
        }
        let contents = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("reading {file:?} for the self-containment guard: {e}"));
        for (n, line) in contents.lines().enumerate() {
            if line.contains(EXEMPT_LINE_SUBSTRING) {
                continue;
            }
            if contains_jef_reference(line) || line.contains("linear.app") {
                offenders.push(format!("{rel}:{}: {}", n + 1, line.trim()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "committed content must be self-contained (CLAUDE.md) — cite an ADR, a file/module \
         path, or inline reasoning, never a Linear ticket ID or a linear.app URL:\n{}",
        offenders.join("\n")
    );
}
