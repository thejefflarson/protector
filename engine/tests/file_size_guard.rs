//! Repo-wide file-size guard (JEF-218). The repo's hard rule (CLAUDE.md): **no source
//! file may exceed 1,000 lines.** A file that grows past the cap becomes unreviewable, so
//! this test fails the build the moment any first-party `.rs` file crosses the line, forcing
//! a split into cohesive submodules instead.
//!
//! It walks every first-party crate `src/` tree under the repo root and asserts each
//! `.rs` file is within the cap. Two things are deliberately excluded:
//!   - `target/`, `.git/`, and `.claude/` (build output, VCS internals, and the
//!     parallel agent worktrees that each carry their own copy of the tree); and
//!   - `vmlinux.rs`, the bindgen-generated kernel BTF bindings for the eBPF agent —
//!     machine-generated, never hand-edited, and not subject to the readability rule.

use std::path::{Path, PathBuf};

/// The hard cap from CLAUDE.md. Tests count toward it, so this is measured over every
/// `.rs` file, test modules included.
const MAX_LINES: usize = 1000;

/// The repo root: the parent of the engine crate's manifest dir (`<root>/engine`).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("engine crate has a parent (the repo root)")
        .to_path_buf()
}

/// Whether a directory should be skipped entirely while walking the tree.
fn is_skipped_dir(name: &str) -> bool {
    // Build output, VCS internals, and the per-agent worktrees (each a full copy of the
    // repo under `.claude/worktrees/`, which would otherwise be scanned many times over).
    matches!(name, "target" | ".git" | ".claude")
}

/// Whether a `.rs` file is exempt from the cap because it is machine-generated.
fn is_generated(path: &Path) -> bool {
    // The aya/bindgen kernel BTF bindings for the eBPF agent: tens of thousands of lines
    // of generated type definitions, regenerated from `vmlinux`, never hand-maintained.
    path.file_name().and_then(|n| n.to_str()) == Some("vmlinux.rs")
}

/// Collect every `.rs` file under `dir` (recursively), skipping build/VCS/worktree
/// directories and generated files.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !is_skipped_dir(name) {
                collect_rs_files(&path, out);
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") && !is_generated(&path) {
            out.push(path);
        }
    }
}

#[test]
fn no_source_file_exceeds_the_line_cap() {
    let root = repo_root();
    // First-party crate source trees. `agent/` is its own (out-of-workspace) eBPF crate,
    // but its hand-written source is still subject to the rule — only `vmlinux.rs` is
    // exempt (handled by `is_generated`).
    let src_trees = ["engine/src", "behavior/src", "agent"];

    let mut files = Vec::new();
    for tree in src_trees {
        let dir = root.join(tree);
        if dir.exists() {
            collect_rs_files(&dir, &mut files);
        }
    }
    assert!(
        !files.is_empty(),
        "found no .rs files to check under {root:?} — the guard would pass vacuously"
    );

    let mut offenders: Vec<(PathBuf, usize)> = Vec::new();
    for file in files {
        let contents = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("reading {file:?} for the line-count guard: {e}"));
        let lines = contents.lines().count();
        if lines > MAX_LINES {
            offenders.push((file, lines));
        }
    }

    assert!(
        offenders.is_empty(),
        "source files exceed the {MAX_LINES}-line cap (CLAUDE.md) — split them into \
         cohesive submodules:\n{}",
        offenders
            .iter()
            .map(|(p, n)| format!("  {n} lines  {}", p.display()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
