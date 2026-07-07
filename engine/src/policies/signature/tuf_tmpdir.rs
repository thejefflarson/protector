//! Keep the sigstore TUF client's atomic temp writes OFF `/tmp` (JEF-377).
//!
//! sigstore-rs 0.14 builds its `tough` TUF client via `RepositoryLoader` WITHOUT calling
//! `.datastore(...)`, so `tough` falls back to `Datastore::new(None)` → `TempDir::new()` — a
//! random dir under `$TMPDIR` (default `/tmp`). On every trust-root load it writes
//! `latest_known_time.json` plus the refreshed root/timestamp/snapshot metadata there. That
//! churns the operator's prompt AND masquerades as a `/tmp/.tmp<rand>/…` drop-and-execute IOC.
//! The `cache_dir` we pass to [`SigstoreTrustRoot::new`](sigstore::trust::sigstore::SigstoreTrustRoot::new)
//! only backs the final `trusted_root.json` checkout read/write — NOT the tough datastore — and
//! sigstore-rs 0.14 exposes no API to redirect the datastore, so the ONLY lever is `$TMPDIR`.
//!
//! We pin `$TMPDIR` to protector's own TUF cache dir at single-threaded startup so tough's temp
//! writes land in a stable, attributable, protector-owned dir alongside the rest of the cache.
//!
//! NON-GOAL (hard): this does NOT suppress `/tmp` write *observation* anywhere — `/tmp` writes
//! are IOCs (drop-and-execute) the agent MUST keep seeing. This only stops protector's OWN benign
//! TUF plumbing from writing to `/tmp`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Default TUF cache dir when `PROTECTOR_TUF_CACHE` is unset. Kept identical to `main`'s default
/// (a single source of truth) so [`pin_from_env`] pins `$TMPDIR` to exactly the dir the
/// `CosignChecker` will use as its cache. In-cluster the chart points this OFF `/tmp` at a
/// protector-owned volume; locally it stays a writable `/tmp` subdir.
pub const DEFAULT_TUF_CACHE: &str = "/tmp/sigstore";

/// Decide the dir to pin as `$TMPDIR` for the TUF/tough temp writes, or `None` to leave the
/// process `$TMPDIR` untouched. An explicit, non-empty operator `$TMPDIR` always wins (the escape
/// hatch); otherwise we route tough's temp files into `cache_dir` so `latest_known_time.json`
/// lands beside the rest of the TUF cache instead of under `/tmp/.tmp<rand>/`.
fn resolve_tmpdir(existing: Option<OsString>, cache_dir: &Path) -> Option<PathBuf> {
    match existing {
        Some(v) if !v.is_empty() => None,
        _ => Some(cache_dir.to_path_buf()),
    }
}

/// Pin `$TMPDIR` (see [`resolve_tmpdir`]) so the sigstore/tough TUF client writes its atomic temp
/// files into protector's TUF cache dir, not `/tmp`.
///
/// MUST be called from `main` BEFORE the async runtime spawns any worker thread:
/// [`std::env::set_var`] is only sound while the process is single-threaded (edition 2024). A
/// best-effort no-op if the dir can't be created — the worst case is the pre-JEF-377 behavior (a
/// `/tmp` temp write), never a startup failure (the `CosignChecker` cache-dir create surfaces any
/// real misconfiguration with context).
pub fn pin_from_env() {
    let cache_dir = std::env::var_os("PROTECTOR_TUF_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_TUF_CACHE));
    let Some(target) = resolve_tmpdir(std::env::var_os("TMPDIR"), &cache_dir) else {
        return;
    };
    // Point $TMPDIR at the dir only if we can actually create it — pointing it at a dir that
    // doesn't exist would make tough's `TempDir::new` fail. If create fails (read-only fs / bad
    // path), leave $TMPDIR alone and fall back to the prior behavior.
    if std::fs::create_dir_all(&target).is_err() {
        return;
    }
    // SAFETY: called from `main` before the tokio runtime is built, so the process is still
    // single-threaded and no other thread can be reading or writing the environment concurrently.
    unsafe {
        std::env::set_var("TMPDIR", &target);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_tmpdir_routes_tough_temp_into_the_cache_dir() {
        // No operator $TMPDIR ⇒ we pin it to the TUF cache dir so tough's atomic temp writes
        // (latest_known_time.json) land there, not under /tmp/.tmp<rand>/.
        let cache = Path::new("/var/lib/protector/tuf");
        assert_eq!(
            resolve_tmpdir(None, cache),
            Some(PathBuf::from("/var/lib/protector/tuf"))
        );
    }

    #[test]
    fn empty_tmpdir_is_treated_as_unset() {
        // An empty $TMPDIR is not a usable dir — treat it like unset and pin the cache dir.
        let cache = Path::new("/var/lib/protector/tuf");
        assert_eq!(
            resolve_tmpdir(Some(OsString::from("")), cache),
            Some(PathBuf::from("/var/lib/protector/tuf"))
        );
    }

    #[test]
    fn an_explicit_operator_tmpdir_wins() {
        // If the operator set $TMPDIR deliberately, respect it (the escape hatch) — don't override.
        let cache = Path::new("/var/lib/protector/tuf");
        assert_eq!(
            resolve_tmpdir(Some(OsString::from("/custom/scratch")), cache),
            None
        );
    }
}
