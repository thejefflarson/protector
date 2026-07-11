//! Trust-root freshness + fleet-wide unverifiable-spike signals (JEF-280, ADR-0020 §5).
//!
//! An [`UnverifiableHere`](crate::policies::signature::SigningPosture::UnverifiableHere) posture
//! is caused by a sigstore trust-root mismatch — so a **stale or starved** TUF root
//! (`PROTECTOR_TUF_CACHE`) can mass-blind signing detection: signatures that WOULD verify against a
//! fresh root instead read "unverifiable here", and downgrade detection (JEF-280) loses its keyless
//! yardstick. This module exposes the two honest, side-effect-light signals the readiness
//! aggregation surfaces so the operator can SEE that risk rather than infer it:
//!
//!   * [`tuf_cache_age_secs`] — the age of the TUF trust-root cache (its newest file mtime), so
//!     readiness can warn when the root is stale.
//!   * [`is_unverifiable_spike`] — whether a *fleet-wide* fraction of this pass's observed images
//!     fail to verify against our trust root, a hint the root drifted or is being starved.
//!
//! Both are pure/deterministic given their inputs (the age reads a directory's mtimes; the spike is
//! arithmetic), so both are exhaustively unit-testable. Neither ever gates — they only feed the
//! read-only readiness view (ADR-0016: presentation is a view, never a decision gate).

use std::path::Path;
use std::time::SystemTime;

/// How old the TUF trust-root cache may get before readiness warns it is **stale** (JEF-280).
///
/// The sigstore public-good TUF metadata (the `timestamp`/`snapshot` roles) is short-lived and is
/// refreshed whenever a verification fetches it, so a cache that has not been touched in a week is a
/// strong signal the root is starved (no successful refresh) — exactly the condition that turns
/// genuine signatures into `UnverifiableHere` and blinds detection. A coarse wall-clock threshold on
/// the cache's newest mtime is the honest, dependency-free freshness signal the ticket asks for;
/// parsing the TUF expiry itself is a future refinement.
pub const TUF_STALE_AFTER_SECS: u64 = 7 * 24 * 60 * 60;

/// The floor of observed images below which an `UnverifiableHere` fraction is NOT called a
/// fleet-wide spike (JEF-280): on a tiny fleet one or two unverifiable images is noise, not a
/// trust-root signal. Kept low so a modest cluster still trips the honest warning.
pub const SPIKE_MIN_IMAGES: usize = 4;

/// Age (seconds) of the sigstore TUF trust-root cache at `cache_dir`, measured from its NEWEST file
/// mtime relative to `now` (JEF-280). Returns `None` when the directory is absent, empty, or holds
/// no readable-mtime file — the honest "no trust root fetched yet" state, distinct from a fresh one.
///
/// Uses the newest mtime (not the oldest) because sigstore-rs rewrites the short-lived TUF metadata
/// on every successful refresh, so the newest touch is the last time the root was actually renewed.
/// A clock that appears to run backwards (mtime in the future) saturates to age `0` (fresh), never a
/// panic.
pub fn tuf_cache_age_secs(cache_dir: &Path, now: SystemTime) -> Option<u64> {
    let entries = std::fs::read_dir(cache_dir).ok()?;
    let mut newest: Option<SystemTime> = None;
    for entry in entries.flatten() {
        // Skip directories so a nested cache layout doesn't count a dir's own mtime; only files
        // carry the metadata whose refresh we track.
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        if let Ok(modified) = meta.modified() {
            newest = Some(match newest {
                Some(prev) if prev >= modified => prev,
                _ => modified,
            });
        }
    }
    let newest = newest?;
    Some(now.duration_since(newest).map(|d| d.as_secs()).unwrap_or(0))
}

/// Whether this pass's observed postures show a **fleet-wide spike** in `UnverifiableHere`
/// (JEF-280): a large fraction of the images that reached a resting, signature-relevant posture
/// fail to verify against our trust root — a hint the trust root drifted or is being starved.
///
/// Honest by construction: it requires both a floor of observed images ([`SPIKE_MIN_IMAGES`], so a
/// tiny fleet's noise never trips it) and that unverifiable images are at least HALF of them. It is
/// a coarse fraction heuristic (a delta against a historical unverifiable rate is a future
/// refinement); the point is only to keep a mass trust-root failure non-green, never to gate.
///
/// `total` is the count of images that reached a resting, signature-relevant posture this pass;
/// `unverifiable` is how many of those were `UnverifiableHere`.
pub fn is_unverifiable_spike(unverifiable: usize, total: usize) -> bool {
    total >= SPIKE_MIN_IMAGES && unverifiable * 2 >= total
}

#[cfg(test)]
#[path = "signing_trust_tests.rs"]
mod tests;
