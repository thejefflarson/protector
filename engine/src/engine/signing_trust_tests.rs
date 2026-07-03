//! Tests for the TUF trust-root freshness + fleet-wide unverifiable-spike signals (JEF-280).

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use super::*;

/// A unique temp directory per test (no temp-file crate), mirroring the journal/baseline helpers.
fn temp_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let n = NONCE.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("protector-tuf-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn no_cache_dir_reads_as_none() {
    // An absent cache dir is the honest "no trust root fetched yet" — None, not a fresh 0.
    let missing = std::env::temp_dir().join(format!(
        "protector-tuf-missing-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    assert!(tuf_cache_age_secs(&missing, SystemTime::now()).is_none());
}

#[test]
fn empty_cache_dir_reads_as_none() {
    let dir = temp_dir("empty");
    assert!(
        tuf_cache_age_secs(&dir, SystemTime::now()).is_none(),
        "an empty cache dir has no metadata to age"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_freshly_written_cache_is_young() {
    let dir = temp_dir("fresh");
    std::fs::write(dir.join("root.json"), b"{}").unwrap();
    let age = tuf_cache_age_secs(&dir, SystemTime::now()).expect("a file was written");
    assert!(age < TUF_STALE_AFTER_SECS, "a just-written cache is fresh");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn age_is_measured_from_the_newest_file() {
    // The newest touch is the last successful refresh; a very old `now` yields a large age.
    let dir = temp_dir("newest");
    std::fs::write(dir.join("root.json"), b"{}").unwrap();
    // `now` is far in the FUTURE relative to the file, so the age exceeds the stale threshold.
    let far_future = SystemTime::now() + Duration::from_secs(TUF_STALE_AFTER_SECS + 60);
    let age = tuf_cache_age_secs(&dir, far_future).expect("a file exists");
    assert!(
        age >= TUF_STALE_AFTER_SECS,
        "a cache untouched for over the stale window reads as stale (age {age})"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_future_mtime_saturates_to_zero_not_a_panic() {
    let dir = temp_dir("future");
    std::fs::write(dir.join("root.json"), b"{}").unwrap();
    // `now` in the PAST relative to the file (clock skew) ⇒ saturating age 0, never underflow.
    let past = SystemTime::UNIX_EPOCH;
    assert_eq!(tuf_cache_age_secs(&dir, past), Some(0));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_fleet_wide_unverifiable_majority_is_a_spike() {
    // Half or more of a fleet above the floor failing to verify ⇒ a spike (trust-root hint).
    assert!(is_unverifiable_spike(4, 8));
    assert!(is_unverifiable_spike(5, 8));
    assert!(is_unverifiable_spike(4, 4), "all unverifiable is a spike");
}

#[test]
fn a_minority_or_tiny_fleet_is_not_a_spike() {
    // A minority is normal drift, not a mass trust-root failure.
    assert!(!is_unverifiable_spike(3, 8));
    // Below the floor, even all-unverifiable is treated as noise, not a fleet signal.
    assert!(!is_unverifiable_spike(3, 3));
    assert!(!is_unverifiable_spike(0, 0), "no observations ⇒ no spike");
}
