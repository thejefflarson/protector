//! Tests for the hot-reloadable feed wrapper: a store pointed at a temp file picks up the
//! new rows when the file changes and is reloaded, and a bad/empty reload keeps the last-good
//! snapshot rather than blanking out exploit intel.

use std::time::Duration;

use super::*;
use crate::engine::observe::epss::EpssStore;
use crate::engine::observe::exploit_intel::KevCatalog;

/// A unique temp path per test so parallel `nextest` runs never collide on the file.
fn temp_path(tag: &str) -> std::path::PathBuf {
    let unique = format!(
        "protector-feed-reload-{tag}-{}-{:?}.tmp",
        std::process::id(),
        std::thread::current().id()
    );
    std::env::temp_dir().join(unique)
}

#[test]
fn reload_serves_the_new_rows_after_the_file_changes() {
    let path = temp_path("kev-new-rows");
    std::fs::write(&path, "CVE-2021-44228\n").unwrap();

    let feed = ReloadableFeed::<KevCatalog>::load_initial(path.to_str().unwrap());
    assert!(feed.snapshot().contains("CVE-2021-44228"));
    assert!(
        !feed.snapshot().contains("CVE-2014-0160"),
        "not yet present"
    );

    // The CronJob refreshes the file with a newly-known-exploited CVE.
    std::fs::write(&path, "CVE-2021-44228\nCVE-2014-0160\n").unwrap();
    assert!(feed.reload_once(), "a good reload swaps");

    let snap = feed.snapshot();
    assert!(snap.contains("CVE-2014-0160"), "new row now served");
    assert!(snap.contains("CVE-2021-44228"), "existing row retained");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_missing_file_reload_keeps_the_last_good_snapshot() {
    let path = temp_path("kev-missing");
    std::fs::write(&path, "CVE-2021-44228\n").unwrap();

    let feed = ReloadableFeed::<KevCatalog>::load_initial(path.to_str().unwrap());
    assert_eq!(feed.snapshot().len(), 1);

    // The file vanishes (a bad sync, an unmounted volume). The reload must not clobber.
    std::fs::remove_file(&path).unwrap();
    assert!(!feed.reload_once(), "a read error does not swap");

    assert!(
        feed.snapshot().contains("CVE-2021-44228"),
        "last-good KEV data still served"
    );
}

#[test]
fn an_empty_reload_over_nonempty_data_is_refused() {
    let path = temp_path("kev-truncated");
    std::fs::write(&path, "CVE-2021-44228\nCVE-2014-0160\n").unwrap();

    let feed = ReloadableFeed::<KevCatalog>::load_initial(path.to_str().unwrap());
    assert_eq!(feed.snapshot().len(), 2);

    // A mid-write truncation leaves the file empty; parsing it yields zero rows. Refuse it.
    std::fs::write(&path, "").unwrap();
    assert!(
        !feed.reload_once(),
        "an empty reload over good data is suspect"
    );
    assert_eq!(
        feed.snapshot().len(),
        2,
        "last-good snapshot preserved through the suspect empty reload"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn epss_reload_swaps_in_the_new_scores() {
    let path = temp_path("epss-new-scores");
    std::fs::write(&path, "cve,epss,percentile\nCVE-2021-44228,0.10,0.5\n").unwrap();

    let feed = ReloadableFeed::<EpssStore>::load_initial(path.to_str().unwrap());
    assert_eq!(feed.snapshot().get("CVE-2021-44228"), Some(0.10));

    // The daily EPSS refresh bumps the probability.
    std::fs::write(&path, "cve,epss,percentile\nCVE-2021-44228,0.94,0.99\n").unwrap();
    assert!(feed.reload_once());
    assert_eq!(
        feed.snapshot().get("CVE-2021-44228"),
        Some(0.94),
        "the reloaded EPSS probability is served"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn initial_load_of_a_missing_file_degrades_to_empty() {
    let path = temp_path("kev-never-existed");
    let _ = std::fs::remove_file(&path);

    let feed = ReloadableFeed::<KevCatalog>::load_initial(path.to_str().unwrap());
    assert!(
        feed.snapshot().is_empty(),
        "a missing feed at startup degrades to empty, never crashes"
    );

    // And a first successful reload then populates it (an empty-over-empty swap is allowed).
    std::fs::write(&path, "CVE-2021-44228\n").unwrap();
    assert!(feed.reload_once());
    assert!(feed.snapshot().contains("CVE-2021-44228"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn parse_reload_interval_falls_back_to_the_default() {
    let default = Duration::from_secs(DEFAULT_RELOAD_SECS);
    assert_eq!(parse_reload_interval(None), default, "unset ⇒ default");
    assert_eq!(parse_reload_interval(Some("")), default, "empty ⇒ default");
    assert_eq!(
        parse_reload_interval(Some("nope")),
        default,
        "junk ⇒ default"
    );
    assert_eq!(parse_reload_interval(Some("0")), default, "zero ⇒ default");
}

#[test]
fn parse_reload_interval_honours_a_configured_value() {
    assert_eq!(
        parse_reload_interval(Some("3600")),
        Duration::from_secs(3600)
    );
    assert_eq!(
        parse_reload_interval(Some("  7200  ")),
        Duration::from_secs(7200),
        "whitespace tolerated"
    );
}

#[tokio::test]
async fn spawned_reloader_picks_up_a_file_change_on_its_interval() {
    let path = temp_path("kev-spawned");
    std::fs::write(&path, "CVE-2021-44228\n").unwrap();

    let feed = ReloadableFeed::<KevCatalog>::load_initial(path.to_str().unwrap());
    let handle = feed.spawn_reloader(Duration::from_millis(20));

    // Change the file after the reloader is running.
    std::fs::write(&path, "CVE-2021-44228\nCVE-2014-0160\n").unwrap();

    // Poll until the background task swaps in the new row (bounded so a stall fails, not hangs).
    let mut picked_up = false;
    for _ in 0..100 {
        if feed.snapshot().contains("CVE-2014-0160") {
            picked_up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    handle.abort();
    assert!(picked_up, "the background reloader picked up the new row");

    let _ = std::fs::remove_file(&path);
}
