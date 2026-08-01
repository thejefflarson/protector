//! Unit tests for the break-glass watcher, split out purely to keep the module root under the
//! 1,000-line cap (repo CLAUDE.md conventions).

use super::*;

/// A unique temp flag path for a test, without a temp-file crate.
fn temp_flag_path(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let n = NONCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "protector-break-glass-{tag}-{}-{n}",
        std::process::id()
    ))
}

#[test]
fn disabled_is_never_engaged() {
    assert!(!BreakGlass::disabled().engaged());
}

#[test]
fn engaged_tracks_file_presence_only_no_content_read() {
    let path = temp_flag_path("presence");
    let bg = BreakGlass::at(&path);
    assert!(!bg.engaged(), "absent file ⇒ clear");

    // Content is irrelevant — even an empty file engages it.
    std::fs::write(&path, "").unwrap();
    assert!(
        bg.engaged(),
        "presence alone engages, regardless of content"
    );

    std::fs::write(&path, "anything at all\nmulti-line too").unwrap();
    assert!(
        bg.engaged(),
        "still just presence — content is never parsed"
    );

    std::fs::remove_file(&path).unwrap();
    assert!(!bg.engaged(), "removing the file clears it");
}

#[tokio::test]
async fn poller_wakes_on_engage_and_clear_edges_only() {
    let path = temp_flag_path("poller");
    let bg = BreakGlass::at(&path);
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let handle = bg.spawn_poller(tx, Duration::from_millis(15));

    // Starts clear: no spurious wakes while nothing changes.
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(
        rx.try_recv().is_err(),
        "no wake while the flag is unchanged"
    );

    // Engage: a wake fires within a bounded window.
    std::fs::write(&path, "").unwrap();
    tokio::time::timeout(Duration::from_millis(500), rx.recv())
        .await
        .expect("a wake must fire on the engage edge");

    // No second wake while it stays engaged.
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(rx.try_recv().is_err(), "no repeat wake while still engaged");

    // Clear: a wake fires again.
    std::fs::remove_file(&path).unwrap();
    tokio::time::timeout(Duration::from_millis(500), rx.recv())
        .await
        .expect("a wake must fire on the clear edge");

    handle.abort();
}
