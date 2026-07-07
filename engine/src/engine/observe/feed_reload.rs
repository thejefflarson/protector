//! Hot-reloadable exploit-intel feeds: keep the KEV catalogue ([`super::exploit_intel`])
//! and the EPSS store ([`super::epss`]) current with the files on disk **without a restart**.
//!
//! The feeds are FILE reads, refreshed out-of-band by a daily CronJob (JEF-273) that syncs
//! CISA KEV + FIRST.org EPSS into a shared volume — the engine only ever *reads* them (no
//! egress, ADR-0015). The engine used to read each feed exactly once at startup and then serve
//! that boot-time snapshot forever, so the daily refreshes never took effect until the pod
//! restarted (stale KEV = missed newly-known-exploited CVEs, JEF-384). This wraps a store in an
//! [`ArcSwap`] and a background task re-reads the file on an interval, hot-swapping the held
//! snapshot so an in-flight sweep never sees a half-updated store — it reads one immutable
//! [`Arc<T>`] for the whole pass.
//!
//! Robustness is the point: a failed or *suspect* reload never clobbers the last-good data.
//! A read error (missing/unreadable file, or a mid-write truncation the OS reports) keeps the
//! current snapshot; a successful read that parses to an **empty** store while we already hold a
//! non-empty one is treated as suspect (a truncated/emptied file mid-CronJob-write) and is also
//! dropped in favour of the last-good snapshot. Either way the engine keeps serving the good
//! data and logs the skip — a bad feed can never blank out exploit intel and can never crash
//! the engine. Memory stays bounded: each reload *replaces* the snapshot, never accumulates.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;

/// The default reload interval: re-read each feed every 6 hours. The feed CronJob refreshes
/// daily, so a 6-hour cadence comfortably picks up every refresh (within hours, not a restart)
/// while keeping the file reads negligible. Overridable via `PROTECTOR_FEED_RELOAD_SECS`.
const DEFAULT_RELOAD_SECS: u64 = 6 * 60 * 60;

/// A feed store that can be loaded from a file, hot-swapped, and reloaded. Both the KEV
/// catalogue and the EPSS store already expose these operations; this trait just names the
/// small surface [`ReloadableFeed`] needs so the reload machinery is written once for both.
pub trait Feed: Sized + Send + Sync + 'static {
    /// A short label for the load/reload logs (e.g. `"KEV catalogue"`).
    const LABEL: &'static str;

    /// The honest empty default — used when the initial file read fails, so a misconfigured
    /// feed degrades to "no evidence" rather than failing the engine.
    fn empty() -> Self;

    /// Parse the feed's file contents into a store. Lenient by contract: malformed input
    /// yields fewer (or zero) rows, never a panic.
    fn parse(contents: &str) -> Self;

    /// How many rows the store carries (for the load count in logs / readiness config).
    fn row_count(&self) -> usize;

    /// Whether the store is empty — the suspect-reload guard reads this to refuse a swap that
    /// would blank out a currently non-empty store.
    fn is_feed_empty(&self) -> bool;
}

impl Feed for super::exploit_intel::KevCatalog {
    const LABEL: &'static str = "KEV catalogue";
    fn empty() -> Self {
        Self::empty()
    }
    fn parse(contents: &str) -> Self {
        Self::parse(contents)
    }
    fn row_count(&self) -> usize {
        self.len()
    }
    fn is_feed_empty(&self) -> bool {
        self.is_empty()
    }
}

impl Feed for super::epss::EpssStore {
    const LABEL: &'static str = "EPSS scores";
    fn empty() -> Self {
        Self::empty()
    }
    fn parse(contents: &str) -> Self {
        Self::parse(contents)
    }
    fn row_count(&self) -> usize {
        self.len()
    }
    fn is_feed_empty(&self) -> bool {
        self.is_empty()
    }
}

impl Feed for super::asn::AsnDb {
    const LABEL: &'static str = "ASN dataset";
    fn empty() -> Self {
        Self::empty()
    }
    fn parse(contents: &str) -> Self {
        Self::parse(contents)
    }
    fn row_count(&self) -> usize {
        self.len()
    }
    fn is_feed_empty(&self) -> bool {
        self.is_empty()
    }
}

/// A feed store held behind an [`ArcSwap`] so it can be atomically hot-swapped by a background
/// reload without disrupting a reader mid-pass. Cheap to clone (it shares the same swap cell and
/// path), so the reload task holds its own handle.
pub struct ReloadableFeed<T> {
    path: String,
    current: Arc<ArcSwap<T>>,
}

impl<T> Clone for ReloadableFeed<T> {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            current: self.current.clone(),
        }
    }
}

impl<T: Feed> ReloadableFeed<T> {
    /// The initial startup load: read + parse the file, or degrade to the empty store (logged)
    /// if the file is missing/unreadable — mirrors the old `from_file` behaviour, so a
    /// misconfigured feed still just means "no evidence", never a crash.
    pub fn load_initial(path: impl Into<String>) -> Self {
        let path = path.into();
        let initial = match read_and_parse::<T>(&path) {
            Ok(store) => {
                tracing::info!(path, count = store.row_count(), "loaded {}", T::LABEL);
                store
            }
            Err(error) => {
                tracing::warn!(
                    path,
                    %error,
                    "could not read {}; serving empty until a reload succeeds",
                    T::LABEL
                );
                T::empty()
            }
        };
        Self {
            path,
            current: Arc::new(ArcSwap::from_pointee(initial)),
        }
    }

    /// A feed seeded with an explicit store and NO backing file — the honest default a
    /// consumer holds when a feed isn't wired (e.g. `Engine::new` holds an empty ASN dataset
    /// until the watch loop attaches the file-backed one via a builder). Its path is empty, so
    /// a `reload_once` on it is a no-op read error that keeps the seeded store; the reloader is
    /// simply never spawned on a `from_store` feed.
    pub fn from_store(store: T) -> Self {
        Self {
            path: String::new(),
            current: Arc::new(ArcSwap::from_pointee(store)),
        }
    }

    /// The current snapshot — one immutable `Arc<T>` a sweep holds for its whole pass. A reload
    /// that lands mid-pass swaps the *next* reader's snapshot, never this one.
    pub fn snapshot(&self) -> Arc<T> {
        self.current.load_full()
    }

    /// Re-read the file once and hot-swap the snapshot, preserving the last-good data on any
    /// failure or suspect result. Returns `true` only when it actually swapped. Blocking file
    /// I/O — the interval task runs it via `spawn_blocking`; tests call it directly.
    ///
    /// - Read error ⇒ keep last-good (the file is missing, unreadable, or mid-write).
    /// - Parses empty while we already hold non-empty rows ⇒ suspect (a truncated/emptied file);
    ///   keep last-good.
    /// - Otherwise ⇒ swap in the fresh snapshot.
    pub fn reload_once(&self) -> bool {
        match read_and_parse::<T>(&self.path) {
            Ok(fresh) => {
                if fresh.is_feed_empty() && !self.current.load().is_feed_empty() {
                    tracing::warn!(
                        path = self.path,
                        "reloaded {} is empty but the current one is not; keeping the last-good snapshot (suspect truncated/emptied file)",
                        T::LABEL
                    );
                    return false;
                }
                let count = fresh.row_count();
                self.current.store(Arc::new(fresh));
                tracing::info!(path = self.path, count, "reloaded {}", T::LABEL);
                true
            }
            Err(error) => {
                tracing::warn!(
                    path = self.path,
                    %error,
                    "could not re-read {}; keeping the last-good snapshot",
                    T::LABEL
                );
                false
            }
        }
    }

    /// Spawn the background reloader: every `interval`, re-read the file and hot-swap the
    /// snapshot (last-good-preserving). The first tick fires one interval out — the startup load
    /// already seeded the snapshot, so there's no point re-reading immediately. The blocking read
    /// runs on the blocking pool so it never stalls the async runtime. Returns the task handle so
    /// the caller can abort it on engine shutdown (like the keep-warm task).
    pub fn spawn_reloader(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        let feed = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Consume the immediate first tick; the startup load already read the file.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let feed = feed.clone();
                // The read is blocking file I/O; keep it off the async worker threads.
                let _ = tokio::task::spawn_blocking(move || feed.reload_once()).await;
            }
        })
    }
}

/// Read a feed file and parse it. Distinguishes a read failure (returned `Err`, so the caller
/// keeps the last-good snapshot) from a successful read (parsed leniently into a store).
fn read_and_parse<T: Feed>(path: &str) -> std::io::Result<T> {
    let contents = std::fs::read_to_string(path)?;
    Ok(T::parse(&contents))
}

/// The feed reload interval, resolved from `PROTECTOR_FEED_RELOAD_SECS` (seconds), defaulting to
/// [`DEFAULT_RELOAD_SECS`]. Unset, empty, unparseable, or zero falls back to the default — a zero
/// interval would busy-loop the reloader, so it is never honoured.
pub fn reload_interval() -> Duration {
    parse_reload_interval(std::env::var("PROTECTOR_FEED_RELOAD_SECS").ok().as_deref())
}

/// Pure parse of the `PROTECTOR_FEED_RELOAD_SECS` value, split out so it's testable without
/// touching process-global env.
fn parse_reload_interval(raw: Option<&str>) -> Duration {
    let secs = raw
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&s| s > 0)
        .unwrap_or(DEFAULT_RELOAD_SECS);
    Duration::from_secs(secs)
}

#[cfg(test)]
#[path = "feed_reload_tests.rs"]
mod tests;
