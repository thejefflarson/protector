//! Unit tests for the Rekor transparency-log lane (JEF-266): the query-key selection, the
//! TTL cache (don't re-query an unchanged image, retry after an error), and the off-by-default
//! config posture. The corroboration/divergence decision logic is tested where it lives
//! (`engine::signing_rekor`); here we cover the client/cache plumbing.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use async_trait::async_trait;

use super::{HttpRekorClient, QueryKey, RekorClient, RekorConfig, RekorHistory, RekorLane};

/// A fake client that counts calls and returns a scripted result (or an error) — so we can prove
/// the cache serves without an outbound call and that an error is not frozen in.
struct FakeClient {
    calls: Arc<AtomicUsize>,
    result: Result<RekorHistory, ()>,
}

#[async_trait]
impl RekorClient for FakeClient {
    async fn lookup(&self, _image: &str, _identity: Option<&str>) -> Result<RekorHistory> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.result {
            Ok(h) => Ok(h.clone()),
            Err(()) => bail!("rekor unreachable"),
        }
    }
}

fn lane(result: Result<RekorHistory, ()>, ttl: Duration) -> (RekorLane, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let fake = FakeClient {
        calls: calls.clone(),
        result,
    };
    (RekorLane::new(Arc::new(fake), ttl), calls)
}

#[tokio::test]
async fn cache_serves_a_repeat_lookup_without_a_second_call() {
    let (lane, calls) = lane(
        Ok(RekorHistory {
            signed_in_log: true,
            identities: vec![],
        }),
        Duration::from_secs(3600),
    );
    let first = lane
        .lookup("ghcr.io/org/app@sha256:abc", None)
        .await
        .unwrap();
    assert!(first.signed_in_log);
    let second = lane
        .lookup("ghcr.io/org/app@sha256:abc", None)
        .await
        .unwrap();
    assert!(second.signed_in_log);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the second lookup is served from the cache — no new outbound query"
    );
}

#[tokio::test]
async fn an_error_is_not_cached_and_is_retried() {
    // An unreachable log must degrade AND retry — never freeze a degraded verdict in the cache.
    let (lane, calls) = lane(Err(()), Duration::from_secs(3600));
    assert!(
        lane.lookup("ghcr.io/org/app@sha256:abc", None)
            .await
            .is_err()
    );
    assert!(
        lane.lookup("ghcr.io/org/app@sha256:abc", None)
            .await
            .is_err()
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "an errored lookup is not cached — the next pass retries the log"
    );
}

#[tokio::test]
async fn an_expired_cache_entry_is_refetched() {
    let (lane, calls) = lane(
        Ok(RekorHistory::default()),
        Duration::from_millis(0), // every entry is already stale
    );
    lane.lookup("ghcr.io/org/app@sha256:abc", None)
        .await
        .unwrap();
    lane.lookup("ghcr.io/org/app@sha256:abc", None)
        .await
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a stale cache entry is refetched"
    );
}

#[test]
fn query_key_prefers_the_pinned_digest() {
    let key = HttpRekorClient::query_key("ghcr.io/org/app@sha256:deadbeef", None);
    assert!(matches!(key, Some(QueryKey::Hash(h)) if h == "sha256:deadbeef"));
}

#[test]
fn query_key_falls_back_to_an_email_identity() {
    let key = HttpRekorClient::query_key("ghcr.io/org/app:1", Some("dev@example.com"));
    assert!(matches!(key, Some(QueryKey::Email(e)) if e == "dev@example.com"));
}

#[test]
fn query_key_is_none_for_an_unqueryable_ref() {
    // A tag-only ref signed by a workflow URI has no index key — the lane must degrade, not
    // fabricate a divergence.
    let key = HttpRekorClient::query_key(
        "ghcr.io/org/app:1",
        Some("https://github.com/org/app/.github/workflows/r.yaml@refs/tags/v1"),
    );
    assert!(key.is_none());
}

#[test]
fn config_is_off_by_default() {
    // With PROTECTOR_REKOR_ENABLE unset, the lane is disabled — zero egress preserved.
    let config = RekorConfig::from_env();
    assert!(
        !config.enabled,
        "the Rekor lane is opt-in, OFF by default (zero egress)"
    );
    assert_eq!(config.base_url, RekorConfig::DEFAULT_URL);
}
