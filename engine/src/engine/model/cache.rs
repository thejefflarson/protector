//! Bounded in-memory cache for model completions (JEF-362).
//!
//! This is the ONE mechanism that keeps every model consumer off the wire for a
//! repeated request. Before JEF-362 caching lived per-consumer — the adjudicator
//! cached its *verdict* (JEF-350's fingerprint/journal, still in place for restart
//! survival) — but that only covered one consumer. Moving the cache to the client
//! boundary ([`super::chat`]) covers the adjudication path AND any future consumer
//! with a single bounded LRU, keyed on the request itself rather than on a
//! consumer-specific fingerprint.
//!
//! What is cached and what is not:
//! - Only a **successful completion** (a 200 whose body yields a `content` string) is
//!   stored. Transport errors, timeouts, non-success statuses, over-cap bodies, and
//!   unparseable replies are NOT cached — they must retry next pass (see [`super::chat`]).
//! - `keep_warm` ([`super::keep_warm`]) is a side-effecting keep-alive ping and does
//!   NOT go through this cache: caching it would let the model unload. It calls the
//!   endpoint directly, so it bypasses the cache by construction.
//!
//! Concurrency (JEF-337 made adjudication concurrent): the cache is a
//! `Mutex<LruCache>`. The critical section is tiny — a get-and-clone or a put — and the
//! lock is NEVER held across the HTTP `await` in [`super::chat`] (get releases the lock
//! before the request fires; put takes it again only to store the result). So the cache
//! sits in front of the concurrent dispatch without reintroducing any serialization.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::{Mutex, OnceLock};

use lru::LruCache;
use serde_json::Value;

/// Default cap on the number of cached completions. Each entry is a small model reply
/// (a verdict JSON or a hypothesis list, bounded by `MAX_RESPONSE_BYTES`), so 512
/// entries is a modest, bounded memory footprint that comfortably covers a cluster's
/// worth of distinct entries/prompts within a pass. Override with
/// `PROTECTOR_MODEL_CACHE_ENTRIES`.
pub const DEFAULT_CACHE_ENTRIES: usize = 512;

/// The configured cache capacity, from `PROTECTOR_MODEL_CACHE_ENTRIES`
/// (default [`DEFAULT_CACHE_ENTRIES`]). Unset / unparseable / `0` falls back to the
/// default — an `LruCache` must have a non-zero capacity.
fn cache_capacity() -> NonZeroUsize {
    parse_cache_entries(
        std::env::var("PROTECTOR_MODEL_CACHE_ENTRIES")
            .ok()
            .as_deref(),
    )
}

/// Pure parse of the `PROTECTOR_MODEL_CACHE_ENTRIES` value, split out so it's testable
/// without process-global env: unset / unparseable / `0` → [`DEFAULT_CACHE_ENTRIES`]
/// (never a zero-capacity cache); any positive value is that many entries.
fn parse_cache_entries(raw: Option<&str>) -> NonZeroUsize {
    let entries = raw
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_CACHE_ENTRIES);
    // `entries` is guaranteed positive above; fall back to 1 only if the const were 0.
    NonZeroUsize::new(entries).unwrap_or(NonZeroUsize::MIN)
}

/// The process-wide model-completion cache, initialized once from the environment on
/// first use. A single shared instance so every model consumer is covered by the one
/// bounded mechanism (the whole point of JEF-362).
static CACHE: OnceLock<Mutex<LruCache<u64, String>>> = OnceLock::new();

fn cache() -> &'static Mutex<LruCache<u64, String>> {
    CACHE.get_or_init(|| Mutex::new(LruCache::new(cache_capacity())))
}

/// A stable hash of the full request that determines the completion: the endpoint plus
/// the request body (model name, messages/prompt, response-format, and output-affecting
/// options like `temperature`/`max_tokens`). The body is canonicalized (object keys
/// sorted, array order preserved) before hashing so a byte-stable request always yields
/// the same key regardless of JSON field ordering.
pub(super) fn cache_key(endpoint: &str, body: &Value) -> u64 {
    let mut hasher = DefaultHasher::new();
    endpoint.hash(&mut hasher);
    canonicalize(body).hash(&mut hasher);
    hasher.finish()
}

/// Render a JSON value into a canonical string: object keys are sorted (so field
/// ordering never changes the key) while array order is preserved (message order is
/// semantically meaningful and MUST affect the key). Scalars use their JSON form.
fn canonicalize(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let inner: Vec<String> = entries
                .iter()
                .map(|(k, v)| format!("{k}:{}", canonicalize(v)))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonicalize).collect();
            format!("[{}]", inner.join(","))
        }
        other => other.to_string(),
    }
}

/// Look up a cached completion. Locks, clones the hit, and releases — the lock is never
/// held across an `await`. A `get` also marks the entry most-recently-used.
pub(super) fn get(key: u64) -> Option<String> {
    let mut guard = cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.get(&key).cloned()
}

/// Store a successful completion. Locks briefly to insert, evicting the
/// least-recently-used entry if at capacity, then releases.
pub(super) fn put(key: u64, value: String) {
    let mut guard = cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.put(key, value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_entries_unset_uses_the_default() {
        assert_eq!(
            parse_cache_entries(None).get(),
            DEFAULT_CACHE_ENTRIES,
            "an unset PROTECTOR_MODEL_CACHE_ENTRIES must fall back to the default"
        );
    }

    #[test]
    fn parse_entries_zero_and_garbage_fall_back_to_the_default() {
        assert_eq!(
            parse_cache_entries(Some("0")).get(),
            DEFAULT_CACHE_ENTRIES,
            "0 must fall back to the default (an LruCache needs a non-zero capacity)"
        );
        assert_eq!(
            parse_cache_entries(Some("not-a-number")).get(),
            DEFAULT_CACHE_ENTRIES,
            "an unparseable value must fall back to the default"
        );
        assert_eq!(parse_cache_entries(Some("")).get(), DEFAULT_CACHE_ENTRIES);
    }

    #[test]
    fn parse_entries_positive_is_honoured() {
        assert_eq!(parse_cache_entries(Some("16")).get(), 16);
        assert_eq!(
            parse_cache_entries(Some(" 8 ")).get(),
            8,
            "a trimmed positive value is honoured"
        );
    }

    #[test]
    fn key_is_stable_and_body_order_independent() {
        let a = json!({ "model": "m", "temperature": 0, "messages": [{ "role": "user", "content": "hi" }] });
        // Same fields, different insertion order — must hash identically.
        let b = json!({ "messages": [{ "content": "hi", "role": "user" }], "temperature": 0, "model": "m" });
        assert_eq!(
            cache_key("http://ollama/v1", &a),
            cache_key("http://ollama/v1", &b),
            "field ordering must not change the cache key"
        );
    }

    #[test]
    fn key_differs_on_any_response_determining_field() {
        let base = json!({ "model": "m", "temperature": 0, "messages": [{ "role": "user", "content": "hi" }] });
        let ep = "http://ollama/v1";
        let base_key = cache_key(ep, &base);

        let other_prompt = json!({ "model": "m", "temperature": 0, "messages": [{ "role": "user", "content": "bye" }] });
        assert_ne!(
            base_key,
            cache_key(ep, &other_prompt),
            "a different prompt must miss"
        );

        let other_model = json!({ "model": "n", "temperature": 0, "messages": [{ "role": "user", "content": "hi" }] });
        assert_ne!(
            base_key,
            cache_key(ep, &other_model),
            "a different model must miss"
        );

        let other_temp = json!({ "model": "m", "temperature": 1, "messages": [{ "role": "user", "content": "hi" }] });
        assert_ne!(
            base_key,
            cache_key(ep, &other_temp),
            "a different temperature must miss"
        );

        assert_ne!(
            base_key,
            cache_key("http://other/v1", &base),
            "a different endpoint must miss"
        );
    }

    #[test]
    fn message_order_affects_the_key() {
        let a = json!({ "messages": [{ "role": "user", "content": "a" }, { "role": "user", "content": "b" }] });
        let b = json!({ "messages": [{ "role": "user", "content": "b" }, { "role": "user", "content": "a" }] });
        assert_ne!(
            cache_key("e", &a),
            cache_key("e", &b),
            "array (message) order is semantically meaningful and must affect the key"
        );
    }

    /// The LRU evicts the least-recently-used entry at the capacity bound, and a `get`
    /// on an entry marks it most-recently-used so it survives the next eviction. Tested
    /// on a fresh `LruCache` instance (not the process-global) so the bound is exact.
    #[test]
    fn lru_evicts_at_capacity() {
        let mut cache = LruCache::<u64, String>::new(NonZeroUsize::new(2).unwrap());
        cache.put(1, "one".into());
        cache.put(2, "two".into());
        // Touch key 1 so key 2 becomes the least-recently-used.
        assert_eq!(cache.get(&1).map(String::as_str), Some("one"));
        cache.put(3, "three".into());
        assert_eq!(cache.len(), 2, "capacity bound holds");
        assert_eq!(
            cache.get(&2),
            None,
            "the least-recently-used entry was evicted"
        );
        assert_eq!(
            cache.get(&1).map(String::as_str),
            Some("one"),
            "the touched entry survived"
        );
        assert_eq!(
            cache.get(&3).map(String::as_str),
            Some("three"),
            "the newest entry is present"
        );
    }

    /// The process-global get/put round-trips a value. Uses a key unlikely to collide
    /// with any real request so it doesn't perturb other tests sharing the global cache.
    #[test]
    fn global_get_put_round_trips() {
        let key = cache_key("test://global-round-trip", &json!({ "probe": true }));
        assert_eq!(get(key), None, "a fresh key misses");
        put(key, "cached".into());
        assert_eq!(
            get(key).as_deref(),
            Some("cached"),
            "a stored value is served back"
        );
    }

    // --- Integration: the cache seen end-to-end through `super::chat`/`super::keep_warm`.
    // A localhost server counts every connection it accepts, so a cache hit is provable by
    // the wire seeing ZERO extra requests. Each test binds a fresh random port, so its
    // (endpoint, body) key is unique — no collision with other tests on the shared global
    // cache.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // The parent `model` module owns `chat`/`keep_warm`/`timeout_only_client`. From this
    // nested `tests` module `super` is `cache`, so reach them by the crate path.
    use crate::engine::model::{chat, keep_warm, timeout_only_client};

    /// A raw HTTP 200 carrying an OpenAI-shaped completion with `content`.
    fn ok_response(content: &str) -> String {
        let payload = json!({ "choices": [{ "message": { "content": content } }] }).to_string();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            payload.len(),
            payload
        )
    }

    /// A raw HTTP 500 with a JSON error body — what an OOM-crashing Ollama returns.
    fn error_500() -> String {
        let payload = json!({ "error": "model runner crashed" }).to_string();
        format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            payload.len(),
            payload
        )
    }

    /// Spawn a localhost server that answers connection `n` with `responses[n]` (reusing
    /// the last for any beyond), counting every connection accepted. Returns the endpoint
    /// URL, the shared connection counter, and the server task handle (abort it to stop).
    async fn spawn_counting_server(
        responses: Vec<String>,
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let srv_count = count.clone();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let n = srv_count.fetch_add(1, Ordering::SeqCst);
                let resp = responses
                    .get(n)
                    .or_else(|| responses.last())
                    .cloned()
                    .unwrap_or_default();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.flush().await;
                });
            }
        });
        (format!("http://{addr}/v1/chat/completions"), count, handle)
    }

    /// A second identical request is served from the cache with ZERO HTTP: the counting
    /// server sees exactly ONE connection though `chat` was called twice.
    #[tokio::test]
    async fn identical_request_served_from_cache_with_zero_http() {
        let (endpoint, count, server) = spawn_counting_server(vec![ok_response("hit-me")]).await;
        let client = timeout_only_client(5).unwrap();

        let first = chat(&client, &endpoint, "m", "same-prompt").await;
        assert_eq!(
            first.as_deref(),
            Some("hit-me"),
            "the miss returns the model reply"
        );

        let second = chat(&client, &endpoint, "m", "same-prompt").await;
        assert_eq!(
            second.as_deref(),
            Some("hit-me"),
            "the second identical call returns the cached reply"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "the second identical call must be served from cache — no second HTTP request"
        );
        server.abort();
    }

    /// A different request misses and calls through: two distinct prompts to the same
    /// endpoint both hit the wire.
    #[tokio::test]
    async fn different_request_misses_and_calls_through() {
        let (endpoint, count, server) =
            spawn_counting_server(vec![ok_response("a"), ok_response("b")]).await;
        let client = timeout_only_client(5).unwrap();

        assert_eq!(
            chat(&client, &endpoint, "m", "prompt-a").await.as_deref(),
            Some("a")
        );
        assert_eq!(
            chat(&client, &endpoint, "m", "prompt-b").await.as_deref(),
            Some("b")
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "two distinct requests must each hit the wire (a miss each)"
        );
        server.abort();
    }

    /// An error response is NOT cached: a 500 returns `None`, and an identical follow-up
    /// call retries (hits the wire again) rather than being served the error from cache.
    #[tokio::test]
    async fn error_response_is_not_cached_and_retries() {
        let (endpoint, count, server) =
            spawn_counting_server(vec![error_500(), ok_response("recovered")]).await;
        let client = timeout_only_client(5).unwrap();

        let first = chat(&client, &endpoint, "m", "retry-me").await;
        assert_eq!(
            first, None,
            "a 500 is treated as unavailable, not a verdict"
        );

        let second = chat(&client, &endpoint, "m", "retry-me").await;
        assert_eq!(
            second.as_deref(),
            Some("recovered"),
            "the identical follow-up retries and gets the recovered reply — the error was not cached"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "both calls must hit the wire — a non-success response is never cached"
        );
        server.abort();
    }

    /// `keep_warm` bypasses the cache entirely — caching a keep-alive ping would let the
    /// model unload. Two pings both hit the wire.
    #[tokio::test]
    async fn keep_warm_bypasses_the_cache() {
        let (endpoint, count, server) =
            spawn_counting_server(vec![ok_response("ok"), ok_response("ok")]).await;
        let client = timeout_only_client(5).unwrap();

        assert!(
            keep_warm(&client, &endpoint, "m").await,
            "first ping answered"
        );
        assert!(
            keep_warm(&client, &endpoint, "m").await,
            "second ping answered"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "keep_warm must always hit the wire (never cached) so the model stays resident"
        );
        server.abort();
    }

    /// Concurrent identical requests must not deadlock — the cache lock is never held
    /// across the HTTP await, so every call completes normally.
    #[tokio::test]
    async fn concurrent_identical_requests_do_not_deadlock() {
        let (endpoint, _count, server) = spawn_counting_server(vec![ok_response("v")]).await;
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let endpoint = endpoint.clone();
            set.spawn(async move {
                let client = timeout_only_client(5).unwrap();
                chat(&client, &endpoint, "m", "concurrent").await
            });
        }
        while let Some(res) = set.join_next().await {
            assert_eq!(
                res.unwrap().as_deref(),
                Some("v"),
                "every concurrent call completes (no lock held across await)"
            );
        }
        server.abort();
    }
}
