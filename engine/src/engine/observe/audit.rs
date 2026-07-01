//! The k8s audit-log ingest (JEF-269): the corroborating runtime signal the eBPF agent
//! **cannot** see — a secret fetched through the Kubernetes API via a workload's
//! ServiceAccount RBAC (`get`/`list`/`watch` on `secrets`).
//!
//! A pod reads a secret two ways. A mounted-file read the eBPF agent observes directly
//! (`Behavior::SecretRead { source: Mounted }`). An **API GET** is a TLS call to the
//! apiserver eBPF can't attribute as a secret read — protector models that path as
//! reachability (an RBAC `CanRead [RBAC-GRANTED]` chain) but can't observe it live. The
//! apiserver's own **audit log** records every secret GET/LIST/WATCH, so we ingest it as
//! the missing "corroborated-now" signal (ADR-0016: deviation — here, live authorized
//! access — is the signal).
//!
//! Mechanism (mirrors [`super::runtime`]): the apiserver's audit **webhook** POSTs audit
//! events to an authenticated in-cluster HTTP endpoint. [`parse_audit_event`] normalizes
//! each `get`/`list`/`watch` on `secrets` that was **allowed** and attributed to a
//! ServiceAccount into an [`AuditSecretRead`]; [`AuditEvents`] holds the recent ones on
//! the same short TTL as the runtime store, and the engine is woken only on a *new*
//! observation. The ServiceAccount→workload attribution (an SA maps to many pods — the
//! ambiguity is kept, never falsely narrowed) is engine-side, in the
//! [`AuditSecretReadAdapter`](super::adapter); this module stays a pure parser + store +
//! the cluster-facing HTTP glue.
//!
//! **Zero-egress (ADR-0015):** inbound only — the apiserver connects to protector,
//! in-cluster; protector makes no outbound call here. Every event field is **untrusted**:
//! sizes are bounded, malformed payloads are dropped (never panic), and audit events carry
//! secret *names/refs* only — never *values*, which we neither log nor store.
//!
//! Audit-only / shadow: a secret read is never *blocked* here (protector does not sit in
//! the request path); ingesting it only flips corroboration on an already-proven chain.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::Value;
use tokio::sync::mpsc::Sender;

use super::ingest_guard::{
    DEFAULT_BURST, DEFAULT_RATE_PER_SEC, IngestToken, RateLimit, bearer_auth, rate_limit,
};

/// Upper bound on any single string lifted out of an audit event. Audit events are
/// untrusted input; a hostile or buggy apiserver payload must not let one oversized field
/// balloon the store. Kubernetes names are ≤253 chars, so this never truncates a real one.
const MAX_FIELD_LEN: usize = 512;

/// Truncate an untrusted field to [`MAX_FIELD_LEN`] characters (char-boundary safe).
fn bounded(s: &str) -> String {
    s.chars().take(MAX_FIELD_LEN).collect()
}

/// A normalized, allowed API secret-read lifted from one audit event (JEF-269) — the
/// requesting ServiceAccount and the `objectRef` secret it read. Carries a secret's
/// *name/ref* only, never its value. The verb is retained so a `list`/`watch` of a
/// collection (no single `secret_name`) is represented honestly rather than as a `get` of
/// one named secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSecretRead {
    /// The requesting ServiceAccount's namespace (parsed from
    /// `system:serviceaccount:<ns>:<name>`).
    pub sa_namespace: String,
    /// The requesting ServiceAccount's name.
    pub sa_name: String,
    /// The secret's namespace (`objectRef.namespace`) — absent for a cluster-scoped
    /// list/watch across all namespaces.
    pub secret_namespace: Option<String>,
    /// The secret's name (`objectRef.name`) — absent for a `list`/`watch` of a collection.
    pub secret_name: Option<String>,
    /// The read verb: `get`, `list`, or `watch`.
    pub verb: String,
}

impl AuditSecretRead {
    /// A human, non-value display for the secret read — `ns/name`, `ns/*` for a namespaced
    /// collection list/watch, or `*` for a cluster-wide one. Names/refs only, never values.
    pub fn secret_display(&self) -> String {
        match (&self.secret_namespace, &self.secret_name) {
            (Some(ns), Some(name)) => format!("{ns}/{name}"),
            (Some(ns), None) => format!("{ns}/*"),
            (None, Some(name)) => name.clone(),
            (None, None) => "*".to_string(),
        }
    }
}

/// A time-windowed store of recent API secret-reads. Thread-safe so the HTTP ingest task
/// and the engine loop can share it. Deliberately parallel to [`super::runtime::RuntimeEvents`]:
/// corroboration is live evidence or it is nothing, so entries expire on the same TTL.
pub struct AuditEvents {
    inner: Mutex<Vec<(Instant, AuditSecretRead)>>,
    ttl: Duration,
}

impl AuditEvents {
    /// Upper bound on retained reads, enforced on top of the TTL so an ingest flood can't
    /// grow the store without limit before entries expire.
    const MAX_EVENTS: usize = 4096;

    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
            ttl,
        }
    }

    /// Record a read as of now, pruning anything past the TTL. Returns whether it was a
    /// **change** — see [`Self::record_at`].
    pub fn record(&self, read: AuditSecretRead) -> bool {
        self.record_at(Instant::now(), read)
    }

    /// The reads still within the TTL window as of now.
    pub fn current(&self) -> Vec<AuditSecretRead> {
        self.current_at(Instant::now())
    }

    /// Record a read as of `now`, pruning expired entries. Returns whether the store
    /// actually **changed** — i.e. this was a (SA, secret, verb) we weren't already
    /// holding. A repeat refreshes its freshness and returns `false`, so the caller can
    /// skip waking the engine for activity that wouldn't alter any verdict (a workload's
    /// SA re-reading the same secret every reconcile loop is the common case).
    fn record_at(&self, now: Instant, read: AuditSecretRead) -> bool {
        let mut events = self.inner.lock().expect("audit-events mutex poisoned");
        events.retain(|(at, _)| now.duration_since(*at) < self.ttl);
        if let Some(slot) = events.iter_mut().find(|(_, e)| *e == read) {
            slot.0 = now; // already known — refresh its TTL, nothing new to react to
            return false;
        }
        events.push((now, read));
        if events.len() > Self::MAX_EVENTS {
            let excess = events.len() - Self::MAX_EVENTS;
            events.drain(0..excess);
        }
        true
    }

    fn current_at(&self, now: Instant) -> Vec<AuditSecretRead> {
        self.inner
            .lock()
            .expect("audit-events mutex poisoned")
            .iter()
            .filter(|(at, _)| now.duration_since(*at) < self.ttl)
            .map(|(_, r)| r.clone())
            .collect()
    }
}

/// Parse the requesting username into a `(namespace, name)` ServiceAccount pair, or `None`
/// if it isn't a ServiceAccount (`system:serviceaccount:<ns>:<name>`). Only SA reads can
/// corroborate a workload's RBAC chain — a human `kubectl get secret` is a real audit
/// event but it isn't a workload's runtime behavior, so it is not corroboration here.
fn parse_service_account(username: &str) -> Option<(String, String)> {
    let rest = username.strip_prefix("system:serviceaccount:")?;
    let (ns, name) = rest.split_once(':')?;
    if ns.is_empty() || name.is_empty() {
        return None;
    }
    Some((bounded(ns), bounded(name)))
}

/// Normalize one Kubernetes audit event into an [`AuditSecretRead`], or `None` if it isn't
/// an allowed API secret-read attributable to a ServiceAccount. Drops (returns `None`) any
/// event that is:
///   * not a `get`/`list`/`watch` (a create/update/delete is not a read),
///   * not on `secrets` in the core API group (a non-secret resource),
///   * **not allowed** (a denied request never counts as a read — ADR-0016 says observe
///     it, never mis-record it), or
///   * not attributed to a ServiceAccount.
///
/// Every field is treated as untrusted: missing/wrong-typed fields collapse to `None`
/// (never a panic) and string fields are size-bounded. Secret *values* never appear in an
/// audit event; only the `objectRef` name/namespace is read.
pub fn parse_audit_event(event: &Value) -> Option<AuditSecretRead> {
    let verb = event.get("verb")?.as_str()?;
    if !matches!(verb, "get" | "list" | "watch") {
        return None;
    }

    let object_ref = event.get("objectRef")?;
    if object_ref.get("resource").and_then(Value::as_str)? != "secrets" {
        return None;
    }
    // Secrets live in the core group, encoded as an absent or empty `apiGroup`. A non-core
    // `secrets` resource (some CRD named "secrets") is not a Kubernetes Secret — drop it.
    if let Some(group) = object_ref.get("apiGroup").and_then(Value::as_str)
        && !group.is_empty()
    {
        return None;
    }

    // The authorizer's decision. Only an explicit "allow" is a read; a "forbid"/deny (or a
    // missing decision) is recorded as nothing, never as a read.
    let decision = event
        .get("annotations")
        .and_then(|a| a.get("authorization.k8s.io/decision"))
        .and_then(Value::as_str);
    if decision != Some("allow") {
        return None;
    }

    let username = event.get("user")?.get("username")?.as_str()?;
    let (sa_namespace, sa_name) = parse_service_account(username)?;

    let secret_namespace = object_ref
        .get("namespace")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(bounded);
    let secret_name = object_ref
        .get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(bounded);

    Some(AuditSecretRead {
        sa_namespace,
        sa_name,
        secret_namespace,
        secret_name,
        verb: verb.to_string(),
    })
}

/// Upper bound on audit events processed from one POST body. The apiserver's audit webhook
/// batches events into an `EventList`; a batch is normally small, but the body is untrusted,
/// so cap the number we walk (the body-size limit already bounds bytes; this bounds the
/// per-request work). Excess events are dropped with a warning.
const MAX_EVENTS_PER_BODY: usize = 1024;

/// Parse an audit-webhook POST body into the secret-reads it carries. The apiserver posts
/// an `audit.k8s.io/v1 EventList` (`{"items": [...]}`); a bare single event is also
/// accepted for robustness. Non-matching events are silently skipped (that's the common
/// case — most audited requests aren't secret reads).
pub fn parse_audit_body(body: &Value) -> Vec<AuditSecretRead> {
    match body.get("items").and_then(Value::as_array) {
        Some(items) => {
            if items.len() > MAX_EVENTS_PER_BODY {
                tracing::warn!(
                    total = items.len(),
                    cap = MAX_EVENTS_PER_BODY,
                    "audit EventList exceeds the per-body cap; processing only the first {MAX_EVENTS_PER_BODY}"
                );
            }
            items
                .iter()
                .take(MAX_EVENTS_PER_BODY)
                .filter_map(parse_audit_event)
                .collect()
        }
        None => parse_audit_event(body).into_iter().collect(),
    }
}

/// Shared state for the ingest handler: the event store and a wake channel.
type IngestState = (Arc<AuditEvents>, Sender<()>);

/// Receive one audit-webhook POST (an `EventList` or a single event), record the secret
/// reads it carries, and wake the engine iff the store changed. Always returns `200`:
/// signalling an error to the apiserver's audit backend triggers a retry-storm, and an
/// unparseable or irrelevant event is expected, not exceptional.
async fn ingest(
    State((events, notify)): State<IngestState>,
    Json(body): Json<Value>,
) -> StatusCode {
    let mut changed = false;
    for read in parse_audit_body(&body) {
        changed |= events.record(read);
    }
    if changed {
        // A full channel already has a pending wake — dropping this one is fine.
        let _ = notify.try_send(());
    }
    StatusCode::OK
}

/// Serve the k8s audit-log ingest (JEF-269). One route (`/`) accepts the apiserver's audit
/// webhook POSTs. Guarded exactly like the runtime ingest ([`super::runtime::serve_runtime`]):
/// a bearer token (rejected 401 before deserialization; a loud WARNING if unconfigured so
/// the engine can deploy ahead of the Secret), a per-peer rate limit, and a body-size cap.
/// This is the cluster-facing glue; the parser and store it drives are what the tests cover.
pub async fn serve_audit(
    addr: SocketAddr,
    events: Arc<AuditEvents>,
    notify: Sender<()>,
) -> anyhow::Result<()> {
    let token = IngestToken::from_env();
    let limiter = RateLimit::new(DEFAULT_RATE_PER_SEC, DEFAULT_BURST);

    let mut app = Router::new()
        .route("/", post(ingest))
        // An audit batch is small; cap the body so the apiserver can't OOM the engine with
        // a giant POST (mirrors the runtime ingest and the webhook server).
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state((events, notify));

    app = app.layer(axum::middleware::from_fn_with_state(limiter, rate_limit));

    match token {
        Some(token) => {
            app = app.layer(axum::middleware::from_fn_with_state(token, bearer_auth));
            tracing::info!(%addr, "k8s audit-log ingest listening (/) — bearer-authenticated");
        }
        None => {
            tracing::warn!(
                %addr,
                "k8s audit-log ingest is UNAUTHENTICATED — set PROTECTOR_INGEST_TOKEN or \
                 PROTECTOR_INGEST_TOKEN_FILE to require a bearer token. Any caller that can \
                 reach this port could post forged secret-read observations."
            );
        }
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
