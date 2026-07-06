//! The reporter: batches a window's observations and (when this node has one) its per-node
//! liveness beacon into ONE [`RuntimeReport`] envelope and POSTs it to the engine's unified
//! behavioral ingest (`/behavior`, ADR-0014 / JEF-336). In-cluster, mesh-protected hop; the agent
//! never sends behavioral data anywhere else (the data is a map of the cluster — it stays
//! in-cluster, per VISION's local-first conviction).
//!
//! One endpoint, one envelope (JEF-336): liveness always travels with the report, so a quiet node
//! still POSTs (empty observations, liveness present) and the engine reads it HEALTHY-quiet rather
//! than blind. This replaced a separate `/agent-liveness` beacon POST that shipped a single
//! `AgentReport` the engine's array-typed handler 422-rejected — the "no agents connected" bug.
//!
//! The POST carries an `Authorization: Bearer <token>` (Fix A) so the engine can
//! reject forged observations from any other caller that can reach :9999. The token
//! is the shared secret the engine also reads; authentication (this header) is
//! complementary to the cluster's Linkerd mesh authorization.
//!
//! ## Self-healing token rotation (JEF-240)
//!
//! The token is read once at startup, but the kubelet updates the mounted secret file
//! in place when the Secret rolls. If the engine and agent read `protector-ingest-auth`
//! seconds apart during a rotation, the agent can be left holding a stale token and the
//! engine 401-rejects *every* batch — silently dropping 100% of behavioral signal until
//! the pod restarts. To self-heal without a restart, the reporter tracks consecutive
//! 401s and, past a small threshold, re-resolves the token from
//! `PROTECTOR_INGEST_TOKEN_FILE` (the kubelet has by then written the fresh value) and
//! uses it for subsequent posts. The counter resets on the first 2xx. Sustained
//! rejection is escalated from a per-batch WARN to a rate-limited ERROR plus delivered/
//! rejected counters folded into the agent's periodic heartbeat.

use std::time::Duration;

use protector_behavior::RuntimeReport;

/// Re-resolve the token after this many consecutive 401s. Small so a genuine skew heals
/// fast, but >1 so a single transient 401 (e.g. an engine mid-restart that hasn't loaded
/// its own token yet) doesn't churn a file read.
const RERESOLVE_AFTER_401S: u32 = 3;

/// Emit the escalated ERROR at most once per this many consecutive rejections, so a
/// wedged ingest is loud once (and on a slow cadence) rather than a WARN every 30s.
const ERROR_EVERY_N_REJECTIONS: u64 = 20;

/// Resolves the ingest bearer from the environment — the seam JEF-240 re-invokes to pick
/// up a rotated secret file. Boxed so tests can inject a deterministic, mutating source
/// (a stale-then-fresh token) without touching the filesystem or sleeping.
type TokenSource = Box<dyn FnMut() -> Option<String> + Send>;

/// POSTs per-window [`RuntimeReport`] envelopes (observations + optional per-node liveness beacon,
/// JEF-336) to `{base}/behavior`.
pub struct Reporter {
    client: reqwest::Client,
    url: String,
    /// Shared-secret bearer for the engine's ingest authn (Fix A). `None` = send no
    /// `Authorization` header (the engine then runs the ingest unauthenticated, which
    /// it warns about); set it once the Secret has rolled out.
    token: Option<String>,
    /// Re-resolves the token on sustained 401s (JEF-240). Defaults to reading
    /// `PROTECTOR_INGEST_TOKEN_FILE` / `PROTECTOR_INGEST_TOKEN`.
    token_source: TokenSource,
    /// Consecutive 401s since the last accepted (2xx) batch. Drives both re-resolution
    /// and the rate-limited ERROR. Reset to 0 on any success.
    consecutive_401s: u32,
    /// Cumulative observations the engine has accepted, for the heartbeat.
    delivered_total: u64,
    /// Cumulative batches the engine has rejected (any non-2xx status), for the heartbeat.
    rejected_total: u64,
}

/// Resolve the ingest token from the environment, file-before-env — matching the
/// engine's own resolution so the agent and engine read the same secret:
///
///   * `PROTECTOR_INGEST_TOKEN_FILE` — a mounted file (takes precedence); its trailing
///     newline (the usual secret-file artifact) is trimmed.
///   * `PROTECTOR_INGEST_TOKEN` — an inline value.
///
/// `None` when neither is set or the resolved value is empty. Re-invoked by the reporter
/// on sustained 401s, so a freshly-rotated secret file is picked up without a restart.
fn ingest_token() -> Option<String> {
    if let Ok(path) = std::env::var("PROTECTOR_INGEST_TOKEN_FILE") {
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let token = contents.trim().to_string();
                if token.is_empty() {
                    tracing::warn!(%path, "PROTECTOR_INGEST_TOKEN_FILE is empty — ingest token unset");
                    return None;
                }
                return Some(token);
            }
            Err(error) => {
                tracing::warn!(%path, %error, "PROTECTOR_INGEST_TOKEN_FILE unreadable — ingest token unset");
                return None;
            }
        }
    }
    std::env::var("PROTECTOR_INGEST_TOKEN")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

impl Reporter {
    /// `base` is the engine's runtime-ingest URL (e.g.
    /// `http://protector.protector.svc.cluster.local:9999`). The ingest token is read
    /// once from the environment (file before env); on sustained 401s it is re-read from
    /// the same source (JEF-240).
    pub fn new(base: &str) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self::with_source(client, base, Box::new(ingest_token)))
    }

    /// Construct over an explicit token source — the JEF-240 seam. `source` is resolved
    /// once now (the startup read) and re-invoked on sustained 401s. Used by the crate's
    /// tests to inject a stale-then-fresh token deterministically.
    fn with_source(client: reqwest::Client, base: &str, mut source: TokenSource) -> Self {
        let token = source();
        if token.is_none() {
            tracing::warn!(
                "no ingest token configured (PROTECTOR_INGEST_TOKEN / \
                 PROTECTOR_INGEST_TOKEN_FILE) — posting behavioral observations \
                 without an Authorization header"
            );
        }
        let base = base.trim_end_matches('/');
        Self {
            client,
            url: format!("{base}/behavior"),
            token,
            token_source: source,
            consecutive_401s: 0,
            delivered_total: 0,
            rejected_total: 0,
        }
    }

    /// Build the POST for one [`RuntimeReport`] envelope, attaching the bearer header when a token
    /// is configured. Split out so the header/URL wiring is unit-testable without a server.
    fn build_request(&self, report: &RuntimeReport) -> reqwest::RequestBuilder {
        let mut req = self.client.post(&self.url).json(report);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        req
    }

    /// Cumulative (delivered, rejected) tallies for the periodic heartbeat (JEF-240).
    /// `delivered` counts accepted observations; `rejected` counts rejected batches.
    pub fn counters(&self) -> (u64, u64) {
        (self.delivered_total, self.rejected_total)
    }

    /// Handle a 401 (`Unauthorized`): bump the consecutive count, re-resolve the token at
    /// the threshold (a rotated secret file self-heals here, no restart), and escalate to
    /// a rate-limited ERROR. A non-401 rejection is counted but doesn't trigger a re-read
    /// — only an auth failure implicates the token.
    fn on_unauthorized(&mut self) {
        self.consecutive_401s = self.consecutive_401s.saturating_add(1);

        // At the threshold, re-resolve the token from its source. The kubelet has by now
        // written the rotated secret file, so this picks up the fresh value the engine is
        // already using. Only swap when it actually changed, to keep the path quiet
        // (and to name the real fault when it didn't: the two secrets genuinely disagree).
        if self.consecutive_401s == RERESOLVE_AFTER_401S {
            let fresh = (self.token_source)();
            if fresh != self.token {
                tracing::info!(
                    consecutive_401s = self.consecutive_401s,
                    "ingest token re-resolved after sustained 401s — retrying with the \
                     current secret (JEF-240 self-heal)"
                );
                self.token = fresh;
            } else {
                tracing::warn!(
                    consecutive_401s = self.consecutive_401s,
                    "sustained 401s but the re-resolved ingest token is unchanged — the \
                     engine and agent secrets disagree (check protector-ingest-auth)"
                );
            }
        }

        // Escalate from per-batch WARN to a rate-limited ERROR: loud once, then on a slow
        // cadence, so a wedged ingest is impossible to miss without spamming every flush.
        if self.consecutive_401s == 1
            || u64::from(self.consecutive_401s).is_multiple_of(ERROR_EVERY_N_REJECTIONS)
        {
            tracing::error!(
                consecutive_401s = self.consecutive_401s,
                rejected_total = self.rejected_total,
                "behavior ingest rejecting every batch with 401 — the agent's bearer is \
                 not accepted; dropping behavioral signal until the token agrees"
            );
        }
    }

    /// Send one per-window [`RuntimeReport`] envelope (observations + optional liveness, JEF-336);
    /// returns how many observations were accepted (0 on failure, or when the envelope carries
    /// neither observations nor liveness). An envelope with empty observations but a liveness beacon
    /// IS sent — that is the quiet-node path that keeps a silent node reading HEALTHY-quiet, not
    /// blind. Best-effort: a failed POST is logged and dropped — behavioral evidence is additive, so
    /// a lost report costs a little freshness, never correctness, and must never wedge the agent.
    /// The caller rolls the count into an interval heartbeat; per-send detail stays at debug.
    ///
    /// On a run of 401s the token is re-resolved (JEF-240) so a secret rotation self-heals
    /// without a pod restart; the run-length resets on the first 2xx.
    pub async fn send(&mut self, report: &RuntimeReport) -> usize {
        if report.observations.is_empty() && report.liveness.is_none() {
            return 0;
        }
        let n = report.observations.len();
        match self.build_request(report).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!(
                    observations = n,
                    liveness = report.liveness.is_some(),
                    "reported runtime envelope"
                );
                if self.consecutive_401s > 0 {
                    tracing::info!(
                        after_401s = self.consecutive_401s,
                        "behavior ingest accepted a batch again — ingest auth recovered"
                    );
                }
                self.consecutive_401s = 0;
                self.delivered_total = self.delivered_total.saturating_add(n as u64);
                n
            }
            Ok(resp) if resp.status() == reqwest::StatusCode::UNAUTHORIZED => {
                self.rejected_total = self.rejected_total.saturating_add(1);
                self.on_unauthorized();
                0
            }
            Ok(resp) => {
                // A non-auth rejection (e.g. 400/500): the token isn't implicated, so no
                // re-read; a 401 run in progress is left intact (this isn't a recovery).
                self.rejected_total = self.rejected_total.saturating_add(1);
                tracing::warn!(status = %resp.status(), "behavior ingest rejected batch");
                0
            }
            Err(error) => {
                tracing::warn!(%error, "behavior ingest unreachable");
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protector_behavior::{
        AgentReport, Attribution, Behavior, RuntimeObservation, SecretReadSource,
    };

    fn reporter_with(token: Option<&str>) -> Reporter {
        let owned = token.map(str::to_string);
        let for_source = owned.clone();
        Reporter {
            client: reqwest::Client::new(),
            url: "http://engine.svc:9999/behavior".to_string(),
            token: owned,
            token_source: Box::new(move || for_source.clone()),
            consecutive_401s: 0,
            delivered_total: 0,
            rejected_total: 0,
        }
    }

    fn sample_observation() -> RuntimeObservation {
        RuntimeObservation {
            attribution: Attribution::by_namespaced_name("app", "web"),
            source: Some("agent".into()),
            observed_at_ms: None,
            node: None,
            behavior: Behavior::SecretRead {
                secret: "app/session-key".into(),
                source: SecretReadSource::Mounted,
            },
        }
    }

    fn sample_report() -> RuntimeReport {
        RuntimeReport {
            observations: vec![sample_observation()],
            liveness: None,
        }
    }

    /// When a token is configured the POST carries `Authorization: Bearer <token>`.
    #[test]
    fn attaches_bearer_header_when_token_set() {
        let reporter = reporter_with(Some("s3cr3t"));
        let req = reporter
            .build_request(&sample_report())
            .build()
            .expect("request builds");
        let auth = req
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .expect("Authorization header present");
        assert_eq!(auth, "Bearer s3cr3t");
    }

    /// JEF-336: the unified envelope — including a quiet-node liveness-only report — POSTs to the
    /// single `{base}/behavior` route carrying the same bearer (no separate `/agent-liveness`).
    #[test]
    fn liveness_rides_the_behavior_envelope_with_bearer() {
        let reporter = reporter_with(Some("s3cr3t"));
        let report = RuntimeReport {
            observations: Vec::new(),
            liveness: Some(AgentReport {
                node: "node-a".into(),
                probes_loaded: 6,
                probes_total: 6,
                signals_emitted: 3,
                observed_at_ms: None,
            }),
        };
        let req = reporter
            .build_request(&report)
            .build()
            .expect("request builds");
        assert_eq!(req.url().as_str(), "http://engine.svc:9999/behavior");
        assert_eq!(
            req.headers().get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer s3cr3t"
        );
    }

    /// Without a token, no Authorization header is sent (the engine warns + accepts,
    /// or rejects if it has a token — the rollout-ordering contract).
    #[test]
    fn omits_bearer_header_when_token_unset() {
        let reporter = reporter_with(None);
        let req = reporter
            .build_request(&sample_report())
            .build()
            .expect("request builds");
        assert!(
            req.headers().get(reqwest::header::AUTHORIZATION).is_none(),
            "no Authorization header when token unset"
        );
        // The body is still the JSON envelope — auth is the only thing that changed.
        assert_eq!(req.url().as_str(), "http://engine.svc:9999/behavior");
    }

    /// JEF-240: a token source backed by a shared cell the test flips, so the re-resolve
    /// seam is exercised deterministically with no real sleeps or filesystem.
    fn rotating_source(cell: std::sync::Arc<std::sync::Mutex<Option<String>>>) -> TokenSource {
        Box::new(move || cell.lock().unwrap().clone())
    }

    /// The startup read is the only resolution on the happy path; the source is not
    /// re-invoked while batches succeed.
    #[test]
    fn resolves_token_once_at_construction() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = calls.clone();
        let reporter = Reporter::with_source(
            reqwest::Client::new(),
            "http://engine.svc:9999",
            Box::new(move || {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Some("startup".to_string())
            }),
        );
        assert_eq!(reporter.token.as_deref(), Some("startup"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// Re-resolution fires exactly at the threshold and adopts the rotated token, so the
    /// next post would carry the fresh bearer — the self-heal, no restart.
    #[test]
    fn re_resolves_token_after_threshold_401s() {
        let cell = std::sync::Arc::new(std::sync::Mutex::new(Some("stale".to_string())));
        let mut reporter = Reporter::with_source(
            reqwest::Client::new(),
            "http://engine.svc:9999",
            rotating_source(cell.clone()),
        );
        assert_eq!(reporter.token.as_deref(), Some("stale"));

        // The secret rotates after startup — the kubelet rewrites the mounted file.
        *cell.lock().unwrap() = Some("fresh".to_string());

        // Below the threshold: still holding the stale token, source not consulted.
        for _ in 0..(RERESOLVE_AFTER_401S - 1) {
            reporter.on_unauthorized();
        }
        assert_eq!(reporter.token.as_deref(), Some("stale"));

        // At the threshold: re-resolved to the fresh value.
        reporter.on_unauthorized();
        assert_eq!(reporter.token.as_deref(), Some("fresh"));

        // The fresh bearer is what subsequent posts attach.
        let req = reporter
            .build_request(&sample_report())
            .build()
            .expect("request builds");
        assert_eq!(
            req.headers().get(reqwest::header::AUTHORIZATION).unwrap(),
            "Bearer fresh"
        );
    }

    /// A success resets the consecutive-401 run so a later skew is treated as a new run
    /// (and re-resolution can fire again).
    #[test]
    fn success_resets_the_401_run() {
        let cell = std::sync::Arc::new(std::sync::Mutex::new(Some("t".to_string())));
        let mut reporter = Reporter::with_source(
            reqwest::Client::new(),
            "http://engine.svc:9999",
            rotating_source(cell),
        );
        reporter.on_unauthorized();
        reporter.on_unauthorized();
        assert_eq!(reporter.consecutive_401s, 2);

        // The success path's bookkeeping (no network in a unit test).
        reporter.consecutive_401s = 0;
        reporter.delivered_total += 1;

        // A fresh run starts from zero.
        reporter.on_unauthorized();
        assert_eq!(reporter.consecutive_401s, 1);
    }

    /// Counters track delivered vs rejected for the heartbeat (JEF-240 surfacing).
    #[test]
    fn counters_tally_rejections() {
        let mut reporter = reporter_with(Some("t"));
        assert_eq!(reporter.counters(), (0, 0));
        // The send path bumps the rejected tally before dispatching to on_unauthorized;
        // exercise that tally directly here (no network in a unit test).
        reporter.rejected_total += 1;
        reporter.on_unauthorized();
        assert_eq!(reporter.counters(), (0, 1));
    }
}
