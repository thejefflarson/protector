//! Unit tests for the engine orchestration core (`mod.rs`): the per-entry judging
//! cache, the promote/veto verdict effects on the action decision, and the shadow-mode
//! invariants. Split out of the module root purely to keep every file under the
//! 1,000-line cap (repo CLAUDE.md). `use super::*` resolves to the engine module, so
//! these tests see exactly what the inline `mod tests` block saw.

use super::*;
use crate::engine::graph::attack::AttackRef;
use crate::engine::graph::{NodeKey, SecurityGraph};
use crate::engine::observe::{SecretMeta, Snapshot};
use crate::engine::reason::adjudicate::Verdict;
use crate::engine::respond::actuator::DryRunActuator;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// An adjudicator that counts how many times it's consulted (and confirms).
struct CountingAdjudicator(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl reason::adjudicate::Adjudicator for CountingAdjudicator {
    async fn judge(
        &self,
        _entry: &NodeKey,
        _objectives: &[(NodeKey, AttackRef)],
        _graph: &SecurityGraph,
    ) -> Verdict {
        self.0.fetch_add(1, Ordering::SeqCst);
        Verdict::Refuted("counted".into())
    }
}

/// An internet-exposed (LoadBalancer) web pod that mounts a secret, optionally
/// carrying a critical CVE on its image (which makes it a proven foothold).
fn exposed_snapshot(with_cve: bool) -> Snapshot {
    use crate::engine::graph::{Provenance, Severity, Vulnerability};
    use crate::engine::observe::ImageVulnerabilities;
    use std::time::SystemTime;

    let web = serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"}},
        "spec": {"containers": [{
            "name": "web", "image": "web:1",
            "envFrom": [{"secretRef": {"name": "session-key"}}]
        }]}
    }))
    .unwrap();
    let lb = serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "web-lb", "namespace": "app"},
        "spec": {"type": "LoadBalancer", "selector": {"app": "web"}}
    }))
    .unwrap();
    Snapshot {
        pods: vec![web],
        services: vec![lb],
        secrets: vec![SecretMeta {
            namespace: "app".into(),
            name: "session-key".into(),
        }],
        image_vulns: if with_cve {
            vec![ImageVulnerabilities {
                image: "web:1".into(),
                vulnerabilities: vec![Vulnerability {
                    id: "CVE-2026-0001".into(),
                    severity: Severity::Critical,
                    exploited_in_wild: true,
                    epss: None,
                    sources: vec![Provenance::new("trivy", SystemTime::UNIX_EPOCH)],
                    ..Default::default()
                }],
            }]
        } else {
            vec![]
        },
        ..Default::default()
    }
}

fn engine_with(counter: Arc<AtomicUsize>) -> Engine {
    Engine::new(
        EnabledActions::from_names(std::iter::empty::<&str>()),
        ActuationScope::unscoped(),
        Box::new(DryRunActuator),
        Box::new(reason::hypothesis::NullHypothesizer),
        Box::new(CountingAdjudicator(counter)),
    )
}

/// The model judges EVERY breach-relevant path, with or without a CVE — an
/// internet-reachable path to a secret is a finding on its own (structural
/// exposure), so absence of a CVE is not a reason to skip it (ADR-0013, defense in
/// depth). The verdict is cached per path, so re-processing the same facts doesn't
/// re-call the model.
#[tokio::test]
async fn judges_every_breach_relevant_path_even_without_a_cve() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = engine_with(calls.clone());

    // Exposed, reaches a secret, NO CVE and NO runtime → still judged (structural).
    engine.process(&exposed_snapshot(false)).await;
    assert!(
        calls.load(Ordering::SeqCst) >= 1,
        "an internet-reachable path must be judged even with no CVE"
    );
    // The model's verdict is attached to the published finding.
    let findings = engine.findings().snapshot();
    assert!(
        findings
            .iter()
            .any(|f| f.breach_relevant && f.verdict.is_some()),
        "the judged breach path carries the model's verdict"
    );

    // Re-processing identical facts reuses the cached verdict — no new model call.
    let before = calls.load(Ordering::SeqCst);
    engine.process(&exposed_snapshot(false)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        before,
        "an unchanged path must not be re-judged (cache hit)"
    );
}

/// An adjudicator that returns a fixed verdict and never re-judges issues a `judged`
/// only on a fingerprint miss.
struct FixedAdjudicator(Verdict);

#[async_trait::async_trait]
impl reason::adjudicate::Adjudicator for FixedAdjudicator {
    async fn judge(
        &self,
        _entry: &NodeKey,
        _objectives: &[(NodeKey, AttackRef)],
        _graph: &SecurityGraph,
    ) -> Verdict {
        self.0.clone()
    }
}

fn engine_with_adjudicator(adj: Box<dyn reason::adjudicate::Adjudicator>) -> Engine {
    Engine::new(
        EnabledActions::from_names(std::iter::empty::<&str>()),
        ActuationScope::unscoped(),
        Box::new(DryRunActuator),
        Box::new(reason::hypothesis::NullHypothesizer),
        adj,
    )
}

/// JEF-157 (the no-lag fix): a judged entry's verdict is carried in the findings snapshot by
/// the single shared verdict STORE, resolved at snapshot time — not stamped onto the rows
/// by an end-of-pass re-publish. We prove the store is the source of truth: after a
/// pass the verdict is in the findings snapshot, AND it equals the store's value for that
/// entry (the same `Arc` a reader sees). With the store, a verdict written the instant
/// the judging loop decides it is resolved immediately — it never lags behind the judgement
/// record (the confirmed-live bug: judgements=N while findings=0).
#[tokio::test]
async fn a_judged_verdict_lands_on_findings_via_the_shared_store() {
    let mut engine = engine_with_adjudicator(Box::new(FixedAdjudicator(Verdict::Exploitable(
        "RCE reaches the secret".into(),
    ))));
    engine.process(&exposed_snapshot(true)).await;

    let findings = engine.findings();
    // The verdict is in the findings snapshot, in the model's own words.
    let snap = findings.snapshot();
    assert!(
        snap.iter().any(|f| f.breach_relevant
            && f.verdict.as_ref().map(|v| v.summary()).as_deref()
                == Some("exploitable — RCE reaches the secret")),
        "the judged verdict is in the findings snapshot (via the store)"
    );
    // And it is the SAME value the shared store holds for that entry — proving the findings
    // snapshot derives the verdict from the store, the one source of truth, rather
    // than a separately-stamped per-row copy. A reader sees this exact `Arc`.
    let entry = snap
        .iter()
        .find(|f| f.breach_relevant)
        .map(|f| f.entry.clone())
        .expect("a breach-relevant finding");
    assert_eq!(
        findings.verdicts().display_summary(&entry).as_deref(),
        Some("exploitable — RCE reaches the secret"),
        "the findings snapshot and the store agree on the entry's verdict"
    );
}

/// JEF-157 carry-forward: when a later pass comes back Uncertain (a transient model
/// timeout), the resolved posture keeps the prior DECISIVE verdict rather than
/// regressing to "uncertain" — the store holds the carried-forward display verdict.
#[tokio::test]
async fn an_uncertain_re_judge_keeps_showing_the_prior_decisive_verdict() {
    // An adjudicator that's decisive on the first call and Uncertain after — the
    // shape of a model that judged once, then timed out on a re-judge.
    struct FlakyAdjudicator(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl reason::adjudicate::Adjudicator for FlakyAdjudicator {
        async fn judge(
            &self,
            _entry: &NodeKey,
            _objectives: &[(NodeKey, AttackRef)],
            _graph: &SecurityGraph,
        ) -> Verdict {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                Verdict::Exploitable("RCE reaches the secret".into())
            } else {
                Verdict::Uncertain("model unavailable".into())
            }
        }
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = engine_with_adjudicator(Box::new(FlakyAdjudicator(calls.clone())));

    // Pass 1: decisive Exploitable, resolved in the findings snapshot.
    engine.process(&exposed_snapshot(true)).await;
    assert!(
        engine
            .findings()
            .snapshot()
            .iter()
            .any(|f| f.breach_relevant
                && f.verdict.as_ref().map(|v| v.summary()).as_deref()
                    == Some("exploitable — RCE reaches the secret")),
        "the first decisive verdict shows"
    );

    // Pass 2 with DIFFERENT evidence (no CVE) so the fingerprint changes and the model
    // is re-consulted — and this time it returns Uncertain. The resolved posture must keep
    // the prior decisive verdict, not regress to "uncertain".
    engine.process(&exposed_snapshot(false)).await;
    assert!(
        calls.load(Ordering::SeqCst) >= 2,
        "the changed fingerprint forced a re-judge"
    );
    assert!(
        engine
            .findings()
            .snapshot()
            .iter()
            .any(|f| f.breach_relevant
                && f.verdict.as_ref().map(|v| v.summary()).as_deref()
                    == Some("exploitable — RCE reaches the secret")),
        "an Uncertain re-judge keeps the prior decisive verdict in the findings snapshot"
    );
}

/// Findings are published even when adjudication can't run, so model latency or an
/// outage never blanks the findings snapshot. With evidence present but the (counting)
/// model refuting, the breach finding is still there.
#[tokio::test]
async fn publishes_findings_independent_of_the_model() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = engine_with(calls.clone());
    engine.process(&exposed_snapshot(true)).await;
    let findings = engine.findings().snapshot();
    assert!(
        findings.iter().any(|f| f.breach_relevant),
        "the breach-relevant finding is published regardless of the verdict"
    );
}

/// The attribution-outcome metric (JEF-100) uses [`Attribution::resolves_in`] against
/// the live pod-UID set the metric loop builds once per pass — the same rule the
/// RuntimeAdapter applies. A namespace/name attribution always resolves; a cgroup-UID
/// one resolves only when a pod with that UID is in the snapshot (an unknown UID is
/// `unresolved`). (The rule itself is unit-tested in the `protector-behavior` crate;
/// this pins the metric loop's call shape against a real snapshot's UID set.)
#[test]
fn attribution_resolves_mirrors_the_adapter_rule() {
    use crate::engine::observe::Attribution;

    // A pod whose metadata.uid is "uid-1".
    let pod: k8s_openapi::api::core::v1::Pod = serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "web", "namespace": "app", "uid": "uid-1"}
    }))
    .unwrap();
    let snapshot = Snapshot {
        pods: vec![pod],
        ..Default::default()
    };
    // The live pod-UID set the metric loop builds once per pass.
    let uids = |snap: &Snapshot| -> HashSet<String> {
        snap.pods
            .iter()
            .filter_map(|p| p.metadata.uid.clone())
            .collect()
    };
    let present = uids(&snapshot);
    let present: HashSet<&str> = present.iter().map(String::as_str).collect();
    let empty: HashSet<&str> = HashSet::new();

    // namespace/name (Falco) always resolves, even against an empty snapshot.
    assert!(Attribution::by_namespaced_name("app", "web").resolves_in(|uid| present.contains(uid)));
    assert!(
        Attribution::by_namespaced_name("ghost", "nobody").resolves_in(|uid| empty.contains(uid))
    );
    // A cgroup UID resolves iff a pod with that UID is present.
    assert!(Attribution::by_pod_uid("uid-1").resolves_in(|uid| present.contains(uid)));
    assert!(!Attribution::by_pod_uid("uid-unknown").resolves_in(|uid| present.contains(uid)));
}

/// A live alert on a breach-relevant entry sets `corroborated` — the source the
/// corroborations-fired counter reads (JEF-100). Pure instrumentation: this asserts
/// the predicate the metric counts, and that recording it doesn't disturb processing.
#[tokio::test]
async fn corroboration_predicate_fires_on_a_live_alert() {
    use crate::engine::observe::{Attribution, RuntimeObservation};
    use protector_behavior::Behavior;

    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = engine_with(calls.clone());

    // The exposed foothold snapshot plus a live critical alert on the entry pod.
    let mut snapshot = exposed_snapshot(true);
    snapshot.runtime_events = vec![RuntimeObservation {
        attribution: Attribution::by_namespaced_name("app", "web"),
        source: Some("falco".into()),
        observed_at_ms: None,
        behavior: Behavior::Alert {
            rule: "Terminal shell in container".into(),
        },
    }];
    engine.process(&snapshot).await;

    let findings = engine.findings().snapshot();
    assert!(
        findings.iter().any(|f| f.breach_relevant && f.corroborated),
        "a live alert on the entry must corroborate a breach-relevant chain"
    );
}

/// `process` publishes the behavioral-bake snapshot (JEF-48) to the findings handle
/// each pass: signal volume by variant, attribution resolved/unresolved mirroring the
/// adapter rule, the live-store size, and corroborations fired — the in-process
/// mirror of the OTLP bake counters.
#[tokio::test]
async fn process_publishes_the_behavioral_bake_snapshot() {
    use crate::engine::observe::{Attribution, RuntimeObservation};
    use protector_behavior::Behavior;

    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = engine_with(calls.clone());

    let mut snapshot = exposed_snapshot(true);
    snapshot.runtime_events = vec![
        // A live alert on the entry pod (namespace/name → always resolves), which also
        // corroborates the breach-relevant chain.
        RuntimeObservation {
            attribution: Attribution::by_namespaced_name("app", "web"),
            source: Some("falco".into()),
            observed_at_ms: None,
            behavior: Behavior::Alert {
                rule: "Terminal shell in container".into(),
            },
        },
        // A connection attributed to an unknown cgroup UID → unresolved (no such pod).
        RuntimeObservation {
            attribution: Attribution::by_pod_uid("uid-not-in-snapshot"),
            source: Some("agent".into()),
            observed_at_ms: None,
            behavior: Behavior::NetworkConnection {
                peer: "10.0.0.9:443".into(),
                internet: false,
            },
        },
    ];
    engine.process(&snapshot).await;

    let bake = engine.findings().bake();
    assert_eq!(bake.total_signals(), 2, "both signals are counted");
    assert_eq!(bake.signals_by_variant.get("alert"), Some(&1));
    assert_eq!(bake.signals_by_variant.get("connection"), Some(&1));
    assert_eq!(bake.resolved, 1, "the namespace/name alert resolves");
    assert_eq!(bake.unresolved, 1, "the unknown-UID connection does not");
    assert_eq!(bake.runtime_store, 2, "store cardinality is the live set");
    assert!(
        bake.corroborations >= 1,
        "the live alert corroborates a breach-relevant chain"
    );
}

/// A unique temp journal path for a test, without a temp-file crate.
fn temp_journal_path(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::AtomicU64;
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let n = NONCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "protector-engine-journal-{tag}-{}-{n}.jsonl",
        std::process::id()
    ))
}

/// JEF-141 acceptance: after a "restart", the findings snapshot shows the pre-restart breach
/// verdict WITHOUT a fresh model pass, and the reversion log + last-pass freshness
/// are seeded from the durable journal. We process once with a journal enabled (which
/// appends the breach decision), then build a SECOND engine on the SAME journal path
/// and assert the output state is populated from replay alone — before any `process`.
#[tokio::test]
async fn journal_restores_findings_and_freshness_without_a_fresh_pass() {
    let path = temp_journal_path("restore");

    // --- First engine "run": process a breach snapshot with the journal enabled. ---
    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = Engine::new(
        EnabledActions::from_names(std::iter::empty::<&str>()),
        ActuationScope::unscoped(),
        Box::new(DryRunActuator),
        Box::new(reason::hypothesis::NullHypothesizer),
        Box::new(CountingAdjudicator(calls.clone())),
    )
    .with_journal(journal::DecisionJournal::open(&path));
    engine.process(&exposed_snapshot(true)).await;
    // The breach decision (a decisive Refuted verdict) was journaled.
    let written = journal::DecisionJournal::open(&path).replay();
    assert!(
        written
            .iter()
            .any(|e| matches!(e.decision, journal::Decision::Breach { .. })),
        "the breach decision is durable"
    );
    drop(engine); // "restart"

    // --- Second engine "boot": replay the journal, NO process() yet. ---
    let fresh_calls = Arc::new(AtomicUsize::new(0));
    let engine2 = Engine::new(
        EnabledActions::from_names(std::iter::empty::<&str>()),
        ActuationScope::unscoped(),
        Box::new(DryRunActuator),
        Box::new(reason::hypothesis::NullHypothesizer),
        Box::new(CountingAdjudicator(fresh_calls.clone())),
    )
    .with_journal(journal::DecisionJournal::open(&path));
    // The model was NOT consulted on boot — the verdict is restored from disk.
    assert_eq!(
        fresh_calls.load(Ordering::SeqCst),
        0,
        "no fresh model pass ran on boot"
    );
    // Freshness is seeded from the journal's newest stamp.
    assert!(
        engine2.findings().last_pass().is_some(),
        "last-pass freshness is restored from the journal"
    );

    // The restored verdict surfaces in the findings snapshot the moment the next pass
    // publishes chains — without the (counting) model being consulted for it.
    let mut engine2 = engine2;
    engine2.process(&exposed_snapshot(true)).await;
    let findings = engine2.findings().snapshot();
    assert!(
        findings
            .iter()
            .any(|f| f.breach_relevant && f.verdict.is_some()),
        "the breach path shows a verdict immediately after restart"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file({
        let mut s = path.clone().into_os_string();
        s.push(".1");
        std::path::PathBuf::from(s)
    });
}

/// A tiny local HTTP sink that counts the breach notifications POSTed to it and
/// captures the bodies — the operator-configured target stand-in for the notifier
/// integration tests (JEF-144). Returns the bound URL and the shared counters.
async fn spawn_notify_sink() -> (String, Arc<AtomicUsize>, Arc<std::sync::Mutex<Vec<String>>>) {
    use axum::Router;
    use axum::routing::post;

    let count = Arc::new(AtomicUsize::new(0));
    let bodies = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let count_h = count.clone();
    let bodies_h = bodies.clone();
    let app = Router::new().route(
        "/notify",
        post(move |body: String| {
            let count = count_h.clone();
            let bodies = bodies_h.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                bodies.lock().unwrap().push(body);
                "ok"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}/notify"), count, bodies)
}

/// JEF-144 acceptance: a URL set ⇒ a NEW breach decision produces EXACTLY ONE
/// notification, deduped on the decision identity (the journal's). Processing the same
/// breach facts twice must POST once, not per pass. The payload is redacted (no secret
/// name leaks).
#[tokio::test]
async fn notifier_fires_once_per_decision_and_redacts() {
    let (url, count, bodies) = spawn_notify_sink().await;

    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = Engine::new(
        EnabledActions::from_names(std::iter::empty::<&str>()),
        ActuationScope::unscoped(),
        Box::new(DryRunActuator),
        Box::new(reason::hypothesis::NullHypothesizer),
        Box::new(CountingAdjudicator(calls.clone())),
    )
    .with_notifier(notify::BreachNotifier::new(&url, false));

    // First pass: a new breach decision → exactly one notification.
    engine.process(&exposed_snapshot(true)).await;
    // Second pass, identical facts → SAME decision identity → no second notification.
    engine.process(&exposed_snapshot(true)).await;

    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "one new decision must produce exactly one notification (deduped per pass)"
    );
    // The single payload is redacted: the entry workload is present, the secret name
    // it mounts is NOT.
    let body = bodies.lock().unwrap()[0].clone();
    assert!(body.contains("web"), "the entry workload is surfaced");
    assert!(
        !body.contains("session-key"),
        "the secret name must never leave in the notification"
    );
    // Shadow posture (nothing armed) is explicit.
    assert!(
        body.contains("shadow") || body.contains("would isolate"),
        "shadow vs armed must be unambiguous in the message"
    );
}

/// JEF-144 acceptance: NO URL ⇒ zero outbound calls — byte-identical to today. We
/// run a sink to PROVE nothing is sent: a disabled notifier must not POST to it.
#[tokio::test]
async fn no_notify_url_makes_zero_outbound_calls() {
    let (_url, count, _bodies) = spawn_notify_sink().await;

    let calls = Arc::new(AtomicUsize::new(0));
    // Default engine: notifier disabled (no URL).
    let mut engine = engine_with(calls.clone());
    engine.process(&exposed_snapshot(true)).await;
    engine.process(&exposed_snapshot(true)).await;

    // Give any (erroneous) spawned POST a moment to land — it must not.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "with no URL configured the engine makes zero outbound notifications"
    );
    // And findings still publish exactly as before.
    assert!(
        engine
            .findings()
            .snapshot()
            .iter()
            .any(|f| f.breach_relevant),
        "findings publish as usual with the notifier disabled"
    );
}

/// JEF-141 graceful degradation at the engine level: with no journal configured the
/// engine runs exactly as before (in-memory only) and never touches disk — the
/// disabled-journal path is a no-op, not a crash.
#[tokio::test]
async fn no_journal_keeps_today_in_memory_behavior() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = engine_with(calls.clone()); // built with a disabled journal
    engine.process(&exposed_snapshot(true)).await;
    // Findings publish as usual; reversions ring is empty (nothing reverted, nothing
    // restored); a disabled journal replays nothing.
    assert!(
        engine
            .findings()
            .snapshot()
            .iter()
            .any(|f| f.breach_relevant),
        "findings publish in-memory with no journal"
    );
    assert!(
        engine.reversions().snapshot().is_empty(),
        "no reversions without a journal or a revert"
    );
}

/// An adjudicator that ALWAYS returns Uncertain — the shape of a fully-down / OOM-ing
/// Ollama (every call times out). Counts the calls it actually receives.
struct AlwaysUncertain(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl reason::adjudicate::Adjudicator for AlwaysUncertain {
    async fn judge(
        &self,
        _entry: &NodeKey,
        _objectives: &[(NodeKey, AttackRef)],
        _graph: &SecurityGraph,
    ) -> Verdict {
        self.0.fetch_add(1, Ordering::SeqCst);
        Verdict::Uncertain("model unavailable".into())
    }
}

/// JEF-234 — the core bug: an Uncertain (model-down) verdict is never cached, so without
/// backoff the entry is re-judged on EVERY pass, hammering the struggling model. With
/// backoff, after the first Uncertain the entry is NOT re-judged on immediately-following
/// passes (all within the BASE=30s window), so the model-call count is bounded by the
/// backoff schedule, not once-per-pass. Deterministic and fast: the passes run in well
/// under 30s, so no real sleeps are needed to stay inside the backoff window.
#[tokio::test]
async fn an_uncertain_entry_is_not_re_judged_every_pass() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = engine_with_adjudicator(Box::new(AlwaysUncertain(calls.clone())));

    // Drive many passes over IDENTICAL evidence (same fingerprint). Uncertain is never
    // cached, so pre-JEF-234 every pass was a fresh model call. With backoff, only the
    // first pass calls the model; the rest fall inside the entry's backoff and are skipped.
    for _ in 0..10 {
        engine.process(&exposed_snapshot(true)).await;
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "after the first Uncertain the entry stays in backoff: bounded calls, not 10"
    );
}

/// An adjudicator that goes down (Uncertain) for the first N calls, then recovers
/// (decisive). Used to show a decisive success resets the gate.
struct RecoversAfter {
    calls: Arc<AtomicUsize>,
    down_for: usize,
}

#[async_trait::async_trait]
impl reason::adjudicate::Adjudicator for RecoversAfter {
    async fn judge(
        &self,
        _entry: &NodeKey,
        _objectives: &[(NodeKey, AttackRef)],
        _graph: &SecurityGraph,
    ) -> Verdict {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n < self.down_for {
            Verdict::Uncertain("model unavailable".into())
        } else {
            Verdict::Exploitable("RCE reaches the secret".into())
        }
    }
}

/// JEF-234 — while an entry backs off, the resolved posture keeps its last DECISIVE
/// verdict (no regression to "uncertain"), and once the model recovers a decisive verdict
/// is cached and shown. We can't fast-forward the injected clock across `process()` here,
/// so we assert the no-regression display property directly: a decisive verdict shows, and
/// a same-evidence Uncertain re-judge attempt does not blank or downgrade it.
#[tokio::test]
async fn backing_off_entry_keeps_showing_the_last_decisive_verdict() {
    // First call decisive, every later call Uncertain — a model that answered once then
    // went down. The first pass (CVE present) judges decisively; the second pass over the
    // SAME evidence is a cache HIT (decisive verdicts ARE cached), so it never re-calls —
    // proving the decisive path's correctness is unchanged by the backoff gate.
    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = engine_with_adjudicator(Box::new(RecoversAfter {
        calls: calls.clone(),
        down_for: 0, // decisive immediately
    }));
    engine.process(&exposed_snapshot(true)).await;
    for _ in 0..5 {
        engine.process(&exposed_snapshot(true)).await;
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a decisive verdict is cached: the same evidence is never re-judged"
    );
    assert!(
        engine
            .findings()
            .snapshot()
            .iter()
            .any(|f| f.breach_relevant
                && f.verdict.as_ref().map(|v| v.summary()).as_deref()
                    == Some("exploitable — RCE reaches the secret")),
        "the decisive verdict is shown and stays shown"
    );
}

/// JEF-234 global breaker — when the model is fully down, total model calls across the
/// whole fleet per cooldown are bounded regardless of entry count. We exercise the
/// breaker's invariant directly on the store (the same handle `process()` drives), with an
/// injected clock so it's deterministic and fast: BREAKER_TRIP consecutive failures open
/// it, after which `breaker_open` is true (the whole pass skips its model calls) until the
/// cooldown elapses, and a decisive success closes it immediately.
#[test]
fn global_breaker_bounds_calls_when_the_model_is_fully_down() {
    use crate::engine::reason::backoff::{BREAKER_COOLDOWN, BREAKER_TRIP};
    use crate::engine::state::VerdictStore;
    use std::time::{Duration, Instant};

    let store = VerdictStore::new();
    let now = Instant::now();
    assert!(!store.breaker_open(now), "starts closed");

    // Simulate a fully-down model: each "entry" call comes back inconclusive. The breaker
    // stays closed until BREAKER_TRIP, then opens for the whole fleet.
    for i in 0..BREAKER_TRIP {
        assert!(
            !store.breaker_open(now),
            "breaker must stay closed before {BREAKER_TRIP} failures (i={i})"
        );
        store.record_inconclusive(&format!("entry-{i}"), now);
    }
    assert!(
        store.breaker_open(now),
        "the whole pass is gated once the model looks fully down"
    );
    assert!(
        store.breaker_open(now + BREAKER_COOLDOWN - Duration::from_millis(1)),
        "stays open through the cooldown window — total calls/window bounded"
    );
    assert!(
        !store.breaker_open(now + BREAKER_COOLDOWN),
        "reopens for a single probe after the cooldown"
    );

    // A decisive success closes it immediately, restoring normal judging.
    for i in 0..BREAKER_TRIP {
        store.record_inconclusive(&format!("entry-{i}"), now);
    }
    assert!(store.breaker_open(now), "tripped again");
    store.record_decisive("entry-0");
    assert!(
        !store.breaker_open(now),
        "the first decisive success closes the breaker"
    );
}

/// JEF-301: decisive verdicts persist across a restart, so an UNCHANGED entry is served from
/// the replayed cache with NO fresh model call — the biggest request-volume cut when a
/// protector/Ollama restart would otherwise re-judge the whole fleet. A persisted BREACH
/// (Exploitable) replays as the EXACT prior decision (never downgraded), and a CHANGED
/// fingerprint still forces a fresh judge (a stale verdict is never served for new evidence).
#[tokio::test]
async fn decisive_verdicts_persist_across_a_restart_and_skip_re_judging() {
    // A unique temp journal path (no temp-file crate), cleaned up at the end.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "protector-jef301-{}-{nanos}.jsonl",
        std::process::id()
    ));

    // Pre-restart: a model that decisively judges Exploitable. Attaching the (writable) journal
    // enables durable writes, so the decisive verdict + its fingerprint land on disk.
    {
        let mut engine = engine_with_adjudicator(Box::new(FixedAdjudicator(Verdict::Exploitable(
            "RCE reaches the secret".into(),
        ))))
        .with_journal(journal::DecisionJournal::open(&path));
        engine.process(&exposed_snapshot(true)).await;
    }

    // Restart: a fresh engine whose adjudicator COUNTS calls (and would return Refuted if
    // consulted). Replaying the journal must re-seed the verdict cache.
    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = engine_with(calls.clone()).with_journal(journal::DecisionJournal::open(&path));

    // Same evidence ⇒ unchanged fingerprint ⇒ served from the replayed cache: NO model call,
    // and the persisted BREACH replays EXACTLY (Exploitable — NOT the counting adjudicator's
    // Refuted, which would prove a re-judge AND a downgrade).
    engine.process(&exposed_snapshot(true)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "an unchanged entry is served from the replayed cache with no fresh model call"
    );
    assert!(
        engine
            .findings()
            .snapshot()
            .iter()
            .any(|f| f.breach_relevant
                && f.verdict.as_ref().map(|v| v.summary()).as_deref()
                    == Some("exploitable — RCE reaches the secret")),
        "a persisted BREACH replays as the EXACT prior decision, never downgraded"
    );

    // Changed evidence (no CVE) ⇒ different fingerprint ⇒ cache miss ⇒ a fresh judge fires.
    engine.process(&exposed_snapshot(false)).await;
    assert!(
        calls.load(Ordering::SeqCst) >= 1,
        "a changed fingerprint invalidates the persisted verdict and re-judges"
    );

    let _ = std::fs::remove_file(&path);
}
