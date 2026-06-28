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

/// JEF-157 (the no-lag fix): a judged entry's verdict is carried on `/findings` by the
/// single shared verdict STORE, resolved at snapshot time — not stamped onto the rows
/// by an end-of-pass re-publish. We prove the store is the source of truth: after a
/// pass the verdict is on `/findings`, AND it equals the store's value for that entry
/// (the same `Arc` the dashboard reads). With the store, a verdict written the instant
/// the judging loop decides it is visible immediately — it never lags behind
/// `/judgements` (the confirmed-live bug: `/judgements`=N while `/findings`=0).
#[tokio::test]
async fn a_judged_verdict_lands_on_findings_via_the_shared_store() {
    let mut engine = engine_with_adjudicator(Box::new(FixedAdjudicator(Verdict::Exploitable(
        "RCE reaches the secret".into(),
    ))));
    engine.process(&exposed_snapshot(true)).await;

    let findings = engine.findings();
    // The verdict is on /findings, in the model's own words.
    let snap = findings.snapshot();
    assert!(
        snap.iter().any(|f| f.breach_relevant
            && f.verdict.as_deref() == Some("exploitable — RCE reaches the secret")),
        "the judged verdict is on /findings (via the store)"
    );
    // And it is the SAME value the shared store holds for that entry — proving
    // /findings derives the verdict from the store, the one source of truth, rather
    // than a separately-stamped per-row copy. The dashboard reads this exact `Arc`.
    let entry = snap
        .iter()
        .find(|f| f.breach_relevant)
        .map(|f| f.entry.clone())
        .expect("a breach-relevant finding");
    assert_eq!(
        findings.verdicts().display_summary(&entry).as_deref(),
        Some("exploitable — RCE reaches the secret"),
        "/findings and the store agree on the entry's verdict"
    );
}

/// JEF-157 carry-forward: when a later pass comes back Uncertain (a transient model
/// timeout), the dashboard keeps showing the prior DECISIVE verdict rather than
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

    // Pass 1: decisive Exploitable, shown on /findings.
    engine.process(&exposed_snapshot(true)).await;
    assert!(
        engine
            .findings()
            .snapshot()
            .iter()
            .any(|f| f.breach_relevant
                && f.verdict.as_deref() == Some("exploitable — RCE reaches the secret")),
        "the first decisive verdict shows"
    );

    // Pass 2 with DIFFERENT evidence (no CVE) so the fingerprint changes and the model
    // is re-consulted — and this time it returns Uncertain. The dashboard must keep
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
                && f.verdict.as_deref() == Some("exploitable — RCE reaches the secret")),
        "an Uncertain re-judge keeps the prior decisive verdict on /findings"
    );
}

/// Findings are published even when adjudication can't run, so model latency or an
/// outage never blanks the dashboard. With evidence present but the (counting)
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
/// adapter rule, the live-store size, and corroborations fired — the dashboard's
/// in-process mirror of the OTLP bake counters.
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

/// JEF-141 acceptance: after a "restart", `/findings` shows the pre-restart breach
/// verdict WITHOUT a fresh model pass, and the reversions ring + last-pass freshness
/// are seeded from the durable journal. We process once with a journal enabled (which
/// appends the breach decision), then build a SECOND engine on the SAME journal path
/// and assert the dashboard is populated from replay alone — before any `process`.
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

    // The restored verdict surfaces on /findings the moment the next pass publishes
    // chains — without the (counting) model being consulted for it.
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
