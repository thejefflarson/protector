//! Journal / notifier / persistence tests for the engine orchestration core, split out of
//! `tests.rs` purely to keep every file under the 1,000-line cap (repo CLAUDE.md). These cover
//! JEF-141 (journal restore of findings + freshness), JEF-144 (breach notifier fires once per
//! decision, redacts, zero-egress when unset), JEF-234 (backoff / global breaker), and JEF-301
//! (decisive verdicts persist across a restart). `use super::*` resolves to the engine module,
//! and the shared fixtures (`exposed_snapshot`, `engine_with*`, the counting/fixed adjudicators)
//! come from `super::tests`, matching the sibling `*_tests.rs` pattern.

use super::*;
use crate::engine::graph::attack::AttackRef;
use crate::engine::graph::{NodeKey, SecurityGraph};
use crate::engine::reason::adjudicate::Verdict;
use crate::engine::respond::actuator::DryRunActuator;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::tests::{
    CountingAdjudicator, FixedAdjudicator, engine_with, engine_with_adjudicator, exposed_snapshot,
};

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
        _prompt: &str,
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
        _prompt: &str,
    ) -> Verdict {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n < self.down_for {
            Verdict::Uncertain("model unavailable".into())
        } else {
            Verdict::Exploitable("RCE reaches the secret".into())
        }
    }
}

/// JEF-445 — the model's own positive (`Exploitable`) is RE-VERIFIED every pass; it is never
/// served from the verdict cache, so a one-time temp-0 tail-flip can't freeze into a permanent
/// false breach. With a model that keeps affirming the breach, every pass re-judges (one model
/// call per pass, NOT one total) and the exploitable verdict stays shown — proving the re-verify
/// is continuous, not a cache hit. (A NEGATIVE decisive verdict still caches — see the JEF-301
/// replay tests — this re-verify is scoped to the fabricable positive.)
#[tokio::test]
async fn exploitable_is_reverified_every_pass_not_cached() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = engine_with_adjudicator(Box::new(RecoversAfter {
        calls: calls.clone(),
        down_for: 0, // always decisive Exploitable
    }));
    for _ in 0..6 {
        engine.process(&exposed_snapshot(true)).await;
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        6,
        "an Exploitable is re-verified every pass (JEF-445), never served from the cache"
    );
    assert!(
        engine
            .findings()
            .snapshot()
            .iter()
            .any(|f| f.breach_relevant
                && f.verdict.as_ref().map(|v| v.summary()).as_deref()
                    == Some("exploitable — RCE reaches the secret")),
        "the re-affirmed exploitable verdict stays shown"
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

/// JEF-301 + JEF-445: decisive verdicts persist across a restart and re-seed the verdict cache on
/// boot with NO fresh model call (JEF-141) — the request-volume cut. BUT a persisted POSITIVE
/// (`Exploitable`) is RE-VERIFIED on the first pass rather than replayed blind (JEF-445): if the
/// model now REFUTES it (the temp-0 tail-flip is gone), the display SELF-HEALS to refuted instead
/// of freezing the stale breach. This is the fix for the frozen-false-exploitable — a persisted
/// NEGATIVE would still serve from the cache (see `journal_restores_findings_and_freshness…`).
#[tokio::test]
async fn a_persisted_exploitable_is_reverified_on_restart_and_self_heals() {
    let path = temp_journal_path("jef445-reverify");

    // Pre-restart: a model that decisively judges Exploitable. Attaching the (writable) journal
    // enables durable writes, so the decisive verdict + its fingerprint land on disk.
    {
        let mut engine = engine_with_adjudicator(Box::new(FixedAdjudicator(Verdict::Exploitable(
            "RCE reaches the secret".into(),
        ))))
        .with_journal(journal::DecisionJournal::open(&path));
        engine.process(&exposed_snapshot(true)).await;
    }

    // Restart: a fresh engine whose (counting) adjudicator now returns Refuted — the flip is gone.
    // Replaying the journal re-seeds the verdict cache with the persisted Exploitable.
    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = engine_with(calls.clone()).with_journal(journal::DecisionJournal::open(&path));

    // First pass over the SAME evidence: the replayed POSITIVE is RE-VERIFIED (JEF-445), so the
    // model IS consulted (one fresh call — unlike a cached negative), and its fresh Refuted
    // supersedes the stale breach on the display. The frozen false-exploitable self-heals.
    engine.process(&exposed_snapshot(true)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a persisted Exploitable is re-verified on restart (one fresh call), not served blind"
    );
    let snapshot = engine.findings().snapshot();
    assert!(
        snapshot.iter().any(|f| f.breach_relevant
            && f.verdict.as_ref().map(|v| v.summary()).as_deref()
                == Some("not exploitable — counted")),
        "the re-verified verdict (now Refuted) supersedes the stale Exploitable — the self-heal"
    );
    assert!(
        !snapshot
            .iter()
            .any(|f| f.verdict.as_ref().map(|v| v.summary()).as_deref()
                == Some("exploitable — RCE reaches the secret")),
        "the frozen false breach is gone from the display"
    );

    let _ = std::fs::remove_file(&path);
}
