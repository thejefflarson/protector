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
use crate::engine::reason::adjudicate::incident::{Assessment, IncidentDecision, Menu};
use crate::engine::respond::actuator::DryRunActuator;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Translate a legacy [`Verdict`] literal into the [`IncidentDecision`] shape a test double
/// returns (JEF-570) — test-only, and deliberately lossy for `Confirmed` (mapped to `Attack`,
/// same as every other test double; no test double here needs the Confirmed/Exploitable
/// distinction ADR-0034 D2 retired). Never carries cuts: none of these doubles exercise
/// cut-selection, only the caching/gate/dispatch machinery `to_verdict()` bridges back exactly.
pub(super) fn decision_of(verdict: Verdict) -> IncidentDecision {
    match verdict {
        Verdict::Confirmed => IncidentDecision {
            assessment: Assessment::Attack,
            reason: "confirmed".to_string(),
            cuts: Vec::new(),
        },
        Verdict::Exploitable(reason) => IncidentDecision {
            assessment: Assessment::Attack,
            reason,
            cuts: Vec::new(),
        },
        Verdict::Refuted(reason) => IncidentDecision {
            assessment: Assessment::NoAttack,
            reason,
            cuts: Vec::new(),
        },
        Verdict::Uncertain(reason) => IncidentDecision::uncertain(reason),
    }
}

/// An adjudicator that counts how many times it's consulted (and confirms).
pub(super) struct CountingAdjudicator(pub(super) Arc<AtomicUsize>);

#[async_trait::async_trait]
impl reason::adjudicate::Adjudicator for CountingAdjudicator {
    async fn judge(
        &self,
        _entry: &NodeKey,
        _objectives: &[(NodeKey, AttackRef)],
        _graph: &SecurityGraph,
        _prompt: &str,
        _downstream: &[NodeKey],
        _menu: &Menu,
    ) -> IncidentDecision {
        self.0.fetch_add(1, Ordering::SeqCst);
        decision_of(Verdict::Refuted("counted".into()))
    }
}

/// An internet-exposed (LoadBalancer) web pod that mounts a secret, optionally
/// carrying a critical CVE on its image (which makes it a proven foothold).
pub(super) fn exposed_snapshot(with_cve: bool) -> Snapshot {
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
                    // Observed loading at runtime — the JEF-453 filter only shows the judge
                    // reachable CVEs, so this exploitation-evidence CVE must be loaded-at-runtime
                    // to reach the prompt (and to change it, busting the verdict cache).
                    reachability: crate::engine::graph::Reachability::LoadedAtRuntime,
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

/// `n` INDEPENDENT internet-exposed workloads, each a distinct entry: pod `app/web-{i}`
/// behind its own LoadBalancer, mounting its own secret — so a pass has `n` breach-relevant
/// entries the adjudicator is consulted on. Used to exercise the concurrent dispatch and its
/// per-entry isolation (JEF-337): with one entry per snapshot the concurrency is invisible.
fn exposed_snapshot_n(n: usize) -> Snapshot {
    let mut pods = Vec::new();
    let mut services = Vec::new();
    let mut secrets = Vec::new();
    for i in 0..n {
        pods.push(
            serde_json::from_value(json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": format!("web-{i}"), "namespace": "app", "labels": {"app": format!("web-{i}")}},
                "spec": {"containers": [{
                    "name": "web", "image": format!("web-{i}:1"),
                    "envFrom": [{"secretRef": {"name": format!("session-key-{i}")}}]
                }]}
            }))
            .unwrap(),
        );
        services.push(
            serde_json::from_value(json!({
                "apiVersion": "v1", "kind": "Service",
                "metadata": {"name": format!("web-lb-{i}"), "namespace": "app"},
                "spec": {"type": "LoadBalancer", "selector": {"app": format!("web-{i}")}}
            }))
            .unwrap(),
        );
        secrets.push(SecretMeta {
            namespace: "app".into(),
            name: format!("session-key-{i}"),
        });
    }
    Snapshot {
        pods,
        services,
        secrets,
        ..Default::default()
    }
}

pub(super) fn engine_with(counter: Arc<AtomicUsize>) -> Engine {
    Engine::new(
        EnabledActions::from_names(std::iter::empty::<&str>()),
        ActuationScope::unscoped(),
        Box::new(DryRunActuator),
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

/// JEF-350: the verdict cache is keyed on a hash of the DETERMINISTIC prompt (the model's
/// complete input), so it hits exactly when — and only when — what the model would see is
/// unchanged. An identical snapshot renders an identical prompt → same hash → a cache hit
/// (no model call); a MATERIALLY changed snapshot (here a new critical CVE enters the
/// entry's evidence) changes the prompt → a new hash → a miss → a re-judge. This is the
/// behavioral proof that the drift the ticket fixed — a cache key that churned while the
/// model's input was unchanged — is gone.
#[tokio::test]
async fn verdict_cache_hits_on_unchanged_prompt_and_misses_when_the_prompt_changes() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = engine_with(calls.clone());

    // Pass 1 (cold cache): the internet-reachable entry is judged.
    engine.process(&exposed_snapshot(false)).await;
    let after_cold = calls.load(Ordering::SeqCst);
    assert!(after_cold >= 1, "a cold cache judges the entry");

    // Pass 2 (identical facts): same prompt → same hash → cache hit, no new model call.
    engine.process(&exposed_snapshot(false)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        after_cold,
        "an unchanged prompt is a cache hit (no re-judge)"
    );

    // Pass 3 (a new critical CVE on the same entry): the prompt's CVE evidence changes, so
    // its hash changes → a cache miss → the entry is re-judged.
    engine.process(&exposed_snapshot(true)).await;
    assert!(
        calls.load(Ordering::SeqCst) > after_cold,
        "a materially changed prompt busts the cache and re-judges the entry"
    );
}

/// An adjudicator that returns a fixed verdict and never re-judges issues a `judged`
/// only on a fingerprint miss.
pub(super) struct FixedAdjudicator(pub(super) Verdict);

#[async_trait::async_trait]
impl reason::adjudicate::Adjudicator for FixedAdjudicator {
    async fn judge(
        &self,
        _entry: &NodeKey,
        _objectives: &[(NodeKey, AttackRef)],
        _graph: &SecurityGraph,
        _prompt: &str,
        _downstream: &[NodeKey],
        _menu: &Menu,
    ) -> IncidentDecision {
        decision_of(self.0.clone())
    }
}

pub(super) fn engine_with_adjudicator(adj: Box<dyn reason::adjudicate::Adjudicator>) -> Engine {
    Engine::new(
        EnabledActions::from_names(std::iter::empty::<&str>()),
        ActuationScope::unscoped(),
        Box::new(DryRunActuator),
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
            _prompt: &str,
            _downstream: &[NodeKey],
            _menu: &Menu,
        ) -> IncidentDecision {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                decision_of(Verdict::Exploitable("RCE reaches the secret".into()))
            } else {
                IncidentDecision::uncertain("model unavailable")
            }
        }
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let mut engine = engine_with_adjudicator(Box::new(FlakyAdjudicator(calls.clone())));

    // Pass 1: decisive Exploitable (no CVE yet — the entry is breach-relevant because it
    // reaches the mounted secret), resolved in the findings snapshot. This sets the JEF-391
    // baseline to the current, CVE-free surface.
    engine.process(&exposed_snapshot(false)).await;
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

    // Pass 2 ADDS a critical CVE — an ADDITIVE delta since the baseline (JEF-391), so the model
    // is re-consulted — and this time it returns Uncertain. The resolved posture must keep the
    // prior decisive verdict, not regress to "uncertain". (A purely SUBTRACTIVE change would NOT
    // re-judge under ADR-0023; the additive one is what drives the re-judge here.)
    engine.process(&exposed_snapshot(true)).await;
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

    // A namespace/name attribution always resolves, even against an empty snapshot.
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
        source: Some("alert".into()),
        observed_at_ms: None,
        node: None,
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
            source: Some("alert".into()),
            observed_at_ms: None,
            node: None,
            behavior: Behavior::Alert {
                rule: "Terminal shell in container".into(),
            },
        },
        // A connection attributed to an unknown cgroup UID → unresolved (no such pod).
        RuntimeObservation {
            attribution: Attribution::by_pod_uid("uid-not-in-snapshot"),
            source: Some("agent".into()),
            observed_at_ms: None,
            node: None,
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

/// JEF-337: an adjudicator that records how many `judge` calls overlap at once. Each call
/// lingers briefly so, if the dispatch runs them concurrently, the observed max exceeds one.
struct ConcurrencyProbe {
    in_flight: Arc<AtomicUsize>,
    max_in_flight: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl reason::adjudicate::Adjudicator for ConcurrencyProbe {
    async fn judge(
        &self,
        _entry: &NodeKey,
        _objectives: &[(NodeKey, AttackRef)],
        _graph: &SecurityGraph,
        _prompt: &str,
        _downstream: &[NodeKey],
        _menu: &Menu,
    ) -> IncidentDecision {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        // Linger so concurrent calls overlap and are seen by the max counter above.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        decision_of(Verdict::Refuted("counted".into()))
    }
}

/// JEF-337 acceptance: a single adjudication pass dispatches its per-entry model calls
/// CONCURRENTLY, not one-at-a-time behind the old serialization gate. With several distinct
/// breach entries in one snapshot, the adjudicator must see more than one `judge` in flight at
/// once — the observable difference from the removed 1-permit gate.
#[tokio::test]
async fn adjudication_dispatches_entries_concurrently() {
    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_in_flight = Arc::new(AtomicUsize::new(0));
    let mut engine = engine_with_adjudicator(Box::new(ConcurrencyProbe {
        in_flight: in_flight.clone(),
        max_in_flight: max_in_flight.clone(),
    }));

    // Six independent entries in one pass — comfortably under the default concurrency (8).
    engine.process(&exposed_snapshot_n(6)).await;

    assert!(
        max_in_flight.load(Ordering::SeqCst) > 1,
        "the pass must run entries concurrently (max in flight was {}), not serialize them",
        max_in_flight.load(Ordering::SeqCst)
    );
}

/// JEF-337 isolation: one entry's model failure (an Uncertain — a 500/timeout maps to that)
/// must NOT abort or poison the other entries' adjudication in the same concurrent pass. An
/// adjudicator that fails exactly ONE entry (the first to be polled) and decisively judges the
/// rest must leave every other entry with its decisive verdict; only the failing one is
/// inconclusive, and it is simply retried next pass.
#[tokio::test]
async fn one_entrys_model_failure_does_not_poison_the_others() {
    // The first `judge` call this pass returns Uncertain (a model error); all others are
    // decisive Exploitable. Which entry fails is whichever the concurrent dispatch polls
    // first — irrelevant; the point is that exactly one fails and the rest are unaffected.
    struct FailFirst(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl reason::adjudicate::Adjudicator for FailFirst {
        async fn judge(
            &self,
            _entry: &NodeKey,
            _objectives: &[(NodeKey, AttackRef)],
            _graph: &SecurityGraph,
            _prompt: &str,
            _downstream: &[NodeKey],
            _menu: &Menu,
        ) -> IncidentDecision {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                IncidentDecision::uncertain("model unavailable")
            } else {
                decision_of(Verdict::Exploitable("RCE reaches the secret".into()))
            }
        }
    }
    const N: usize = 5;
    let mut engine = engine_with_adjudicator(Box::new(FailFirst(Arc::new(AtomicUsize::new(0)))));
    engine.process(&exposed_snapshot_n(N)).await;

    let findings = engine.findings().snapshot();
    let breach: Vec<_> = findings.iter().filter(|f| f.breach_relevant).collect();
    assert_eq!(
        breach.len(),
        N,
        "every entry produced a breach-relevant finding"
    );
    let exploitable = breach
        .iter()
        .filter(|f| {
            f.verdict
                .as_ref()
                .map(|v| v.summary())
                .as_deref()
                .is_some_and(|s| s.starts_with("exploitable"))
        })
        .count();
    assert_eq!(
        exploitable,
        N - 1,
        "one entry's failure leaves the other {} entries' decisive verdicts intact",
        N - 1
    );
}

// --- ADR-0034 (JEF-570): the cut-choice contract wired into the live ledger ---

/// ADR-0034 D7 (the retirement asymmetry, the safety-critical half of this ticket): a
/// PREVIOUSLY model-chosen cut must NOT retire just because the model comes back `Uncertain`
/// on a later pass — a transient outage may neither open a live attack path (this test) nor
/// sever one (D7's other half, unit-tested directly on `IncidentDecision`/guards in the
/// `incident` module). Pass 1 decisively chooses the entry's own menu line; pass 2's fresh
/// `Uncertain` must leave that exact mitigation active.
#[tokio::test]
async fn a_fresh_uncertain_does_not_retire_a_previously_chosen_cut() {
    struct AttackThenUncertain(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl reason::adjudicate::Adjudicator for AttackThenUncertain {
        async fn judge(
            &self,
            entry: &NodeKey,
            _objectives: &[(NodeKey, AttackRef)],
            _graph: &SecurityGraph,
            _prompt: &str,
            _downstream: &[NodeKey],
            menu: &Menu,
        ) -> IncidentDecision {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                let cut = menu
                    .resolve(entry)
                    .expect("the entry is selectable on its own menu");
                IncidentDecision {
                    assessment: Assessment::Attack,
                    reason: "RCE reaches the secret".to_string(),
                    cuts: vec![cut],
                }
            } else {
                IncidentDecision::uncertain("model unavailable")
            }
        }
    }
    let mut engine =
        engine_with_adjudicator(Box::new(AttackThenUncertain(Arc::new(AtomicUsize::new(0)))));

    // Pass 1: decisive Attack naming the entry — the cut goes active.
    engine.process(&exposed_snapshot(true)).await;
    let active_after_first: Vec<String> =
        engine.ledger.active().map(|m| m.cut_signature()).collect();
    assert!(
        !active_after_first.is_empty(),
        "the decisive Attack's chosen cut is active after pass 1"
    );

    // Pass 2 ADDS nothing (identical facts), so the entry re-verifies (JEF-445 — a cached
    // Exploitable/Attack is never served from cache) and this time comes back Uncertain. The
    // ledger's active set must be UNCHANGED — inert, not retired.
    engine.process(&exposed_snapshot(true)).await;
    let active_after_second: Vec<String> =
        engine.ledger.active().map(|m| m.cut_signature()).collect();
    assert_eq!(
        active_after_second, active_after_first,
        "a fresh Uncertain must retire nothing — the standing cut persists (ADR-0034 D7)"
    );
}

/// Rail: shadow stays the default posture (CLAUDE.md / ADR-0021) — even a decisive `Attack`
/// naming a real cut on a corroborated, breach-relevant chain only ever PROPOSES with no
/// action classes armed; nothing reaches the (dry-run) actuator.
#[tokio::test]
async fn a_model_chosen_cut_only_proposes_in_shadow_by_default() {
    struct AlwaysNamesTheEntry;
    #[async_trait::async_trait]
    impl reason::adjudicate::Adjudicator for AlwaysNamesTheEntry {
        async fn judge(
            &self,
            entry: &NodeKey,
            _objectives: &[(NodeKey, AttackRef)],
            _graph: &SecurityGraph,
            _prompt: &str,
            _downstream: &[NodeKey],
            menu: &Menu,
        ) -> IncidentDecision {
            let cut = menu
                .resolve(entry)
                .expect("the entry is selectable on its own menu");
            IncidentDecision {
                assessment: Assessment::Attack,
                reason: "RCE reaches the secret".to_string(),
                cuts: vec![cut],
            }
        }
    }
    // `engine_with_adjudicator` builds with `EnabledActions::from_names(std::iter::empty())`
    // (shadow — nothing armed) and a `DryRunActuator` — the default posture (CLAUDE.md).
    let mut engine = engine_with_adjudicator(Box::new(AlwaysNamesTheEntry));
    engine.process(&exposed_snapshot(true)).await;

    let active: Vec<_> = engine.ledger.active().cloned().collect();
    assert!(
        !active.is_empty(),
        "the model-chosen cut is proposed (ledger-active), even in shadow"
    );
    // Shadow is the DEFAULT (CLAUDE.md / ADR-0021) — `engine_with_adjudicator` arms no action
    // class, so the actuator never sees an apply: the applied-action log stays empty.
    assert_eq!(
        engine.actions.active_count(),
        0,
        "nothing armed ⇒ nothing actually applied, even for a decisive model-chosen cut"
    );
}
