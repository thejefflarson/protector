//! Per-pass signing-posture sweep (ADR-0020 Stage 1, JEF-261).
//!
//! The webhook observes each *admitted* image; this sweep covers the other half — the pods
//! **already running** when protector started, which no admission event will ever replay.
//! It reads the analysis engine's Pod reflector store (the typed `Pod`s in the per-pass
//! [`Snapshot`](super::observe::Snapshot)) and runs every distinct container image through the
//! shared [`SigningObserver`], recording the observed [`SigningPosture`] into the same
//! [`PolicyDecisionLog`] the webhook writes — so the operator sees one signing inventory
//! across both admitted and pre-existing workloads.
//!
//! The posture is recorded as the low-cardinality status word on an `image-signature` row (the
//! field is free-text, escaped at render); the signer identity rides the row's reason, also escaped
//! downstream. State is the in-memory [`SigningObserver`] cache + the bounded [`PolicyDecisionLog`]
//! ring — no durable schema.
//!
//! ## Drift findings (JEF-264, ADR-0020 §3)
//!
//! After recording each posture, the sweep classifies it against the repo's CURRENT baseline
//! (JEF-263) via the pure [`signing_drift`](super::signing_drift) classifier and, on a regression
//! against prior signed history (signed→unsigned/invalid, or a new signer), records a
//! signing-**regression** finding onto the SAME admission-decision log — keyed
//! `SigningRegression/<repo>`, decision `allow`. This is **audit-only — still admitted** (the
//! shadow invariant, ADR-0016): the finding is surfaced, never acted on. Enforcement (JEF-265) and
//! Rekor history (JEF-266) are later stages and are NOT built here.

use std::sync::Arc;
use std::time::SystemTime;

use k8s_openapi::api::core::v1::Pod;

use super::journal::DecisionJournal;
use super::observe::Snapshot;
use super::policy_log::{PolicyDecisionLog, PolicyDecisionRecord};
use super::signing_baseline_strength::strength_record;
use super::signing_drift::{RegressionKind, SigningDrift, classify};
use super::state::{SigningBaseline, SigningBaselineStore};
use crate::policies::signature::{PostureMap, SigningObserver, SigningPosture, repo_key};

/// The subject prefix a signing-**regression** finding is keyed under (`SigningRegression/<repo>`),
/// so the row folds one-per-repo and is partitioned OUT of the webhook decision rows (like the
/// `Image/<ref>` observation rows) by the Admission view_model — a regression is a signing finding,
/// not a webhook admission decision, and must not inflate the admitted/audited/denied tallies.
pub const REGRESSION_SUBJECT_PREFIX: &str = "SigningRegression/";

/// Collect every distinct container image a running Pod references — regular, init, and
/// ephemeral containers — across the snapshot. Deduping is left to the observer's sweep (it
/// keys on the image ref), so this just flattens.
fn snapshot_images(pods: &[Pod]) -> Vec<String> {
    let mut images = Vec::new();
    for pod in pods {
        let Some(spec) = pod.spec.as_ref() else {
            continue;
        };
        for c in &spec.containers {
            if let Some(image) = c.image.as_ref() {
                images.push(image.clone());
            }
        }
        for c in spec.init_containers.iter().flatten() {
            if let Some(image) = c.image.as_ref() {
                images.push(image.clone());
            }
        }
        for c in spec.ephemeral_containers.iter().flatten() {
            if let Some(image) = c.image.as_ref() {
                images.push(image.clone());
            }
        }
    }
    images
}

/// The human-facing reason text for a recorded posture row. The signer identity + issuer are
/// UNTRUSTED third-party text (an attacker-influenceable Fulcio cert subject); they are
/// recorded verbatim here and MUST be escaped wherever this row is later rendered (the
/// `PolicyDecisionLog` contract already requires it). Empty for a plain `not-signed`, which
/// needs no prose beyond its status word.
fn posture_reason(posture: &SigningPosture) -> String {
    match posture {
        SigningPosture::Signed(signer) => match signer.issuer.as_deref() {
            Some(issuer) => format!("signed by {} via {}", signer.identity, issuer),
            None => format!("signed by {}", signer.identity),
        },
        SigningPosture::SignedKeyBased => {
            "signed with a key-based cosign signature (verified transparency-log inclusion, no \
             Fulcio identity) \u{2014} signer is opaque to keyless verification"
                .to_string()
        }
        SigningPosture::UnverifiableHere => {
            "signature present but could not be verified against our trust root (transparency-log/\
             TUF variance) \u{2014} not a verification failure"
                .to_string()
        }
        SigningPosture::InvalidSignature => {
            "signature present but genuinely fails to verify (tampered/broken chain)".to_string()
        }
        SigningPosture::NotSigned => String::new(),
        SigningPosture::Checking => {
            "signing posture not yet known (registry/log unreachable)".to_string()
        }
    }
}

/// Record an observed [`PostureMap`] into the admission-decision log as `image-signature`
/// rows, keyed (for dedup) by the image ref. The decision word stays `allow` — this is pure
/// observation, never a gate (ADR-0016: presentation is a view); the signing posture is the
/// security-bearing fact, carried in the `signature` status column. Pre-existing rows for the
/// same image fold via the log's `(subject, image, decision)` dedup.
fn record_postures(log: &PolicyDecisionLog, map: &PostureMap) {
    for (image, posture) in map.entries() {
        // The subject is the image itself for a sweep row: the running-Pod sweep observes by
        // image, not per workload (a digest is shared across replicas/workloads), and a
        // per-workload attribution is JEF-262's render concern, not Stage-1 recording.
        let record = PolicyDecisionRecord::now(
            "image-signature",
            "allow",
            format!("Image/{image}"),
            image,
            posture.status(),
            "",
            "",
            posture_reason(posture),
        );
        log.record(record);
    }
}

/// Encode a signing-regression finding as an admission-decision-log row (JEF-264, ADR-0020 §3).
///
/// Routing: the regression rides the SAME admission-decision log as the posture observation rows
/// (the admission-finding path), NOT the reachability breach/LLM pipeline. It is keyed
/// `SigningRegression/<repo>` so it folds one-per-repo and the Admission view_model partitions it
/// out of the webhook decision tallies. The decision word stays `allow`: a drift is **audit-only —
/// still admitted** (the shadow invariant, ADR-0016); nothing here ever denies.
///
/// The row is self-describing so the render needs no baseline handle:
///   * `signature` carries the low-cardinality drift token `regression-<kind>-<strength>` (kind ∈
///     unsigned/invalid/identity, strength ∈ established/cold) — the render parses it back.
///   * `reason` carries the before→after prose: the fresh posture clause, then `| before: <ids>`
///     (the baseline signers, comma-joined). Both the before signers and any after signer are
///     UNTRUSTED Fulcio cert text — carried verbatim here and escaped wherever rendered.
fn regression_record(
    repo: &str,
    image: &str,
    kind: &RegressionKind,
    established: bool,
    baseline: Option<&SigningBaseline>,
) -> PolicyDecisionRecord {
    let strength = if established { "established" } else { "cold" };
    let signature = format!("regression-{}-{}", kind.word(), strength);
    let after_clause = match kind {
        RegressionKind::Unsigned => "now not signed (was signed)".to_string(),
        RegressionKind::Invalid => "now invalid signature (was signed)".to_string(),
        // Reuse the observation-row signer prose (`signed by <id>[ via <issuer>]`) so the view_model
        // parses the "after" identity with the exact same helper it already uses for observed rows.
        RegressionKind::IdentityChange {
            new_identity,
            new_issuer,
        } => match new_issuer.as_deref() {
            Some(issuer) => format!("signed by {new_identity} via {issuer}"),
            None => format!("signed by {new_identity}"),
        },
    };
    // The baseline signers (the "before"), comma-joined. Fulcio SANs (workflow URIs / emails) don't
    // contain ", ", so the join round-trips; the render escapes each identity regardless.
    let before = baseline
        .map(|b| b.identities.iter().cloned().collect::<Vec<_>>().join(", "))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let reason = format!("{after_clause} | before: {before}");
    PolicyDecisionRecord::now(
        "signing-regression",
        "allow",
        format!("{REGRESSION_SUBJECT_PREFIX}{repo}"),
        image,
        signature,
        "",
        "",
        reason,
    )
}

/// Classify each observed posture against the repo's CURRENT baseline (JEF-264) and record a
/// signing-regression finding for any drift against prior signed history. Runs BEFORE
/// [`learn_baselines`] so a new signer is still visible as not-yet-in the identity set (learning
/// would fold it in and hide the change). Pure classification + append-only recording — never a
/// gate; the store is read, not mutated.
fn detect_regressions(store: &SigningBaselineStore, log: &PolicyDecisionLog, map: &PostureMap) {
    for (image, posture) in map.entries() {
        let repo = repo_key(image);
        let baseline = store.get(&repo);
        if let SigningDrift::Regression { kind, established } = classify(baseline, posture) {
            log.record(regression_record(
                &repo,
                image,
                &kind,
                established,
                baseline,
            ));
        }
    }
}

/// Fold this pass's observed postures into the durable per-repo signing baseline (JEF-263),
/// then compact the whole store back to the journal so a live repo's baseline stays inside
/// the rotation window (never aged out). Only `Signed` postures learn a baseline; the store
/// itself ignores the rest. Every step is a no-op on a disabled journal / cold store, so this
/// is safe to call unconditionally each pass.
fn learn_baselines(store: &mut SigningBaselineStore, journal: &DecisionJournal, map: &PostureMap) {
    let now_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    for (image, posture) in map.entries() {
        store.observe(image, posture, now_ms);
    }
    // Full-state compaction per pass: re-append every live repo so rotation can never drop an
    // established baseline (the durability discipline that keeps cold-start trust from
    // silently re-arming). Bounded by the store's repo cap; a handful of small lines for a
    // real cluster.
    store.compact(journal);
}

/// Record each observed repo's baseline **strength** (JEF-266) as a `SigningStrength/<repo>` row —
/// log-corroborated vs local-only. Written every pass regardless of the Rekor lane, so the
/// inventory shows the honest local-only default when the lane is off; the Rekor reconcile pass
/// refreshes a repo it corroborates. Only repos with a learned baseline (a `Signed` sight) get a
/// row.
fn record_strengths(store: &SigningBaselineStore, log: &PolicyDecisionLog, map: &PostureMap) {
    for (image, _) in map.entries() {
        let repo = repo_key(image);
        if let Some(baseline) = store.get(&repo) {
            log.record(strength_record(&repo, baseline));
        }
    }
}

/// Run one signing-posture sweep over the snapshot's running pods and record the result.
/// A no-op (zero outbound calls, nothing recorded) when no observer is configured — so a
/// deploy without signature config behaves exactly as before. Bounded by the observer's
/// `max_images` cap + TTL cache, so a steady cluster re-sweeps for free and a churny one
/// can't amplify outbound verification.
///
/// The observed postures also feed the durable per-repo signing baseline (JEF-263) when a
/// `baseline` store + `journal` are wired: a signed image teaches the repo's TOFU baseline,
/// which is persisted to (and, on boot, replayed from) the SAME decision journal. This is
/// pure learning — never a gate (ADR-0016); drift/enforcement are later stages.
///
/// Returns the [`PostureMap`] observed this pass so the caller can run the opt-in Rekor
/// reconciliation pass (JEF-266) over the same observations without re-sweeping. An empty map when
/// no observer is configured or there are no running images.
pub async fn sweep(
    observer: Option<&SigningObserver>,
    snapshot: &Snapshot,
    log: &Arc<PolicyDecisionLog>,
    baseline: Option<&mut SigningBaselineStore>,
    journal: &DecisionJournal,
) -> PostureMap {
    let Some(observer) = observer else {
        return PostureMap::new();
    };
    let images = snapshot_images(&snapshot.pods);
    if images.is_empty() {
        return PostureMap::new();
    }
    let map = observer.sweep(images).await;
    record_postures(log, &map);
    if let Some(store) = baseline {
        // Classify against the baseline as it stands BEFORE this pass's learning, then learn — so
        // a regression / new signer is detected before the observation folds into the baseline.
        detect_regressions(store, log, &map);
        learn_baselines(store, journal, &map);
        // Surface each repo's baseline strength (JEF-266) — log-corroborated vs local-only. Written
        // after learning so the row reflects the freshly-updated baseline.
        record_strengths(store, log, &map);
    }
    map
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;

    use super::*;
    use crate::engine::state::SigningBaselineStore;
    use crate::policies::signature::{SignatureObserver, Signer};

    fn pod(images: &[&str], init: &[&str]) -> Pod {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "demo", "namespace": "default"},
            "spec": {
                "containers": images.iter().map(|i| serde_json::json!({"name": "c", "image": i})).collect::<Vec<_>>(),
                "initContainers": init.iter().map(|i| serde_json::json!({"name": "i", "image": i})).collect::<Vec<_>>(),
            }
        }))
        .expect("valid pod")
    }

    struct FakeObserver {
        postures: HashMap<String, SigningPosture>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl SignatureObserver for FakeObserver {
        async fn observe(&self, image: &str) -> SigningPosture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.postures
                .get(image)
                .cloned()
                .unwrap_or(SigningPosture::NotSigned)
        }
    }

    fn observer(postures: Vec<(&str, SigningPosture)>) -> (SigningObserver, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let fake = FakeObserver {
            postures: postures
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            calls: calls.clone(),
        };
        (
            SigningObserver::new(Arc::new(fake), 32, Duration::from_secs(300)),
            calls,
        )
    }

    fn signed(identity: &str) -> SigningPosture {
        SigningPosture::Signed(Signer {
            identity: identity.to_string(),
            issuer: Some("https://token.actions.githubusercontent.com".to_string()),
        })
    }

    #[test]
    fn extracts_images_from_running_pods() {
        let pods = vec![
            pod(&["ghcr.io/org/app:1"], &["ghcr.io/org/init:1"]),
            pod(&["docker.io/library/postgres:16"], &[]),
        ];
        let images = snapshot_images(&pods);
        assert!(images.contains(&"ghcr.io/org/app:1".to_string()));
        assert!(images.contains(&"ghcr.io/org/init:1".to_string()));
        assert!(images.contains(&"docker.io/library/postgres:16".to_string()));
    }

    #[tokio::test]
    async fn sweep_records_postures_for_running_pods() {
        // The acceptance behavior: already-running pods (not just admissions) are observed and
        // their posture recorded into the shared log.
        let (obs, _calls) = observer(vec![
            (
                "ghcr.io/org/app:1",
                signed("https://github.com/org/app/.github/workflows/r.yaml@refs/tags/v1"),
            ),
            ("ghcr.io/org/tampered:1", SigningPosture::InvalidSignature),
        ]);
        let snapshot = Snapshot {
            pods: vec![
                pod(&["ghcr.io/org/app:1"], &[]),
                pod(&["ghcr.io/org/tampered:1"], &[]),
                pod(&["docker.io/library/postgres:16"], &[]),
            ],
            ..Default::default()
        };
        let log = Arc::new(PolicyDecisionLog::new());
        sweep(
            Some(&obs),
            &snapshot,
            &log,
            None,
            &DecisionJournal::disabled(),
        )
        .await;
        let rows = log.snapshot();
        assert_eq!(rows.len(), 3, "one row per distinct running image");
        let by_image: HashMap<_, _> = rows.iter().map(|r| (r.image.as_str(), r)).collect();
        assert_eq!(by_image["ghcr.io/org/app:1"].signature, "signed");
        assert!(
            by_image["ghcr.io/org/app:1"]
                .reason
                .contains("signed by https://github.com/org/app")
        );
        assert_eq!(
            by_image["ghcr.io/org/tampered:1"].signature,
            "invalid-signature"
        );
        assert_eq!(
            by_image["docker.io/library/postgres:16"].signature,
            "not-signed"
        );
        // Pure observation: never a gate (ADR-0016) — the decision word stays `allow`.
        assert!(rows.iter().all(|r| r.decision == "allow"));
    }

    #[tokio::test]
    async fn checking_posture_is_recorded_not_dropped_and_distinguishable() {
        let (obs, _calls) = observer(vec![(
            "ghcr.io/org/unreachable:1",
            SigningPosture::Checking,
        )]);
        let snapshot = Snapshot {
            pods: vec![pod(&["ghcr.io/org/unreachable:1"], &[])],
            ..Default::default()
        };
        let log = Arc::new(PolicyDecisionLog::new());
        sweep(
            Some(&obs),
            &snapshot,
            &log,
            None,
            &DecisionJournal::disabled(),
        )
        .await;
        let rows = log.snapshot();
        assert_eq!(rows[0].signature, "checking");
        assert_ne!(
            rows[0].signature, "not-signed",
            "transient is not a false clean"
        );
    }

    #[tokio::test]
    async fn no_observer_is_a_no_op() {
        // A deploy without signature config records nothing and makes no outbound call.
        let snapshot = Snapshot {
            pods: vec![pod(&["ghcr.io/org/app:1"], &[])],
            ..Default::default()
        };
        let log = Arc::new(PolicyDecisionLog::new());
        sweep(None, &snapshot, &log, None, &DecisionJournal::disabled()).await;
        assert!(log.snapshot().is_empty());
    }

    #[tokio::test]
    async fn re_sweep_reuses_cache_zero_extra_calls() {
        let (obs, calls) = observer(vec![(
            "ghcr.io/org/app:1",
            signed("https://github.com/org/app/.github/workflows/r.yaml@refs/tags/v1"),
        )]);
        let snapshot = Snapshot {
            pods: vec![pod(&["ghcr.io/org/app:1"], &[])],
            ..Default::default()
        };
        let log = Arc::new(PolicyDecisionLog::new());
        sweep(
            Some(&obs),
            &snapshot,
            &log,
            None,
            &DecisionJournal::disabled(),
        )
        .await;
        sweep(
            Some(&obs),
            &snapshot,
            &log,
            None,
            &DecisionJournal::disabled(),
        )
        .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the second sweep is served from the observer cache — zero new outbound calls"
        );
    }

    #[tokio::test]
    async fn sweep_teaches_the_repo_baseline_from_a_signed_image() {
        // The JEF-263 wiring: a signed image observed by the sweep learns a per-repo baseline,
        // keyed by registry/repo. Pure learning — the log still records `allow`.
        let (obs, _calls) = observer(vec![(
            "ghcr.io/org/app:1",
            signed("https://github.com/org/app/.github/workflows/r.yaml@refs/tags/v1"),
        )]);
        let snapshot = Snapshot {
            pods: vec![pod(&["ghcr.io/org/app:1"], &[])],
            ..Default::default()
        };
        let log = Arc::new(PolicyDecisionLog::new());
        let mut baseline = SigningBaselineStore::new();
        sweep(
            Some(&obs),
            &snapshot,
            &log,
            Some(&mut baseline),
            &DecisionJournal::disabled(),
        )
        .await;
        let learned = baseline
            .get("ghcr.io/org/app")
            .expect("the signed image taught a repo baseline");
        assert!(
            learned
                .identities
                .contains("https://github.com/org/app/.github/workflows/r.yaml@refs/tags/v1")
        );
        assert!(
            !learned.established,
            "first sight is a fresh, weak baseline"
        );
    }

    #[tokio::test]
    async fn sweep_does_not_learn_a_baseline_for_an_unsigned_image() {
        // A not-signed posture must never create a baseline (that's JEF-264 drift territory).
        let (obs, _calls) = observer(vec![]); // unknown image ⇒ FakeObserver returns NotSigned
        let snapshot = Snapshot {
            pods: vec![pod(&["docker.io/library/postgres:16"], &[])],
            ..Default::default()
        };
        let log = Arc::new(PolicyDecisionLog::new());
        let mut baseline = SigningBaselineStore::new();
        sweep(
            Some(&obs),
            &snapshot,
            &log,
            Some(&mut baseline),
            &DecisionJournal::disabled(),
        )
        .await;
        assert!(baseline.is_empty(), "an unsigned image learns no baseline");
    }

    // ---- JEF-264 signing-regression detection over the sweep -------------------------------

    const DAY_MS: u64 = 24 * 60 * 60 * 1000;
    const CI: &str = "https://github.com/org/app/.github/workflows/release.yaml@refs/tags/v1";
    const ATTACKER: &str = "https://github.com/evil/app/.github/workflows/pwn.yaml@refs/heads/main";

    /// A store carrying an ESTABLISHED signed baseline for `ghcr.io/org/app` (signer `CI`). Seeded
    /// by observing at t=0 (first_seen), then again well past the 24h grace window so the baseline
    /// matures — exactly the JEF-263 establishment path, without a real clock.
    fn established_store() -> SigningBaselineStore {
        let mut store = SigningBaselineStore::new();
        let signed = SigningPosture::Signed(Signer {
            identity: CI.to_string(),
            issuer: Some("https://token.actions.githubusercontent.com".to_string()),
        });
        store.observe("ghcr.io/org/app@sha256:seed", &signed, 0);
        store.observe("ghcr.io/org/app@sha256:seed", &signed, 3 * DAY_MS);
        assert!(
            store.get("ghcr.io/org/app").unwrap().established,
            "the seeded baseline is established"
        );
        store
    }

    /// The regression row recorded for `repo`, if any.
    fn regression_row(log: &PolicyDecisionLog, repo: &str) -> Option<PolicyDecisionRecord> {
        log.snapshot()
            .into_iter()
            .find(|r| r.subject == format!("{REGRESSION_SUBJECT_PREFIX}{repo}"))
    }

    async fn run_sweep(
        obs: &SigningObserver,
        image: &str,
        store: &mut SigningBaselineStore,
    ) -> Arc<PolicyDecisionLog> {
        let snapshot = Snapshot {
            pods: vec![pod(&[image], &[])],
            ..Default::default()
        };
        let log = Arc::new(PolicyDecisionLog::new());
        sweep(
            Some(obs),
            &snapshot,
            &log,
            Some(store),
            &DecisionJournal::disabled(),
        )
        .await;
        log
    }

    #[tokio::test]
    async fn signed_to_unsigned_on_established_repo_records_a_regression() {
        let (obs, _c) = observer(vec![]); // unknown image ⇒ NotSigned
        let mut store = established_store();
        let log = run_sweep(&obs, "ghcr.io/org/app:2", &mut store).await;
        let row = regression_row(&log, "ghcr.io/org/app").expect("a regression is recorded");
        assert_eq!(row.signature, "regression-unsigned-established");
        assert_eq!(
            row.decision, "allow",
            "audit-only — the image is still admitted"
        );
        assert!(row.reason.contains("now not signed"));
        assert!(row.reason.contains(&format!("before: {CI}")));
    }

    #[tokio::test]
    async fn signed_to_invalid_on_established_repo_records_a_regression() {
        let (obs, _c) = observer(vec![(
            "ghcr.io/org/app:2",
            SigningPosture::InvalidSignature,
        )]);
        let mut store = established_store();
        let log = run_sweep(&obs, "ghcr.io/org/app:2", &mut store).await;
        let row = regression_row(&log, "ghcr.io/org/app").expect("a regression is recorded");
        assert_eq!(row.signature, "regression-invalid-established");
        assert_eq!(row.decision, "allow");
    }

    #[tokio::test]
    async fn new_signer_on_established_repo_records_an_identity_change() {
        let (obs, _c) = observer(vec![("ghcr.io/org/app:2", signed(ATTACKER))]);
        let mut store = established_store();
        let log = run_sweep(&obs, "ghcr.io/org/app:2", &mut store).await;
        let row = regression_row(&log, "ghcr.io/org/app").expect("a regression is recorded");
        assert_eq!(row.signature, "regression-identity-established");
        assert!(row.reason.contains(&format!("signed by {ATTACKER}")));
        assert!(
            row.reason.contains(&format!("before: {CI}")),
            "the before signer is stated in full"
        );
    }

    #[tokio::test]
    async fn normal_redeploy_by_a_known_signer_records_no_regression() {
        // A new digest under a known repo, signed by the KNOWN identity ⇒ no false positive.
        let (obs, _c) = observer(vec![("ghcr.io/org/app:2", signed(CI))]);
        let mut store = established_store();
        let log = run_sweep(&obs, "ghcr.io/org/app:2", &mut store).await;
        assert!(
            regression_row(&log, "ghcr.io/org/app").is_none(),
            "a known signer to a new digest is continuous — no finding"
        );
    }

    #[tokio::test]
    async fn cold_start_first_signed_sight_records_no_regression() {
        // First observation of a never-seen repo is TOFU cold start — never a regression.
        let (obs, _c) = observer(vec![("ghcr.io/new/app:1", signed(CI))]);
        let mut store = SigningBaselineStore::new();
        let log = run_sweep(&obs, "ghcr.io/new/app:1", &mut store).await;
        assert!(
            regression_row(&log, "ghcr.io/new/app").is_none(),
            "cold start is TOFU, not drift"
        );
        assert!(
            store.get("ghcr.io/new/app").is_some(),
            "the baseline is still recorded on first sight"
        );
    }

    #[tokio::test]
    async fn key_based_posture_is_recorded_calm_and_never_regresses_an_established_repo() {
        // JEF-276 end-to-end: an established keyless-signed repo that now serves a key-based
        // signature records the calm `signed-key-based` status, learns NO new baseline (no signer to
        // teach), and surfaces NO regression — the false-alarm fix, wired through the sweep.
        let (obs, _c) = observer(vec![("ghcr.io/org/app:2", SigningPosture::SignedKeyBased)]);
        let mut store = established_store();
        let log = run_sweep(&obs, "ghcr.io/org/app:2", &mut store).await;
        let rows = log.snapshot();
        let posture_row = rows
            .iter()
            .find(|r| r.subject == "Image/ghcr.io/org/app:2")
            .expect("the posture is recorded");
        assert_eq!(posture_row.signature, "signed-key-based");
        assert!(
            regression_row(&log, "ghcr.io/org/app").is_none(),
            "a calm key-based signature is not a regression"
        );
        assert!(
            !store
                .get("ghcr.io/org/app")
                .unwrap()
                .identities
                .contains("ghcr.io/org/app:2"),
            "a key-based signature teaches no new signer identity"
        );
    }

    #[tokio::test]
    async fn regression_against_a_cold_baseline_is_reduced() {
        // A freshly-learned (cold) baseline that then regresses is flagged reduced-intensity.
        let mut store = SigningBaselineStore::new();
        store.observe(
            "ghcr.io/org/app@sha256:seed",
            &signed(CI),
            0, // first sight ⇒ cold (not established)
        );
        assert!(!store.get("ghcr.io/org/app").unwrap().established);
        let (obs, _c) = observer(vec![]); // ⇒ NotSigned
        let log = run_sweep(&obs, "ghcr.io/org/app:2", &mut store).await;
        let row = regression_row(&log, "ghcr.io/org/app").expect("a regression is recorded");
        assert_eq!(
            row.signature, "regression-unsigned-cold",
            "a cold-baseline regression is flagged weak (reduced intensity)"
        );
    }
}
