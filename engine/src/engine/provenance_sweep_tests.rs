//! Integration-style tests for the build-provenance sweep (JEF-275): posture recording, TOFU
//! provenance learning (augment-only), and provenance-change detection.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;

use super::*;
use crate::policies::signature::{
    Provenance, ProvenanceObserver, ProvenancePosture, Signer, SigningPosture,
};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const CI_BUILDER: &str = "https://github.com/org/app/.github/workflows/release.yml@refs/heads/main";
const ATTACKER_BUILDER: &str =
    "https://github.com/evil/app/.github/workflows/pwn.yml@refs/heads/main";

fn pod(images: &[&str]) -> Pod {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "demo", "namespace": "default"},
        "spec": {
            "containers": images.iter().map(|i| serde_json::json!({"name": "c", "image": i})).collect::<Vec<_>>(),
        }
    }))
    .expect("valid pod")
}

struct FakeObserver {
    postures: HashMap<String, ProvenancePosture>,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl ProvenanceObserver for FakeObserver {
    async fn observe_provenance(&self, image: &str) -> ProvenancePosture {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.postures
            .get(image)
            .cloned()
            .unwrap_or(ProvenancePosture::Absent)
    }
}

fn scanner(postures: Vec<(&str, ProvenancePosture)>) -> (ProvenanceScanner, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let fake = FakeObserver {
        postures: postures
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        calls: calls.clone(),
    };
    (
        ProvenanceScanner::new(Arc::new(fake), 32, Duration::from_secs(300)),
        calls,
    )
}

fn verified(source: &str, builder: &str) -> ProvenancePosture {
    ProvenancePosture::Verified(Provenance {
        source_repo: source.to_string(),
        builder: builder.to_string(),
    })
}

/// A store carrying an ESTABLISHED signing baseline for `ghcr.io/org/app` — so provenance (which is
/// augment-only) has a baseline to fold into.
fn established_store() -> SigningBaselineStore {
    let mut store = SigningBaselineStore::new();
    let signed = SigningPosture::Signed(Signer {
        identity: "https://github.com/org/app/.github/workflows/release.yml@refs/tags/v1".into(),
        issuer: Some("https://token.actions.githubusercontent.com".into()),
    });
    store.observe("ghcr.io/org/app@sha256:seed", &signed, 0);
    store.observe("ghcr.io/org/app@sha256:seed", &signed, 3 * DAY_MS);
    assert!(store.get("ghcr.io/org/app").unwrap().established);
    store
}

async fn run_sweep(
    scanner: &ProvenanceScanner,
    image: &str,
    store: &mut SigningBaselineStore,
) -> Arc<PolicyDecisionLog> {
    let snapshot = Snapshot {
        pods: vec![pod(&[image])],
        ..Default::default()
    };
    let log = Arc::new(PolicyDecisionLog::new());
    sweep(
        Some(scanner),
        &snapshot,
        &log,
        Some(store),
        &DecisionJournal::disabled(),
    )
    .await;
    log
}

fn row(log: &PolicyDecisionLog, subject: &str) -> Option<PolicyDecisionRecord> {
    log.snapshot().into_iter().find(|r| r.subject == subject)
}

#[tokio::test]
async fn records_posture_for_each_running_image() {
    let (sc, _c) = scanner(vec![
        (
            "ghcr.io/org/app:1",
            verified("github.com/org/app", CI_BUILDER),
        ),
        ("docker.io/library/postgres:16", ProvenancePosture::Absent),
    ]);
    let snapshot = Snapshot {
        pods: vec![pod(&["ghcr.io/org/app:1", "docker.io/library/postgres:16"])],
        ..Default::default()
    };
    let log = Arc::new(PolicyDecisionLog::new());
    sweep(
        Some(&sc),
        &snapshot,
        &log,
        None,
        &DecisionJournal::disabled(),
    )
    .await;
    let by_image: HashMap<_, _> = log
        .snapshot()
        .into_iter()
        .map(|r| (r.image.clone(), r))
        .collect();
    assert_eq!(
        by_image["ghcr.io/org/app:1"].signature,
        "provenance-verified"
    );
    assert!(
        by_image["ghcr.io/org/app:1"]
            .reason
            .contains("built by https://github.com/org/app")
    );
    // Absent provenance is the calm state — recorded honestly, never n/a, never an alarm.
    assert_eq!(
        by_image["docker.io/library/postgres:16"].signature,
        "no-provenance"
    );
    assert!(log.snapshot().iter().all(|r| r.decision == "allow"));
}

#[tokio::test]
async fn no_scanner_is_a_no_op() {
    let snapshot = Snapshot {
        pods: vec![pod(&["ghcr.io/org/app:1"])],
        ..Default::default()
    };
    let log = Arc::new(PolicyDecisionLog::new());
    sweep(None, &snapshot, &log, None, &DecisionJournal::disabled()).await;
    assert!(log.snapshot().is_empty(), "off ⇒ zero rows, zero egress");
}

#[tokio::test]
async fn absent_provenance_learns_nothing_and_never_alarms() {
    let (sc, _c) = scanner(vec![("ghcr.io/org/app:2", ProvenancePosture::Absent)]);
    let mut store = established_store();
    let log = run_sweep(&sc, "ghcr.io/org/app:2", &mut store).await;
    assert!(
        row(&log, "ProvenanceChange/ghcr.io/org/app").is_none(),
        "absent provenance is calm, never a change"
    );
    assert!(
        !store.get("ghcr.io/org/app").unwrap().has_provenance(),
        "absent provenance teaches no baseline"
    );
}

#[tokio::test]
async fn first_verified_provenance_learns_the_baseline_no_finding() {
    let (sc, _c) = scanner(vec![(
        "ghcr.io/org/app:2",
        verified("github.com/org/app", CI_BUILDER),
    )]);
    let mut store = established_store();
    let log = run_sweep(&sc, "ghcr.io/org/app:2", &mut store).await;
    assert!(
        row(&log, "ProvenanceChange/ghcr.io/org/app").is_none(),
        "cold-start TOFU is not a change"
    );
    let baseline = store.get("ghcr.io/org/app").unwrap();
    assert!(baseline.provenance_builders.contains(CI_BUILDER));
    assert!(baseline.provenance_sources.contains("github.com/org/app"));
}

#[tokio::test]
async fn a_new_builder_on_an_established_repo_records_a_change() {
    // Establish the provenance identity, then serve a different builder ⇒ provenance-change finding.
    let mut store = established_store();
    let (sc1, _) = scanner(vec![(
        "ghcr.io/org/app:1",
        verified("github.com/org/app", CI_BUILDER),
    )]);
    run_sweep(&sc1, "ghcr.io/org/app:1", &mut store).await;

    let (sc2, _) = scanner(vec![(
        "ghcr.io/org/app:2",
        verified("github.com/org/app", ATTACKER_BUILDER),
    )]);
    let log = run_sweep(&sc2, "ghcr.io/org/app:2", &mut store).await;
    let change = row(&log, "ProvenanceChange/ghcr.io/org/app").expect("a change is recorded");
    assert_eq!(change.signature, "provenance-change-established");
    assert_eq!(change.decision, "allow", "audit-only — still admitted");
    assert!(
        change
            .reason
            .contains(&format!("built by {ATTACKER_BUILDER}"))
    );
    assert!(
        change.reason.contains(&format!("before: {CI_BUILDER}")),
        "the before builder is stated in full"
    );
}

#[tokio::test]
async fn a_known_rebuild_records_no_change() {
    let mut store = established_store();
    let (sc1, _) = scanner(vec![(
        "ghcr.io/org/app:1",
        verified("github.com/org/app", CI_BUILDER),
    )]);
    run_sweep(&sc1, "ghcr.io/org/app:1", &mut store).await;
    // A new digest, same source+builder ⇒ continuous.
    let (sc2, _) = scanner(vec![(
        "ghcr.io/org/app:2",
        verified("github.com/org/app", CI_BUILDER),
    )]);
    let log = run_sweep(&sc2, "ghcr.io/org/app:2", &mut store).await;
    assert!(
        row(&log, "ProvenanceChange/ghcr.io/org/app").is_none(),
        "a known rebuild is continuous — no finding"
    );
}

#[tokio::test]
async fn provenance_without_a_signing_baseline_is_not_learned() {
    // A repo with NO signing baseline (augment-only): verified provenance neither learns nor alarms.
    let (sc, _c) = scanner(vec![(
        "ghcr.io/new/app:1",
        verified("github.com/new/app", CI_BUILDER),
    )]);
    let mut store = SigningBaselineStore::new();
    let log = run_sweep(&sc, "ghcr.io/new/app:1", &mut store).await;
    assert!(store.get("ghcr.io/new/app").is_none());
    assert!(row(&log, "ProvenanceChange/ghcr.io/new/app").is_none());
    // The posture itself is still recorded honestly.
    assert_eq!(
        row(&log, "Provenance/ghcr.io/new/app:1").unwrap().signature,
        "provenance-verified"
    );
}
