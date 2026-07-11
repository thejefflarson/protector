//! Acceptance tests for the Rekor reconciliation pass (JEF-266): history-seed (corroboration),
//! no-history local-only fallback, divergence in both directions, unreachable degrade, and the
//! off-by-default no-op. The transparency log is a fake [`RekorClient`] keyed by image, so the
//! whole rule table runs with no network.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use async_trait::async_trait;

use super::*;
use crate::engine::journal::DecisionJournal;
use crate::engine::policy_log::PolicyDecisionLog;
use crate::engine::state::SigningBaselineStore;
use crate::engine::supply_chain::signing_baseline_strength::{
    CORROBORATED_WORD, STRENGTH_SUBJECT_PREFIX,
};
use crate::policies::signature::{
    PostureMap, RekorClient, RekorHistory, RekorLane, Signer, SigningPosture,
};

const CI: &str = "https://github.com/org/app/.github/workflows/release.yaml@refs/tags/v1";
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// A fake transparency log keyed by image ref: `Ok(history)` for a scripted entry, or `Err`
/// (unreachable) for an image mapped to `None`. An unmapped image reads as "no log entry".
struct FakeLog {
    entries: HashMap<String, Option<RekorHistory>>,
}

#[async_trait]
impl RekorClient for FakeLog {
    async fn lookup(&self, image: &str, _identity: Option<&str>) -> Result<RekorHistory> {
        match self.entries.get(image) {
            Some(Some(history)) => Ok(history.clone()),
            Some(None) => bail!("rekor unreachable"),
            None => Ok(RekorHistory::default()), // definitively not in the log
        }
    }
}

fn lane(entries: Vec<(&str, Option<RekorHistory>)>) -> RekorLane {
    let fake = FakeLog {
        entries: entries
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    };
    RekorLane::new(Arc::new(fake), Duration::from_secs(3600))
}

fn in_log() -> RekorHistory {
    RekorHistory {
        signed_in_log: true,
        identities: vec![],
    }
}

fn not_in_log() -> RekorHistory {
    RekorHistory::default()
}

fn signed(identity: &str) -> SigningPosture {
    SigningPosture::Signed(Signer {
        identity: identity.to_string(),
        issuer: Some("https://token.actions.githubusercontent.com".to_string()),
    })
}

fn posture_map(pairs: Vec<(&str, SigningPosture)>) -> PostureMap {
    let mut map = PostureMap::new();
    for (image, posture) in pairs {
        map.record(image, posture);
    }
    map
}

/// A store carrying a cold (local-only, not corroborated) baseline for `ghcr.io/org/app`.
fn cold_store() -> SigningBaselineStore {
    let mut store = SigningBaselineStore::new();
    store.observe("ghcr.io/org/app@sha256:seed", &signed(CI), 0);
    let b = store.get("ghcr.io/org/app").unwrap();
    assert!(!b.log_corroborated && !b.established);
    store
}

fn regression_row(
    log: &PolicyDecisionLog,
    repo: &str,
) -> Option<crate::engine::policy_log::PolicyDecisionRecord> {
    log.snapshot()
        .into_iter()
        .find(|r| r.subject == format!("{REGRESSION_SUBJECT_PREFIX}{repo}"))
}

#[tokio::test]
async fn history_seed_marks_the_baseline_log_corroborated() {
    // A repo the public log already carries an entry for inherits real provenance: its baseline is
    // marked stronger than local-only, and a corroborated strength row surfaces.
    let mut store = cold_store();
    let map = posture_map(vec![("ghcr.io/org/app:2", signed(CI))]);
    let l = lane(vec![("ghcr.io/org/app:2", Some(in_log()))]);
    let log = PolicyDecisionLog::new();
    reconcile(
        Some(&l),
        &map,
        &log,
        Some(&mut store),
        &DecisionJournal::disabled(),
    )
    .await;
    assert!(
        store.get("ghcr.io/org/app").unwrap().log_corroborated,
        "the log-corroborated baseline is stronger than local-only"
    );
    let strength = log
        .snapshot()
        .into_iter()
        .find(|r| r.subject == format!("{STRENGTH_SUBJECT_PREFIX}ghcr.io/org/app"))
        .expect("a strength row is recorded");
    assert_eq!(strength.signature, CORROBORATED_WORD);
    // Corroboration is not a divergence.
    assert!(regression_row(&log, "ghcr.io/org/app").is_none());
}

#[tokio::test]
async fn no_history_leaves_the_baseline_local_only_without_a_divergence() {
    // A signed image the log has no entry for, on a repo we never corroborated, is the honest
    // local-only fallback — weaker, but NOT a divergence (no false-positive tampering alarm).
    let mut store = cold_store();
    let map = posture_map(vec![("ghcr.io/org/app:2", signed(CI))]);
    let l = lane(vec![("ghcr.io/org/app:2", Some(not_in_log()))]);
    let log = PolicyDecisionLog::new();
    reconcile(
        Some(&l),
        &map,
        &log,
        Some(&mut store),
        &DecisionJournal::disabled(),
    )
    .await;
    assert!(
        !store.get("ghcr.io/org/app").unwrap().log_corroborated,
        "no log history ⇒ the baseline stays local-only (weaker)"
    );
    assert!(
        regression_row(&log, "ghcr.io/org/app").is_none(),
        "a genuinely no-history signed image is a fallback, never a divergence"
    );
}

#[tokio::test]
async fn divergence_log_signed_registry_unsigned() {
    // The log remembers a signature for an artifact the registry now serves UNSIGNED — tampering.
    let mut store = cold_store();
    let map = posture_map(vec![("ghcr.io/org/app:2", SigningPosture::NotSigned)]);
    let l = lane(vec![("ghcr.io/org/app:2", Some(in_log()))]);
    let log = PolicyDecisionLog::new();
    reconcile(
        Some(&l),
        &map,
        &log,
        Some(&mut store),
        &DecisionJournal::disabled(),
    )
    .await;
    let row = regression_row(&log, "ghcr.io/org/app").expect("a divergence finding is recorded");
    assert_eq!(row.signature, "regression-divergence-log-cold");
    assert_eq!(row.decision, "allow", "audit-only — still admitted");
    assert!(row.reason.contains("registry\u{2194}log divergence"));
    assert!(row.reason.contains("registry now serves unsigned"));
}

#[tokio::test]
async fn divergence_registry_signed_not_in_log_on_a_corroborated_repo() {
    // A repo we KNOW logs (already corroborated) suddenly serves a signature absent from the log.
    let mut store = cold_store();
    assert!(store.mark_corroborated("ghcr.io/org/app"));
    let map = posture_map(vec![("ghcr.io/org/app:3", signed(CI))]);
    let l = lane(vec![("ghcr.io/org/app:3", Some(not_in_log()))]);
    let log = PolicyDecisionLog::new();
    reconcile(
        Some(&l),
        &map,
        &log,
        Some(&mut store),
        &DecisionJournal::disabled(),
    )
    .await;
    let row = regression_row(&log, "ghcr.io/org/app").expect("a divergence finding is recorded");
    assert_eq!(row.signature, "regression-divergence-registry-cold");
    assert!(row.reason.contains("no entry for"));
}

#[tokio::test]
async fn established_baseline_makes_a_divergence_strong() {
    // The strength token rides the baseline's established flag, exactly like a regression.
    let mut store = SigningBaselineStore::new();
    store.observe("ghcr.io/org/app@sha256:seed", &signed(CI), 0);
    store.observe("ghcr.io/org/app@sha256:seed", &signed(CI), 3 * DAY_MS);
    assert!(store.get("ghcr.io/org/app").unwrap().established);
    let map = posture_map(vec![("ghcr.io/org/app:2", SigningPosture::NotSigned)]);
    let l = lane(vec![("ghcr.io/org/app:2", Some(in_log()))]);
    let log = PolicyDecisionLog::new();
    reconcile(
        Some(&l),
        &map,
        &log,
        Some(&mut store),
        &DecisionJournal::disabled(),
    )
    .await;
    let row = regression_row(&log, "ghcr.io/org/app").unwrap();
    assert_eq!(row.signature, "regression-divergence-log-established");
}

#[tokio::test]
async fn an_unreachable_log_degrades_to_local_only_never_a_false_clean() {
    // The lane returns Err ⇒ this image is skipped: no corroboration, no divergence, no false clean.
    let mut store = cold_store();
    assert!(store.mark_corroborated("ghcr.io/org/app"));
    let map = posture_map(vec![("ghcr.io/org/app:2", SigningPosture::NotSigned)]);
    let l = lane(vec![("ghcr.io/org/app:2", None)]); // None ⇒ unreachable
    let log = PolicyDecisionLog::new();
    reconcile(
        Some(&l),
        &map,
        &log,
        Some(&mut store),
        &DecisionJournal::disabled(),
    )
    .await;
    assert!(
        regression_row(&log, "ghcr.io/org/app").is_none(),
        "an unreachable log never fabricates a divergence"
    );
}

#[tokio::test]
async fn a_disabled_lane_is_a_no_op_zero_egress() {
    let mut store = cold_store();
    let map = posture_map(vec![("ghcr.io/org/app:2", signed(CI))]);
    let log = PolicyDecisionLog::new();
    reconcile(
        None,
        &map,
        &log,
        Some(&mut store),
        &DecisionJournal::disabled(),
    )
    .await;
    assert!(log.snapshot().is_empty(), "no lane ⇒ nothing recorded");
    assert!(!store.get("ghcr.io/org/app").unwrap().log_corroborated);
}

#[test]
fn divergence_is_pure_over_posture_history_and_corroboration() {
    let signed_posture = signed(CI);
    // agreement — both signed
    assert_eq!(divergence(&signed_posture, &in_log(), false), None);
    // agreement — both unsigned
    assert_eq!(
        divergence(&SigningPosture::NotSigned, &not_in_log(), false),
        None
    );
    // log has it, registry unsigned ⇒ divergence (no corroboration needed)
    assert_eq!(
        divergence(&SigningPosture::NotSigned, &in_log(), false),
        Some(Divergence::LogSignedRegistryUnsigned)
    );
    // registry signed, not in log, repo NOT corroborated ⇒ fallback, no divergence
    assert_eq!(divergence(&signed_posture, &not_in_log(), false), None);
    // registry signed, not in log, repo corroborated ⇒ divergence
    assert_eq!(
        divergence(&signed_posture, &not_in_log(), true),
        Some(Divergence::RegistrySignedNotInLog)
    );
    // invalid / checking are never divergence
    assert_eq!(
        divergence(&SigningPosture::InvalidSignature, &in_log(), true),
        None
    );
    assert_eq!(divergence(&SigningPosture::Checking, &in_log(), true), None);
}
