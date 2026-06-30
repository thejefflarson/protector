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
//! Scope (Stage 1): observation + recording only. The posture is recorded as the
//! low-cardinality status word on an `image-signature` row (the field is free-text, escaped
//! at render); the signer identity rides the row's reason, also escaped downstream. The
//! per-repo baseline (JEF-263), drift findings (JEF-264), and the Admission render (JEF-262)
//! consume this; they are NOT built here. State is the in-memory [`SigningObserver`] cache +
//! the bounded [`PolicyDecisionLog`] ring — no durable schema.

use std::sync::Arc;

use k8s_openapi::api::core::v1::Pod;

use super::observe::Snapshot;
use super::policy_log::{PolicyDecisionLog, PolicyDecisionRecord};
use crate::policies::signature::{PostureMap, SigningObserver, SigningPosture};

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
        SigningPosture::InvalidSignature => {
            "signature present but does not verify (untrusted/tampered chain)".to_string()
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

/// Run one signing-posture sweep over the snapshot's running pods and record the result.
/// A no-op (zero outbound calls, nothing recorded) when no observer is configured — so a
/// deploy without signature config behaves exactly as before. Bounded by the observer's
/// `max_images` cap + TTL cache, so a steady cluster re-sweeps for free and a churny one
/// can't amplify outbound verification.
pub async fn sweep(
    observer: Option<&SigningObserver>,
    snapshot: &Snapshot,
    log: &Arc<PolicyDecisionLog>,
) {
    let Some(observer) = observer else {
        return;
    };
    let images = snapshot_images(&snapshot.pods);
    if images.is_empty() {
        return;
    }
    let map = observer.sweep(images).await;
    record_postures(log, &map);
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;

    use super::*;
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
        sweep(Some(&obs), &snapshot, &log).await;
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
        sweep(Some(&obs), &snapshot, &log).await;
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
        sweep(None, &snapshot, &log).await;
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
        sweep(Some(&obs), &snapshot, &log).await;
        sweep(Some(&obs), &snapshot, &log).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the second sweep is served from the observer cache — zero new outbound calls"
        );
    }
}
