//! Unit tests for SLSA build-provenance observation (JEF-275): the pure predicate parser, the
//! posture classifier, and the bounded/cached scanner.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;

use super::*;

fn facts(predicate_type: &str, predicate: serde_json::Value, keyless: bool) -> ProvenanceFacts {
    ProvenanceFacts {
        predicate_type: predicate_type.to_string(),
        predicate: Some(predicate),
        keyless_verified: keyless,
    }
}

fn slsa_v1_predicate() -> serde_json::Value {
    json!({
        "buildDefinition": {
            "buildType": "https://actions.github.io/buildtypes/workflow/v1",
            "externalParameters": {
                "workflow": {
                    "ref": "refs/heads/main",
                    "repository": "https://github.com/org/app",
                    "path": ".github/workflows/release.yml"
                }
            }
        },
        "runDetails": {
            "builder": {
                "id": "https://github.com/org/app/.github/workflows/release.yml@refs/heads/main"
            }
        }
    })
}

fn slsa_v02_predicate() -> serde_json::Value {
    json!({
        "builder": { "id": "https://github.com/org/app/.github/workflows/release.yml@refs/tags/v1" },
        "buildType": "https://github.com/slsa-framework/slsa-github-generator/...",
        "invocation": {
            "configSource": {
                "uri": "git+https://github.com/org/app@refs/tags/v1",
                "entryPoint": ".github/workflows/release.yml"
            }
        },
        "materials": [
            { "uri": "git+https://github.com/org/app@refs/tags/v1", "digest": { "sha1": "abc" } }
        ]
    })
}

// ---- parse_slsa_predicate -----------------------------------------------------------------

#[test]
fn parses_slsa_v1_source_and_builder() {
    let p = parse_slsa_predicate(SLSA_PROVENANCE_V1, &slsa_v1_predicate())
        .expect("v1 predicate yields provenance");
    assert_eq!(p.source_repo, "github.com/org/app");
    assert_eq!(
        p.builder,
        "https://github.com/org/app/.github/workflows/release.yml@refs/heads/main"
    );
}

#[test]
fn parses_slsa_v02_source_and_builder() {
    let p = parse_slsa_predicate(SLSA_PROVENANCE_V02, &slsa_v02_predicate())
        .expect("v0.2 predicate yields provenance");
    // The `git+https://…@ref` config-source URI is cleaned to a stable repo identity.
    assert_eq!(p.source_repo, "github.com/org/app");
    assert_eq!(
        p.builder,
        "https://github.com/org/app/.github/workflows/release.yml@refs/tags/v1"
    );
}

#[test]
fn v1_falls_back_to_resolved_dependencies_for_source() {
    let predicate = json!({
        "buildDefinition": {
            "resolvedDependencies": [
                { "uri": "git+https://github.com/org/fallback@refs/heads/main" }
            ]
        },
        "runDetails": { "builder": { "id": "https://builder.example/ci" } }
    });
    let p = parse_slsa_predicate(SLSA_PROVENANCE_V1, &predicate).expect("provenance");
    assert_eq!(p.source_repo, "github.com/org/fallback");
    assert_eq!(p.builder, "https://builder.example/ci");
}

#[test]
fn no_builder_id_yields_none() {
    // A predicate with no builder identity cannot confer a trusted build.
    let predicate = json!({ "buildDefinition": { "externalParameters": {} } });
    assert!(parse_slsa_predicate(SLSA_PROVENANCE_V1, &predicate).is_none());
}

#[test]
fn unknown_predicate_type_yields_none() {
    assert!(
        parse_slsa_predicate("https://example.com/other/v1", &slsa_v1_predicate()).is_none(),
        "a non-SLSA predicate type is never read as provenance"
    );
}

#[test]
fn builder_id_is_the_source_fallback_when_no_source_uri() {
    let predicate = json!({
        "runDetails": { "builder": { "id": "https://github.com/org/app/.github/workflows/x.yml@refs/heads/main" } }
    });
    let p = parse_slsa_predicate(SLSA_PROVENANCE_V1, &predicate).expect("provenance");
    // The builder id is kept verbatim (the identity, ref included); only the derived source repo is
    // cleaned (scheme + trailing git ref stripped).
    assert_eq!(p.source_repo, "github.com/org/app/.github/workflows/x.yml");
    assert_eq!(
        p.builder,
        "https://github.com/org/app/.github/workflows/x.yml@refs/heads/main"
    );
}

// ---- classify_provenance ------------------------------------------------------------------

#[test]
fn verified_keyless_slsa_layer_is_verified() {
    let posture = classify_provenance(&[facts(SLSA_PROVENANCE_V1, slsa_v1_predicate(), true)]);
    match &posture {
        ProvenancePosture::Verified(p) => assert_eq!(p.source_repo, "github.com/org/app"),
        other => panic!("expected Verified, got {other:?}"),
    }
    assert_eq!(posture.status(), "provenance-verified");
}

#[test]
fn slsa_layer_without_keyless_verification_is_unverifiable() {
    // An attestation artifact is present but its cert did not chain / Rekor did not verify.
    let posture = classify_provenance(&[facts(SLSA_PROVENANCE_V1, slsa_v1_predicate(), false)]);
    assert_eq!(posture, ProvenancePosture::Unverifiable);
    assert!(
        posture.provenance().is_none(),
        "unverifiable never confers a trusted build"
    );
}

#[test]
fn verified_layer_with_no_extractable_builder_is_unverifiable_not_verified() {
    // SECURITY: verified crypto but no builder identity must NOT read as a trusted build.
    let empty = json!({ "buildDefinition": {} });
    let posture = classify_provenance(&[facts(SLSA_PROVENANCE_V1, empty, true)]);
    assert_eq!(posture, ProvenancePosture::Unverifiable);
}

#[test]
fn no_slsa_layers_is_absent() {
    assert_eq!(classify_provenance(&[]), ProvenancePosture::Absent);
    assert_eq!(ProvenancePosture::Absent.status(), "no-provenance");
}

#[test]
fn a_verified_layer_wins_over_an_unverifiable_one() {
    let posture = classify_provenance(&[
        facts(SLSA_PROVENANCE_V1, json!({ "buildDefinition": {} }), false),
        facts(SLSA_PROVENANCE_V1, slsa_v1_predicate(), true),
    ]);
    assert!(matches!(posture, ProvenancePosture::Verified(_)));
}

#[test]
fn is_slsa_predicate_type_recognizes_both_versions() {
    assert!(is_slsa_predicate_type(SLSA_PROVENANCE_V1));
    assert!(is_slsa_predicate_type(SLSA_PROVENANCE_V02));
    assert!(!is_slsa_predicate_type(
        "https://sigstore.dev/cosign/sign/v1"
    ));
}

#[test]
fn checking_is_the_only_non_resting_posture() {
    assert!(!ProvenancePosture::Checking.is_resting());
    assert!(ProvenancePosture::Absent.is_resting());
    assert!(ProvenancePosture::Unverifiable.is_resting());
    assert!(
        ProvenancePosture::Verified(Provenance {
            source_repo: "github.com/org/app".into(),
            builder: "b".into(),
        })
        .is_resting()
    );
}

// ---- ProvenanceScanner (bounded + cached) -------------------------------------------------

struct FakeObserver {
    posture: ProvenancePosture,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl ProvenanceObserver for FakeObserver {
    async fn observe_provenance(&self, _image: &str) -> ProvenancePosture {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.posture.clone()
    }
}

fn scanner(posture: ProvenancePosture) -> (ProvenanceScanner, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let fake = FakeObserver {
        posture,
        calls: calls.clone(),
    };
    (
        ProvenanceScanner::new(Arc::new(fake), 32, Duration::from_secs(300)),
        calls,
    )
}

#[tokio::test]
async fn resting_posture_is_cached_zero_extra_calls() {
    let (scanner, calls) = scanner(ProvenancePosture::Absent);
    scanner.observe("ghcr.io/org/app:1").await;
    scanner.observe("ghcr.io/org/app:1").await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "second observe hits the cache"
    );
}

#[tokio::test]
async fn checking_posture_is_not_cached() {
    let (scanner, calls) = scanner(ProvenancePosture::Checking);
    scanner.observe("ghcr.io/org/app:1").await;
    scanner.observe("ghcr.io/org/app:1").await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a transient checking blip retries next observation"
    );
}

#[tokio::test]
async fn sweep_caps_distinct_images() {
    let calls = Arc::new(AtomicUsize::new(0));
    let fake = FakeObserver {
        posture: ProvenancePosture::Absent,
        calls: calls.clone(),
    };
    let scanner = ProvenanceScanner::new(Arc::new(fake), 2, Duration::from_secs(300));
    let map = scanner
        .sweep(["a:1", "b:1", "c:1", "a:1"]) // 3 distinct, cap 2
        .await;
    assert_eq!(map.len(), 2, "at most max_images distinct images observed");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
