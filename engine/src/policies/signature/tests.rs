//! Tests for the signature module: the gated [`SignaturePolicy`] (behavior preserved
//! through the JEF-261 split) and ADR-0020 Stage 1 signing-posture observation.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use kube::core::DynamicObject;
use kube::core::admission::AdmissionRequest;
use serde_json::json;
use sigstore::registry::Auth;

use super::posture::{SignatureObserver, Signer, SigningObserver, SigningPosture};
use super::{
    CosignChecker, Decision, EnforceScope, Policy, Result, SignatureChecker, SignaturePolicy,
    normalize_registry_host, pod_images,
};

/// Enforce everywhere the test pods live (namespace "default"), or nowhere.
fn scope(enforce: bool) -> EnforceScope {
    if enforce {
        EnforceScope::new(HashSet::from(["default".to_string()]), vec![])
    } else {
        EnforceScope::default()
    }
}

fn pod_request(images: &[&str]) -> AdmissionRequest<DynamicObject> {
    let containers: Vec<_> = images
        .iter()
        .enumerate()
        .map(|(i, img)| json!({"name": format!("c{i}"), "image": img}))
        .collect();
    let review: kube::core::admission::AdmissionReview<DynamicObject> =
        serde_json::from_value(json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "u",
                "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "resource": {"group": "", "version": "v1", "resource": "pods"},
                "name": "demo",
                "namespace": "default",
                "operation": "CREATE",
                "userInfo": {},
                "object": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "demo"},
                    "spec": {"containers": containers}
                }
            }
        }))
        .expect("valid review");
    review.try_into().expect("has request")
}

/// A checker with canned verdicts; `Err` for any image not listed.
struct FakeChecker(HashMap<String, bool>);

#[async_trait]
impl SignatureChecker for FakeChecker {
    async fn is_signed(&self, image: &str) -> Result<bool> {
        self.0
            .get(image)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("no verdict for {image}"))
    }
}

fn policy(verdicts: &[(&str, bool)], enforce: bool) -> SignaturePolicy {
    let map = verdicts.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    SignaturePolicy::new(
        Arc::new(FakeChecker(map)),
        vec!["ghcr.io/thejefflarson/".to_string()],
        scope(enforce),
        32,
        Duration::from_secs(300),
    )
}

#[test]
fn extracts_all_container_images() {
    let obj: DynamicObject = serde_json::from_value(json!({
        "apiVersion": "v1", "kind": "Pod", "metadata": {"name": "x"},
        "spec": {
            "initContainers": [{"name": "i", "image": "ghcr.io/thejefflarson/init:1"}],
            "containers": [{"name": "a", "image": "ghcr.io/thejefflarson/app:1"}],
            "ephemeralContainers": [{"name": "e", "image": "busybox"}]
        }
    }))
    .unwrap();
    assert_eq!(
        pod_images(&obj),
        vec![
            "ghcr.io/thejefflarson/app:1",
            "ghcr.io/thejefflarson/init:1",
            "busybox"
        ]
    );
}

#[test]
fn registry_host_case_is_normalized_for_gating() {
    assert_eq!(
        normalize_registry_host("GHCR.IO/thejefflarson/app:1"),
        "ghcr.io/thejefflarson/app:1"
    );
    // No host segment → left untouched.
    assert_eq!(normalize_registry_host("postgres:16"), "postgres:16");
}

#[test]
fn host_spelling_variants_canonicalize_to_the_gated_form() {
    // A trailing FQDN dot, an explicit default port, and case all resolve to
    // the same image at the runtime; each must reduce to the gated prefix so
    // it can't slip past `starts_with`.
    let canonical = "ghcr.io/thejefflarson/x";
    for variant in [
        "ghcr.io./thejefflarson/x",
        "ghcr.io:443/thejefflarson/x",
        "ghcr.io:80/thejefflarson/x",
        "GHCR.IO/thejefflarson/x",
        "ghcr.io.:443/thejefflarson/x",
    ] {
        assert_eq!(
            normalize_registry_host(variant),
            canonical,
            "{variant} did not canonicalize to {canonical}"
        );
    }
    // A non-default port is part of the identity — preserved.
    assert_eq!(
        normalize_registry_host("ghcr.io:5000/thejefflarson/x"),
        "ghcr.io:5000/thejefflarson/x"
    );
}

#[test]
fn host_spelling_variants_are_all_gated() {
    let p = policy(&[], true);
    for variant in [
        "ghcr.io/thejefflarson/x:1",
        "ghcr.io./thejefflarson/x:1",
        "ghcr.io:443/thejefflarson/x:1",
        "GHCR.IO/thejefflarson/x:1",
    ] {
        assert!(p.gated(variant), "{variant} escaped the gate");
    }
}

#[test]
fn identity_regex_anchors_every_alternation_branch() {
    // `^a|b` must NOT match `prefix-b-suffix`: the second branch has to be
    // anchored too, or a cert SAN merely *containing* a trusted prefix is
    // accepted.
    let checker = CosignChecker::new(
        "^https://github.com/org/|https://gitlab.com/org/",
        "https://token.actions.githubusercontent.com".to_string(),
        Auth::Anonymous,
        std::env::temp_dir().join(format!("protector-anchor-{}", std::process::id())),
        Duration::from_secs(5),
    )
    .expect("regex compiles");
    let identity = checker.identity_regex();
    assert!(
        !identity.is_match("https://evil.example/prefix-https://gitlab.com/org/-suffix"),
        "second alternation branch matched mid-string — not anchored"
    );
    // The legitimate identities still match at the start.
    assert!(identity.is_match("https://github.com/org/repo"));
    assert!(identity.is_match("https://gitlab.com/org/repo"));
    // And a SAN that merely starts with a near-miss does not match.
    assert!(!identity.is_match("https://gitlab.com/other/repo"));
}

#[test]
fn new_creates_the_missing_tuf_cache_dir() {
    // The bug: sigstore-rs won't mkdir the TUF cache, so a non-existent
    // (emptyDir subdir) path made every verification fail with ENOENT. new()
    // must create it. (No network — the TUF fetch is lazy in trust_root.)
    let base = std::env::temp_dir().join(format!("protector-tuf-{}", std::process::id()));
    let cache = base.join("sigstore");
    let _ = std::fs::remove_dir_all(&base);
    assert!(!cache.exists());
    let checker = CosignChecker::new(
        "^https://github\\.com/thejefflarson/",
        "https://token.actions.githubusercontent.com".to_string(),
        Auth::Anonymous,
        cache.clone(),
        Duration::from_secs(5),
    );
    assert!(checker.is_ok(), "new() failed: {:?}", checker.err());
    assert!(cache.is_dir(), "new() must create the TUF cache dir");
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test]
async fn allows_ungated_third_party_images() {
    // postgres isn't ours; never checked, so the (absent) verdict can't error.
    let p = policy(&[], true);
    assert!(matches!(
        p.evaluate(&pod_request(&["docker.io/library/postgres:16"]))
            .await,
        Decision::Allow
    ));
}

#[tokio::test]
async fn allows_signed_gated_image() {
    let p = policy(&[("ghcr.io/thejefflarson/app:1", true)], true);
    assert!(matches!(
        p.evaluate(&pod_request(&["ghcr.io/thejefflarson/app:1"]))
            .await,
        Decision::Allow
    ));
}

#[tokio::test]
async fn denies_unsigned_gated_image_when_enforcing() {
    let p = policy(&[("ghcr.io/thejefflarson/app:1", false)], true);
    match p
        .evaluate(&pod_request(&["ghcr.io/thejefflarson/app:1"]))
        .await
    {
        Decision::Deny { reason } => assert!(reason.contains("ghcr.io/thejefflarson/app:1")),
        other => panic!("expected deny, got {other:?}"),
    }
}

#[tokio::test]
async fn audits_unsigned_gated_image_in_audit_mode() {
    let p = policy(&[("ghcr.io/thejefflarson/app:1", false)], false);
    assert!(matches!(
        p.evaluate(&pod_request(&["ghcr.io/thejefflarson/app:1"]))
            .await,
        Decision::Audit { .. }
    ));
}

#[tokio::test]
async fn case_variant_registry_host_is_still_gated() {
    // The uppercase-host ref resolves to the same first-party image; it must
    // not escape the gate. The checker reports it unsigned → enforce denies.
    let p = policy(&[("GHCR.IO/thejefflarson/app:1", false)], true);
    match p
        .evaluate(&pod_request(&["GHCR.IO/thejefflarson/app:1"]))
        .await
    {
        Decision::Deny { reason } => assert!(reason.contains("GHCR.IO/thejefflarson/app:1")),
        other => panic!("case-variant host evaded the gate: {other:?}"),
    }
}

#[tokio::test]
async fn denies_pod_exceeding_image_cap_when_enforcing() {
    let verdicts: Vec<(String, bool)> = (0..40)
        .map(|i| (format!("ghcr.io/thejefflarson/app{i}:1"), true))
        .collect();
    let map = verdicts.into_iter().collect();
    let p = SignaturePolicy::new(
        Arc::new(FakeChecker(map)),
        vec!["ghcr.io/thejefflarson/".to_string()],
        scope(true),
        32,
        Duration::from_secs(300),
    );
    let refs: Vec<String> = (0..40)
        .map(|i| format!("ghcr.io/thejefflarson/app{i}:1"))
        .collect();
    let refs: Vec<&str> = refs.iter().map(|s| s.as_str()).collect();
    match p.evaluate(&pod_request(&refs)).await {
        Decision::Deny { reason } => assert!(reason.contains("max 32")),
        other => panic!("expected deny, got {other:?}"),
    }
}

/// A checker that COUNTS calls to `is_signed`, so a test can prove the digest cache spares
/// repeated verification across the enforce + shadow paths (JEF-246's zero-egress constraint).
struct CountingChecker {
    signed: bool,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl SignatureChecker for CountingChecker {
    async fn is_signed(&self, _image: &str) -> Result<bool> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.signed)
    }
}

#[tokio::test]
async fn shadow_evaluate_out_of_scope_unsigned_is_would_fail() {
    // JEF-246: an out-of-scope (audit-only) unsigned gated image shadow-evaluates to
    // would-fail — enforcing would deny — even though `evaluate` only audits.
    let p = policy(&[("ghcr.io/thejefflarson/app:1", false)], false);
    let req = pod_request(&["ghcr.io/thejefflarson/app:1"]);
    assert!(matches!(p.evaluate(&req).await, Decision::Audit { .. }));
    let v = p.shadow_evaluate(&req).await;
    assert_eq!(v.status(), "would-fail");
}

#[tokio::test]
async fn shadow_evaluate_signed_out_of_scope_is_would_pass() {
    // A signed gated image out of enforced scope: `would-pass` (out of scope, shadow-checked,
    // would pass) — not empty.
    let p = policy(&[("ghcr.io/thejefflarson/app:1", true)], false);
    let v = p
        .shadow_evaluate(&pod_request(&["ghcr.io/thejefflarson/app:1"]))
        .await;
    assert_eq!(v.status(), "would-pass");
}

#[tokio::test]
async fn shadow_evaluate_signed_in_scope_is_verified() {
    let p = policy(&[("ghcr.io/thejefflarson/app:1", true)], true);
    let v = p
        .shadow_evaluate(&pod_request(&["ghcr.io/thejefflarson/app:1"]))
        .await;
    assert_eq!(v.status(), "verified");
}

#[tokio::test]
async fn ungated_image_has_no_signature_opinion() {
    // The signature gate has no opinion on a third-party image — NotApplicable, an empty
    // status (so the strip doesn't count it).
    let p = policy(&[], false);
    let v = p
        .shadow_evaluate(&pod_request(&["docker.io/library/postgres:16"]))
        .await;
    assert_eq!(v.status(), "");
}

#[tokio::test]
async fn digest_cache_shares_verification_across_enforce_and_shadow_paths() {
    // The zero-egress constraint (JEF-246): shadow-verifying every request must not repeat
    // verification per replica/pass. The enforce path populates the cache; the shadow path
    // (and a second enforce) reuse it — the checker is hit ONCE for the image.
    let calls = Arc::new(AtomicUsize::new(0));
    let p = SignaturePolicy::new(
        Arc::new(CountingChecker {
            signed: true,
            calls: calls.clone(),
        }),
        vec!["ghcr.io/thejefflarson/".to_string()],
        scope(true),
        32,
        Duration::from_secs(300),
    );
    let req = pod_request(&["ghcr.io/thejefflarson/app:1"]);
    let _ = p.evaluate(&req).await; // first call: verifies + caches
    let _ = p.shadow_evaluate(&req).await; // cache hit, no new egress
    let _ = p.evaluate(&req).await; // cache hit
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the image is verified once; replica/pass + shadow re-use the digest cache"
    );
}

// ---------------------------------------------------------------------------
// ADR-0020 Stage 1: signing-posture observation (JEF-261)
// ---------------------------------------------------------------------------

/// A fake observer with canned per-image postures, and a call counter so a test can prove
/// the cache spares repeated outbound observation. An image with no canned posture is
/// reported `NotSigned` (the safe "no signature found" default for an unlisted image).
struct FakeObserver {
    postures: HashMap<String, SigningPosture>,
    calls: Arc<AtomicUsize>,
}

impl FakeObserver {
    fn new(postures: Vec<(&str, SigningPosture)>) -> Self {
        Self {
            postures: postures
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
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

fn signer(identity: &str, issuer: &str) -> Signer {
    Signer {
        identity: identity.to_string(),
        issuer: Some(issuer.to_string()),
    }
}

#[tokio::test]
async fn observes_signed_image_with_signer_identity_and_issuer_no_regex_configured() {
    // Acceptance: a signed image returns signed + signer identity + issuer, with NO identity
    // regex configured (the observer takes none — the Fulcio/Rekor chain is the trust anchor).
    let observer = SigningObserver::new(
        Arc::new(FakeObserver::new(vec![(
            "ghcr.io/distroless/base:latest",
            SigningPosture::Signed(signer(
                "https://github.com/GoogleContainerTools/distroless/.github/workflows/release.yaml@refs/heads/main",
                "https://token.actions.githubusercontent.com",
            )),
        )])),
        32,
        Duration::from_secs(300),
    );
    let posture = observer.observe("ghcr.io/distroless/base:latest").await;
    let s = posture.signer().expect("signed posture carries a signer");
    assert_eq!(posture.status(), "signed");
    assert!(s.identity.contains("GoogleContainerTools/distroless"));
    assert_eq!(
        s.issuer.as_deref(),
        Some("https://token.actions.githubusercontent.com")
    );
}

#[tokio::test]
async fn observes_invalid_signature_distinct_from_not_signed() {
    // Acceptance: a present-but-unverifiable signature returns invalid-signature, distinct
    // from not-signed.
    let observer = SigningObserver::new(
        Arc::new(FakeObserver::new(vec![
            ("ghcr.io/org/tampered:1", SigningPosture::InvalidSignature),
            ("docker.io/library/postgres:16", SigningPosture::NotSigned),
        ])),
        32,
        Duration::from_secs(300),
    );
    assert_eq!(
        observer.observe("ghcr.io/org/tampered:1").await.status(),
        "invalid-signature"
    );
    assert_eq!(
        observer
            .observe("docker.io/library/postgres:16")
            .await
            .status(),
        "not-signed"
    );
    assert_ne!(
        SigningPosture::InvalidSignature,
        SigningPosture::NotSigned,
        "invalid-signature must be a distinct state from not-signed"
    );
}

#[tokio::test]
async fn observes_not_signed_image() {
    // Acceptance: an unsigned image returns not-signed (here via the unlisted-image default).
    let observer = SigningObserver::new(
        Arc::new(FakeObserver::new(vec![])),
        32,
        Duration::from_secs(300),
    );
    assert_eq!(
        observer.observe("docker.io/library/redis:7").await.status(),
        "not-signed"
    );
}

#[tokio::test]
async fn transient_error_is_checking_never_a_resting_posture() {
    // Acceptance: a registry/transparency-log error is a transient "checking" state,
    // distinguishable from all three resting states and never a false clean.
    let observer = SigningObserver::new(
        Arc::new(FakeObserver::new(vec![(
            "ghcr.io/org/unreachable:1",
            SigningPosture::Checking,
        )])),
        32,
        Duration::from_secs(300),
    );
    let posture = observer.observe("ghcr.io/org/unreachable:1").await;
    assert_eq!(posture.status(), "checking");
    assert!(!posture.is_resting(), "checking is not a resting posture");
    assert_eq!(posture.signer(), None, "checking is never read as signed");
}

#[tokio::test]
async fn checking_is_not_cached_so_it_is_retried_then_resolves() {
    // The transient state must not freeze: a `Checking` result is not cached, so the next
    // observation re-hits the observer (and would resolve once the registry is reachable).
    let fake = Arc::new(FakeObserver::new(vec![(
        "ghcr.io/org/x:1",
        SigningPosture::Checking,
    )]));
    let calls = fake.calls.clone();
    let observer = SigningObserver::new(fake, 32, Duration::from_secs(300));
    let _ = observer.observe("ghcr.io/org/x:1").await;
    let _ = observer.observe("ghcr.io/org/x:1").await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a transient checking result is retried, not frozen into a cached posture"
    );
}

#[tokio::test]
async fn cached_resting_posture_adds_zero_outbound_calls() {
    // Acceptance: re-observing a cached image adds zero outbound calls — the cache fronts the
    // one observer round-trip, the same bound the gated path uses.
    let fake = Arc::new(FakeObserver::new(vec![(
        "ghcr.io/org/app:1",
        SigningPosture::Signed(signer(
            "https://github.com/org/app/.github/workflows/release.yaml@refs/tags/v1",
            "https://token.actions.githubusercontent.com",
        )),
    )]));
    let calls = fake.calls.clone();
    let observer = SigningObserver::new(fake, 32, Duration::from_secs(300));
    let first = observer.observe("ghcr.io/org/app:1").await;
    let second = observer.observe("ghcr.io/org/app:1").await;
    assert_eq!(first, second, "the cached posture is identical");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the resting posture is observed once; the re-observation is served from cache"
    );
}

#[tokio::test]
async fn sweep_observes_every_distinct_image_and_records_a_posture_map() {
    // The Pod sweep (admitted + already-running): every distinct image is observed into a
    // definitive posture, deduped (a replica's repeated image costs one observation).
    let fake = Arc::new(FakeObserver::new(vec![
        (
            "ghcr.io/org/app:1",
            SigningPosture::Signed(signer(
                "https://github.com/org/app/.github/workflows/r.yaml@refs/tags/v1",
                "https://token.actions.githubusercontent.com",
            )),
        ),
        ("ghcr.io/org/tampered:1", SigningPosture::InvalidSignature),
    ]));
    let calls = fake.calls.clone();
    let observer = SigningObserver::new(fake, 32, Duration::from_secs(300));
    // A running cluster's images, with a duplicate (a Deployment's replicas reference the
    // same image) and an unlisted image (defaults to not-signed).
    let map = observer
        .sweep([
            "ghcr.io/org/app:1",
            "ghcr.io/org/app:1",
            "ghcr.io/org/tampered:1",
            "docker.io/library/postgres:16",
        ])
        .await;
    assert_eq!(map.len(), 3, "three distinct images observed");
    assert_eq!(map.get("ghcr.io/org/app:1").unwrap().status(), "signed");
    assert_eq!(
        map.get("ghcr.io/org/tampered:1").unwrap().status(),
        "invalid-signature"
    );
    assert_eq!(
        map.get("docker.io/library/postgres:16").unwrap().status(),
        "not-signed"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "the duplicated replica image is observed once, not twice"
    );
}

#[tokio::test]
async fn sweep_caps_distinct_images_at_max_images() {
    // PROTECTOR_MAX_IMAGES bounds the outbound work: a burst of distinct images can't
    // amplify observation past the cap.
    let fake = Arc::new(FakeObserver::new(vec![]));
    let calls = fake.calls.clone();
    let observer = SigningObserver::new(fake, 2, Duration::from_secs(300));
    let images: Vec<String> = (0..10).map(|i| format!("ghcr.io/org/app{i}:1")).collect();
    let map = observer.sweep(&images).await;
    assert_eq!(map.len(), 2, "capped at max_images distinct observations");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "no more than max_images outbound observations per sweep"
    );
}

#[tokio::test]
async fn sweep_across_passes_reuses_cache() {
    // Re-sweeping a steady cluster (the per-pass running-Pod sweep) costs nothing for images
    // already observed within the TTL — the zero-egress bound, applied across passes.
    let fake = Arc::new(FakeObserver::new(vec![(
        "ghcr.io/org/app:1",
        SigningPosture::Signed(signer(
            "https://github.com/org/app/.github/workflows/r.yaml@refs/tags/v1",
            "https://token.actions.githubusercontent.com",
        )),
    )]));
    let calls = fake.calls.clone();
    let observer = SigningObserver::new(fake, 32, Duration::from_secs(300));
    let _ = observer.sweep(["ghcr.io/org/app:1"]).await; // pass 1: observe + cache
    let _ = observer.sweep(["ghcr.io/org/app:1"]).await; // pass 2: cache hit
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a steady cluster re-sweeps for free within the cache TTL"
    );
}

#[test]
fn posture_map_records_last_write_wins() {
    // A later definitive posture supersedes an earlier transient one for the same image.
    let mut map = super::posture::PostureMap::new();
    map.record("ghcr.io/org/app:1", SigningPosture::Checking);
    assert_eq!(map.get("ghcr.io/org/app:1").unwrap().status(), "checking");
    map.record(
        "ghcr.io/org/app:1",
        SigningPosture::Signed(signer(
            "https://github.com/org/app/.github/workflows/r.yaml@refs/tags/v1",
            "https://token.actions.githubusercontent.com",
        )),
    );
    assert_eq!(map.get("ghcr.io/org/app:1").unwrap().status(), "signed");
    assert_eq!(map.len(), 1, "the same image is one entry, overwritten");
}

#[test]
fn email_subject_is_recorded_as_a_legitimate_signer() {
    // ADR-0020 §1: a human keyless signer (Email subject) is recorded as a legitimate signer,
    // even though the org gate rejects Email. The posture carries the email as the identity.
    let posture = SigningPosture::Signed(Signer {
        identity: "dev@example.com".to_string(),
        issuer: Some("https://accounts.google.com".to_string()),
    });
    let s = posture.signer().expect("email subject is a signer");
    assert_eq!(s.identity, "dev@example.com");
    assert_eq!(s.issuer.as_deref(), Some("https://accounts.google.com"));
}
