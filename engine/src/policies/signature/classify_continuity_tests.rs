//! Posture-classification (JEF-276) + admission signing-continuity (ADR-0020 Stage 3 / JEF-265)
//! tests, split out of `tests.rs` purely to keep every file under the 1,000-line cap (CLAUDE.md).
//! The shared admission fixtures (`pod_request`, `policy`, `scope`, `signer`) and the fake
//! checker/observer come from `super::tests`, matching the sibling `*_tests.rs` pattern.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::continuity::{ContinuityGate, SigningExceptions};
use super::cosign::{LayerFacts, classify_facts};
use super::posture::{Signer, SigningObserver, SigningPosture};
use super::{Decision, Policy, SignaturePolicy};
use crate::engine::state::{SharedSigningBaseline, SigningBaselineStore};

use super::tests::{FakeChecker, FakeObserver, pod_request, policy, scope, signer};

// ---------------------------------------------------------------------------
// JEF-276: honest, scheme-aware posture classification (classify_facts)
// ---------------------------------------------------------------------------

/// A keyless-verified layer: a Fulcio signer that chained + Rekor-verified (sigstore only ever
/// populates `signer` after both hold).
fn keyless_layer(identity: &str) -> LayerFacts {
    LayerFacts {
        signer: Some(Signer {
            identity: identity.to_string(),
            issuer: Some("https://token.actions.githubusercontent.com".to_string()),
        }),
        has_verified_bundle: true,
        has_signature: true,
    }
}

/// A key-based layer (reproducer 1 — cert-manager): a verified Rekor bundle + signature, but NO
/// Fulcio cert (`Cert: false`).
fn key_based_layer() -> LayerFacts {
    LayerFacts {
        signer: None,
        has_verified_bundle: true,
        has_signature: true,
    }
}

/// An unverifiable-here layer (reproducer 2 — curl trust-root variance): a signature is present but
/// nothing verified against our trust root (no usable signer, no verified log inclusion).
fn unverifiable_layer() -> LayerFacts {
    LayerFacts {
        signer: None,
        has_verified_bundle: false,
        has_signature: true,
    }
}

#[test]
fn classify_keyless_verified_yields_signed_with_identity() {
    // Our own GH-Actions-OIDC images are unchanged: keyless-verified ⇒ signed + captured signer.
    let posture = classify_facts(&[keyless_layer(
        "https://github.com/org/app/.github/workflows/release.yaml@refs/tags/v1",
    )]);
    assert_eq!(posture.status(), "signed");
    let signer = posture.signer().expect("keyless-verified carries a signer");
    assert!(signer.identity.contains("org/app"));
}

#[test]
fn classify_key_based_signature_is_signed_not_invalid() {
    // Reproducer 1 (quay.io/jetstack/cert-manager-cainjector): a valid `cosign sign --key`
    // signature — cert absent, Rekor bundle present. Must be the CALM key-based state, NEVER the
    // loud invalid, and it carries no trusted signer identity (opaque).
    let posture = classify_facts(&[key_based_layer()]);
    assert_eq!(posture, SigningPosture::SignedKeyBased);
    assert_eq!(posture.status(), "signed-key-based");
    assert_ne!(
        posture,
        SigningPosture::InvalidSignature,
        "a real key-based signature must never be the loud invalid channel"
    );
    assert_eq!(
        posture.signer(),
        None,
        "key-based is signed-but-opaque — never a trusted identity"
    );
}

#[test]
fn classify_trust_root_variance_is_unverifiable_not_invalid() {
    // Reproducer 2 (docker.io/curlimages/curl:latest): a signature is present but keyless verify
    // hits a transparency-log/TUF trust-root variance. Honest "couldn't verify here" — calm-ish,
    // distinct from a genuine failure, and never a trusted identity.
    let posture = classify_facts(&[unverifiable_layer()]);
    assert_eq!(posture, SigningPosture::UnverifiableHere);
    assert_eq!(posture.status(), "unverifiable");
    assert_ne!(posture, SigningPosture::InvalidSignature);
    assert_eq!(posture.signer(), None);
}

#[test]
fn classify_no_layers_is_not_signed() {
    assert_eq!(classify_facts(&[]), SigningPosture::NotSigned);
}

#[test]
fn classify_reserves_invalid_for_a_genuine_failure() {
    // The reserved loud channel: a degenerate layer with neither a signer, a verified bundle, nor
    // even a signature — the only shape treated as genuinely invalid. (sigstore-rs drops a
    // tamper/failed-Rekor layer before it reaches classify; see the classify note — such an image
    // lands as not-signed and, on an established repo, still regresses loudly via JEF-264.)
    let degenerate = LayerFacts {
        signer: None,
        has_verified_bundle: false,
        has_signature: false,
    };
    assert_eq!(
        classify_facts(&[degenerate]),
        SigningPosture::InvalidSignature
    );
}

#[test]
fn classify_prefers_keyless_identity_over_a_key_based_layer() {
    // A multi-scheme image (a keyless referrer sig alongside a key-based .sig): the trusted keyless
    // identity wins, regardless of layer order.
    let a = classify_facts(&[
        key_based_layer(),
        keyless_layer("https://github.com/org/app/.github/workflows/r.yaml@refs/tags/v1"),
    ]);
    let b = classify_facts(&[
        keyless_layer("https://github.com/org/app/.github/workflows/r.yaml@refs/tags/v1"),
        key_based_layer(),
    ]);
    assert_eq!(a.status(), "signed");
    assert_eq!(b.status(), "signed");
}

#[test]
fn classify_prefers_key_based_over_unverifiable() {
    // A verified Rekor bundle (even without a Fulcio cert) is stronger evidence than a bare,
    // unverifiable signature — so a mix resolves to the calm key-based state.
    let posture = classify_facts(&[unverifiable_layer(), key_based_layer()]);
    assert_eq!(posture, SigningPosture::SignedKeyBased);
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

// ---------------------------------------------------------------------------
// ADR-0020 Stage 3: admission signing-CONTINUITY enforcement (JEF-265)
// ---------------------------------------------------------------------------

const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const CI: &str = "https://github.com/org/app/.github/workflows/release.yaml@refs/tags/v1";

/// A signed posture from `identity` (GitHub Actions issuer).
fn signed_by(identity: &str) -> SigningPosture {
    SigningPosture::Signed(signer(
        identity,
        "https://token.actions.githubusercontent.com",
    ))
}

/// A shared baseline with an ESTABLISHED signed history for `ghcr.io/org/app` (signer `CI`).
fn established_shared_baseline() -> SharedSigningBaseline {
    let mut store = SigningBaselineStore::new();
    store.observe("ghcr.io/org/app@sha256:seed", &signed_by(CI), 0);
    store.observe("ghcr.io/org/app@sha256:seed", &signed_by(CI), 3 * DAY_MS);
    let shared = SharedSigningBaseline::new();
    shared.publish(&store);
    shared
}

/// A `SignaturePolicy` with NO gated prefixes (so only the continuity gate has an opinion) and the
/// continuity gate wired to a fake observer + the given baseline/exceptions.
fn continuity_policy(
    postures: Vec<(&str, SigningPosture)>,
    baseline: SharedSigningBaseline,
    exceptions: SigningExceptions,
    enforce: bool,
) -> SignaturePolicy {
    let observer = Arc::new(SigningObserver::new(
        Arc::new(FakeObserver::new(postures)),
        32,
        Duration::from_secs(300),
    ));
    let gate = ContinuityGate::new(observer, baseline, exceptions, vec![], 32);
    SignaturePolicy::new(
        Arc::new(FakeChecker(HashMap::new())),
        vec![], // no gated prefixes — isolate the continuity gate
        scope(enforce),
        32,
        Duration::from_secs(300),
    )
    .with_continuity(gate)
}

#[tokio::test]
async fn continuity_enforced_regression_denies() {
    // An established keyless repo now serving an unsigned image, IN enforced scope ⇒ Deny.
    let policy = continuity_policy(
        vec![], // ⇒ NotSigned
        established_shared_baseline(),
        SigningExceptions::default(),
        true,
    );
    let d = policy.evaluate(&pod_request(&["ghcr.io/org/app:2"])).await;
    assert!(matches!(d, Decision::Deny { .. }), "got {d:?}");
}

#[tokio::test]
async fn continuity_out_of_scope_audits_only() {
    // The SAME regression OUT of enforced scope ⇒ Audit (recorded, still admitted). Enforcement
    // fires only for images in enforceScope.
    let policy = continuity_policy(
        vec![],
        established_shared_baseline(),
        SigningExceptions::default(),
        false,
    );
    let d = policy.evaluate(&pod_request(&["ghcr.io/org/app:2"])).await;
    assert!(matches!(d, Decision::Audit { .. }), "got {d:?}");
}

#[tokio::test]
async fn continuity_unconfigured_denies_nothing() {
    // No continuity gate wired (the default, pre-JEF-265) + an established regression + enforced
    // scope ⇒ still Allow. Unconfigured operators see ZERO behavior change.
    let policy = policy(&[], true); // no gated prefixes, no continuity
    let d = policy.evaluate(&pod_request(&["ghcr.io/org/app:2"])).await;
    assert!(matches!(d, Decision::Allow), "got {d:?}");
}

#[tokio::test]
async fn continuity_cold_start_does_not_deny() {
    // A cold (freshly-learned, not-established) baseline regressing, in enforced scope ⇒ Allow.
    let mut store = SigningBaselineStore::new();
    store.observe("ghcr.io/org/app@sha256:seed", &signed_by(CI), 0);
    let shared = SharedSigningBaseline::new();
    shared.publish(&store);
    let policy = continuity_policy(vec![], shared, SigningExceptions::default(), true);
    let d = policy.evaluate(&pod_request(&["ghcr.io/org/app:2"])).await;
    assert!(
        matches!(d, Decision::Allow),
        "cold-start never denies; got {d:?}"
    );
}

#[tokio::test]
async fn continuity_exception_admits_only_its_repo_and_not_others() {
    // An exception on ghcr.io/org/app admits it; a DIFFERENT established repo still denies.
    let mut store = SigningBaselineStore::new();
    for repo in ["ghcr.io/org/app", "ghcr.io/org/other"] {
        store.observe(&format!("{repo}@sha256:seed"), &signed_by(CI), 0);
        store.observe(&format!("{repo}@sha256:seed"), &signed_by(CI), 3 * DAY_MS);
    }
    let shared = SharedSigningBaseline::new();
    shared.publish(&store);
    let exceptions = SigningExceptions::parse("repo:ghcr.io/org/app unsigned");
    let policy = continuity_policy(vec![], shared, exceptions, true);

    let admitted = policy.evaluate(&pod_request(&["ghcr.io/org/app:2"])).await;
    assert!(
        matches!(admitted, Decision::Allow),
        "excepted repo admits; got {admitted:?}"
    );
    let denied = policy
        .evaluate(&pod_request(&["ghcr.io/org/other:2"]))
        .await;
    assert!(
        matches!(denied, Decision::Deny { .. }),
        "an exception never silences another repo; got {denied:?}"
    );
}

#[tokio::test]
async fn continuity_redrift_after_acceptance_denies_again() {
    // An exception accepts a specific identity rotation; a DIFFERENT later signer re-denies.
    let exceptions =
        SigningExceptions::parse(&format!("repo:ghcr.io/org/app identity:{CI}-rotated"));
    let accepted = continuity_policy(
        vec![("ghcr.io/org/app:2", signed_by(&format!("{CI}-rotated")))],
        established_shared_baseline(),
        exceptions.clone(),
        true,
    );
    assert!(
        matches!(
            accepted
                .evaluate(&pod_request(&["ghcr.io/org/app:2"]))
                .await,
            Decision::Allow
        ),
        "the accepted rotation admits"
    );
    let redrift = continuity_policy(
        vec![(
            "ghcr.io/org/app:3",
            signed_by("https://github.com/evil/x/.github/workflows/p.yml@refs/heads/main"),
        )],
        established_shared_baseline(),
        exceptions,
        true,
    );
    assert!(
        matches!(
            redrift.evaluate(&pod_request(&["ghcr.io/org/app:3"])).await,
            Decision::Deny { .. }
        ),
        "a different subsequent change re-denies — the exception is scoped, not a blanket mute"
    );
}

#[tokio::test]
async fn continuity_webhook_never_mutates_the_baseline() {
    // Admission consults the baseline read-only: after evaluating (even an unknown new repo), the
    // shared baseline is unchanged — admission can never poison it.
    let shared = established_shared_baseline();
    let before_len = shared.len();
    let policy = continuity_policy(
        vec![(
            "ghcr.io/attacker/new:1",
            signed_by("https://github.com/evil/x/.github/workflows/p.yml@refs/heads/main"),
        )],
        shared.clone(),
        SigningExceptions::default(),
        true,
    );
    let _ = policy
        .evaluate(&pod_request(&["ghcr.io/attacker/new:1"]))
        .await;
    assert_eq!(
        shared.len(),
        before_len,
        "no baseline was learned via admission"
    );
    assert!(
        shared.get("ghcr.io/attacker/new").is_none(),
        "an admitted image never establishes a baseline"
    );
}
