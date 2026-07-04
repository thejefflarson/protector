//! Tests for the ADR-0020 Stage-3 signing-continuity gate (JEF-265): the block predicate, the
//! scoped "exception accepted" opt-out, the back-compat pin, and the read-only-baseline guarantee.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;

use super::*;
use crate::engine::state::{SharedSigningBaseline, SigningBaselineStore};
use crate::policies::signature::posture::{SignatureObserver, Signer, SigningObserver};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;
const CI: &str = "https://github.com/org/app/.github/workflows/release.yaml@refs/tags/v1";
const ATTACKER: &str = "https://github.com/evil/app/.github/workflows/pwn.yaml@refs/heads/main";

/// A fake observer returning a fixed posture per image (unknown ⇒ NotSigned), counting calls.
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

fn observer(postures: Vec<(&str, SigningPosture)>) -> (Arc<SigningObserver>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let fake = FakeObserver {
        postures: postures
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        calls: calls.clone(),
    };
    (
        Arc::new(SigningObserver::new(
            Arc::new(fake),
            32,
            Duration::from_secs(300),
        )),
        calls,
    )
}

fn signed(identity: &str) -> SigningPosture {
    SigningPosture::Signed(Signer {
        identity: identity.to_string(),
        issuer: Some("https://token.actions.githubusercontent.com".to_string()),
    })
}

/// A shared baseline carrying an ESTABLISHED signed baseline for `ghcr.io/org/app` (signer `CI`).
fn established_baseline() -> SharedSigningBaseline {
    let mut store = SigningBaselineStore::new();
    store.observe("ghcr.io/org/app@sha256:seed", &signed(CI), 0);
    store.observe("ghcr.io/org/app@sha256:seed", &signed(CI), 3 * DAY_MS);
    assert!(store.get("ghcr.io/org/app").unwrap().established);
    let shared = SharedSigningBaseline::new();
    shared.publish(&store);
    shared
}

fn gate(
    observer: Arc<SigningObserver>,
    baseline: SharedSigningBaseline,
    exceptions: SigningExceptions,
    pins: Vec<SigningPin>,
) -> ContinuityGate {
    ContinuityGate::new(observer, baseline, exceptions, pins, 32)
}

// ---- The block predicate: regression vs continuity vs cold ---------------------------------------

#[tokio::test]
async fn established_regression_blocks() {
    // An established keyless repo now serving an unsigned image is a regression ⇒ would-block.
    let (obs, _c) = observer(vec![]); // ⇒ NotSigned
    let g = gate(
        obs,
        established_baseline(),
        SigningExceptions::default(),
        vec![],
    );
    let block = g.evaluate(&["ghcr.io/org/app:2".to_string()]).await;
    assert!(block.is_some(), "an established-baseline regression blocks");
}

#[tokio::test]
async fn continuous_redeploy_admits() {
    // A new digest signed by the KNOWN identity is continuous ⇒ no block.
    let (obs, _c) = observer(vec![("ghcr.io/org/app:2", signed(CI))]);
    let g = gate(
        obs,
        established_baseline(),
        SigningExceptions::default(),
        vec![],
    );
    assert!(
        g.evaluate(&["ghcr.io/org/app:2".to_string()])
            .await
            .is_none()
    );
}

#[tokio::test]
async fn cold_baseline_regression_does_not_block() {
    // A freshly-learned (cold) baseline that regresses is UNCERTAIN, never a hard block — cold-start
    // never denies (TOFU is the weakest evidence).
    let mut store = SigningBaselineStore::new();
    store.observe("ghcr.io/org/app@sha256:seed", &signed(CI), 0); // cold (not established)
    assert!(!store.get("ghcr.io/org/app").unwrap().established);
    let shared = SharedSigningBaseline::new();
    shared.publish(&store);
    let (obs, _c) = observer(vec![]); // ⇒ NotSigned (a regression)
    let g = gate(obs, shared, SigningExceptions::default(), vec![]);
    assert!(
        g.evaluate(&["ghcr.io/org/app:2".to_string()])
            .await
            .is_none(),
        "a cold-baseline regression must NOT block"
    );
}

#[tokio::test]
async fn never_seen_repo_does_not_block() {
    // A repo with no baseline at all (cold-start first sight) never blocks.
    let (obs, _c) = observer(vec![("ghcr.io/new/app:1", signed(CI))]);
    let g = gate(
        obs,
        SharedSigningBaseline::new(),
        SigningExceptions::default(),
        vec![],
    );
    assert!(
        g.evaluate(&["ghcr.io/new/app:1".to_string()])
            .await
            .is_none()
    );
}

#[tokio::test]
async fn genuinely_invalid_blocks_even_without_a_baseline() {
    // The loud channel: a genuinely-invalid signature blocks regardless of baseline strength, so an
    // attacker can't dodge the block by keeping the repo cold.
    let (obs, _c) = observer(vec![(
        "ghcr.io/new/app:1",
        SigningPosture::InvalidSignature,
    )]);
    let g = gate(
        obs,
        SharedSigningBaseline::new(),
        SigningExceptions::default(),
        vec![],
    );
    assert!(
        g.evaluate(&["ghcr.io/new/app:1".to_string()])
            .await
            .is_some()
    );
}

// ---- "exception accepted" — scoped, fingerprinted, never a global mute ---------------------------

#[tokio::test]
async fn exception_admits_only_the_accepted_repo() {
    // An exception on ghcr.io/org/app for the unsigned drift admits it; a DIFFERENT established repo
    // regressing still blocks (an exception never silences drift elsewhere).
    let mut store = SigningBaselineStore::new();
    store.observe("ghcr.io/org/app@sha256:seed", &signed(CI), 0);
    store.observe("ghcr.io/org/app@sha256:seed", &signed(CI), 3 * DAY_MS);
    store.observe("ghcr.io/org/other@sha256:seed", &signed(CI), 0);
    store.observe("ghcr.io/org/other@sha256:seed", &signed(CI), 3 * DAY_MS);
    let shared = SharedSigningBaseline::new();
    shared.publish(&store);

    let exceptions = SigningExceptions::parse("repo:ghcr.io/org/app unsigned");
    let (obs, _c) = observer(vec![]); // both ⇒ NotSigned (both regress)
    let g = gate(obs, shared, exceptions, vec![]);

    assert!(
        g.evaluate(&["ghcr.io/org/app:2".to_string()])
            .await
            .is_none(),
        "the excepted repo admits"
    );
    assert!(
        g.evaluate(&["ghcr.io/org/other:2".to_string()])
            .await
            .is_some(),
        "a DIFFERENT repo is still enforced — the exception is scoped"
    );
}

#[tokio::test]
async fn exception_admits_only_the_exact_image_when_keyed_by_image() {
    let exceptions = SigningExceptions::parse("image:ghcr.io/org/app:2 unsigned");
    let (obs, _c) = observer(vec![]); // ⇒ NotSigned
    let g = gate(obs, established_baseline(), exceptions, vec![]);
    assert!(
        g.evaluate(&["ghcr.io/org/app:2".to_string()])
            .await
            .is_none(),
        "the exact accepted image admits"
    );
    assert!(
        g.evaluate(&["ghcr.io/org/app:3".to_string()])
            .await
            .is_some(),
        "a different image ref under the same repo is still enforced"
    );
}

#[tokio::test]
async fn re_drift_after_acceptance_re_blocks() {
    // An exception pinned to identity X (a specific new signer) admits that change; a DIFFERENT
    // subsequent change (identity Y) re-flags loud — the acceptance is scoped, not a blanket mute.
    let exceptions =
        SigningExceptions::parse(&format!("repo:ghcr.io/org/app identity:{CI}-rotated"));
    // The accepted rotation:
    let (obs1, _c) = observer(vec![(
        "ghcr.io/org/app:2",
        signed(&format!("{CI}-rotated")),
    )]);
    let g1 = gate(obs1, established_baseline(), exceptions.clone(), vec![]);
    assert!(
        g1.evaluate(&["ghcr.io/org/app:2".to_string()])
            .await
            .is_none(),
        "the accepted identity rotation admits"
    );
    // A DIFFERENT later change — the attacker's identity — is NOT covered by the exception.
    let (obs2, _c) = observer(vec![("ghcr.io/org/app:3", signed(ATTACKER))]);
    let g2 = gate(obs2, established_baseline(), exceptions, vec![]);
    assert!(
        g2.evaluate(&["ghcr.io/org/app:3".to_string()])
            .await
            .is_some(),
        "a different subsequent change re-flags — the exception did not blanket-mute the repo"
    );
}

#[tokio::test]
async fn there_is_no_global_disable_switch() {
    // An exception for one repo's drift never covers another repo's — proving there is no global mute.
    let exceptions = SigningExceptions::parse("repo:ghcr.io/org/app unsigned");
    assert!(exceptions.accepts("ghcr.io/org/app:9", &RegressionKind::Unsigned));
    assert!(!exceptions.accepts("ghcr.io/org/elsewhere:9", &RegressionKind::Unsigned));
    // Even the same repo, a DIFFERENT drift kind is not covered.
    assert!(!exceptions.accepts(
        "ghcr.io/org/app:9",
        &RegressionKind::IdentityChange {
            new_identity: ATTACKER.to_string(),
            new_issuer: None,
        }
    ));
}

// ---- The back-compat PIN acts as the old prefix-gated single-identity gate -----------------------

#[tokio::test]
async fn pin_denies_unsigned_like_the_old_prefix_gate() {
    let pin = SigningPin::new("ghcr.io/org/", "^https://github\\.com/org/").unwrap();
    let (obs, _c) = observer(vec![]); // ⇒ NotSigned
    let g = gate(
        obs,
        SharedSigningBaseline::new(),
        SigningExceptions::default(),
        vec![pin],
    );
    assert!(
        g.evaluate(&["ghcr.io/org/app:1".to_string()])
            .await
            .is_some(),
        "a pinned repo serving unsigned must block (the old gate's behavior)"
    );
}

#[tokio::test]
async fn pin_admits_the_pinned_identity_and_blocks_a_different_signer() {
    let pin = SigningPin::new("ghcr.io/org/", "^https://github\\.com/org/").unwrap();
    let (obs, _c) = observer(vec![
        ("ghcr.io/org/app:1", signed(CI)),        // matches ^…/org/
        ("ghcr.io/org/evil:1", signed(ATTACKER)), // a different signer
    ]);
    let g = gate(
        obs,
        SharedSigningBaseline::new(),
        SigningExceptions::default(),
        vec![pin],
    );
    assert!(
        g.evaluate(&["ghcr.io/org/app:1".to_string()])
            .await
            .is_none(),
        "the pinned identity admits"
    );
    assert!(
        g.evaluate(&["ghcr.io/org/evil:1".to_string()])
            .await
            .is_some(),
        "a different signer on the pinned prefix blocks"
    );
}

#[tokio::test]
async fn pin_does_not_govern_other_prefixes() {
    let pin = SigningPin::new("ghcr.io/org/", "^https://github\\.com/org/").unwrap();
    let (obs, _c) = observer(vec![]); // ⇒ NotSigned
    let g = gate(
        obs,
        SharedSigningBaseline::new(),
        SigningExceptions::default(),
        vec![pin],
    );
    assert!(
        g.evaluate(&["docker.io/library/postgres:16".to_string()])
            .await
            .is_none(),
        "an unpinned, never-signed repo is not governed by the pin"
    );
}

// ---- Read-only on the baseline: the webhook can never poison it ----------------------------------

#[tokio::test]
async fn evaluating_never_mutates_the_baseline() {
    // The gate holds only a read handle; classifying an arriving image adds NOTHING to the baseline
    // — an attacker who gets a Pod admitted can never TOFU-establish a new identity via admission.
    let shared = established_baseline();
    let before = shared.get("ghcr.io/org/app").unwrap();
    let before_len = shared.len();
    let (obs, _c) = observer(vec![("ghcr.io/attacker/new:1", signed(ATTACKER))]);
    let g = gate(obs, shared.clone(), SigningExceptions::default(), vec![]);
    let _ = g
        .evaluate(&[
            "ghcr.io/attacker/new:1".to_string(),
            "ghcr.io/org/app:2".to_string(),
        ])
        .await;
    assert_eq!(
        shared.len(),
        before_len,
        "no new repo was learned via admission"
    );
    assert_eq!(
        shared.get("ghcr.io/org/app").unwrap().identities,
        before.identities,
        "the established baseline's identity set is unchanged"
    );
    assert!(
        shared.get("ghcr.io/attacker/new").is_none(),
        "an admitted image never establishes a baseline"
    );
}

// ---- Exception parsing robustness ----------------------------------------------------------------

#[test]
fn parse_ignores_comments_blanks_and_malformed_entries() {
    let spec = "# a comment\n\nrepo:ghcr.io/org/app unsigned\nbogus-no-scope-prefix unsigned\n\
                image:ghcr.io/org/x@sha256:ab identity:someone\nrepo:missing-fingerprint";
    let ex = SigningExceptions::parse(spec);
    assert!(ex.accepts("ghcr.io/org/app:1", &RegressionKind::Unsigned));
    assert!(ex.accepts(
        "ghcr.io/org/x@sha256:ab",
        &RegressionKind::IdentityChange {
            new_identity: "someone".to_string(),
            new_issuer: None,
        }
    ));
    // "bogus-no-scope-prefix" and "repo:missing-fingerprint" contributed nothing.
    assert!(!ex.accepts("bogus-no-scope-prefix:1", &RegressionKind::Unsigned));
}

#[test]
fn empty_config_excepts_nothing() {
    assert!(SigningExceptions::default().is_empty());
    assert!(!SigningExceptions::default().accepts("ghcr.io/org/app:1", &RegressionKind::Unsigned));
}
