//! Signing-posture observation (ADR-0020 Stage 1: INVENTORY).
//!
//! The old [`SignatureChecker`](super::SignatureChecker) answers one narrow question —
//! *is this gated image signed by the one trusted identity?* — and says
//! `NotApplicable` about everything else, which reads as a green stamp. This module adds
//! the missing half: observe **every** image's signing posture, with **no
//! `gated_prefixes` and no trusted-identity config**, into one of five definitive
//! resting states (never n/a; JEF-276 honest split):
//!
//!   * [`Signed`](SigningPosture::Signed) — keyless-verified: a signature chains to the
//!     public-good Fulcio root + its Rekor bundle, so the signer identity + OIDC issuer
//!     are read from the cert subject. The only trusted-identity posture.
//!   * [`SignedKeyBased`](SigningPosture::SignedKeyBased) — a `cosign sign --key`
//!     signature with a verified Rekor bundle but no Fulcio cert: real and log-included,
//!     signer opaque to keyless. Calm, never invalid.
//!   * [`UnverifiableHere`](SigningPosture::UnverifiableHere) — a signature is present but
//!     can't be verified against *our* trust root (a Rekor/TUF variance). Honest, calm-ish.
//!   * [`InvalidSignature`](SigningPosture::InvalidSignature) — RESERVED loud channel: a
//!     signature that *genuinely* fails (tampered / a cert whose Rekor inclusion doesn't
//!     hold). Distinct from, and more alarming than, every other state.
//!   * [`NotSigned`](SigningPosture::NotSigned) — no signature at all.
//!
//! …plus a transient [`Checking`](SigningPosture::Checking) for a registry/Rekor-
//! unreachable blip, which resolves into a resting state on a later pass — never a
//! resting n/a, never a fabricated posture, never a false clean.
//!
//! Trust anchor: the Fulcio/Rekor chain, NOT a caller identity. So we learn *who signed*
//! for any image by observation, with nothing configured. This is Stage 1 only —
//! observation + recording. The per-repo TOFU baseline (JEF-263), drift findings
//! (JEF-264), enforcement (JEF-265), and Rekor history (JEF-266) consume the
//! [`SigningPosture`] this exposes; they are NOT built here. State is in-memory
//! (a per-pass [`PostureMap`]); there is no durable schema yet.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::Mutex;

/// The signer learned from a verified Fulcio cert subject (ADR-0020 §1). Both fields are
/// UNTRUSTED third-party text — they come from an attacker-influenceable cert — so every
/// consumer MUST escape them at render. We record them purely as observed inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    /// The signer identity from the cert SAN: a workflow URI (GitHub Actions keyless) or an
    /// email (a human who authenticated via GitHub/Google). The org gate rejects `Email`;
    /// observation records it as a legitimate signer (ADR-0020 §1).
    pub identity: String,
    /// The OIDC issuer from the cert (`https://token.actions.githubusercontent.com`,
    /// `https://accounts.google.com`, …). `None` if the cert carried no issuer extension.
    pub issuer: Option<String>,
}

/// An image's observed signing posture (ADR-0020 Stage 1; JEF-276 honest split). Five definitive
/// resting states plus one transient. Never `NotApplicable` — observation always reaches a posture,
/// and a registry blip is the explicit [`Checking`](Self::Checking) rather than a fake clean.
///
/// The load-bearing distinction (JEF-276): [`InvalidSignature`](Self::InvalidSignature) is the
/// LOUD channel and means a signature *genuinely failed to verify* — NOT "we don't understand this
/// signing scheme". A real, correctly-signed image that isn't keyless-Fulcio (a key-based cosign
/// signature, or one we can't verify against our own trust root) is a CALM, honestly-labelled
/// state, never the loud one. The critical security property: a calm state is never read as an
/// identity we trust — it is signed-but-opaque, distinct from a keyless [`Signed`](Self::Signed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningPosture {
    /// **Keyless-verified**: a signature is present, its Fulcio cert chained to the trusted root and
    /// its Rekor inclusion verified — so we captured the signer identity. The only posture that
    /// yields a trusted signer.
    Signed(Signer),
    /// **Signed (key-based)**: a signature is present with a verified transparency-log (Rekor)
    /// bundle but NO Fulcio certificate — a `cosign sign --key` signature (e.g. cert-manager). The
    /// signature is real and its log inclusion verifies; the signer is simply opaque to keyless
    /// verification (no SAN/issuer to read). CALM, never invalid — but never a trusted identity.
    SignedKeyBased,
    /// **Signed but unverifiable here**: a signature artifact is present but verification could not
    /// complete against *our* trust root (a Rekor/TUF trust-root variance, e.g. "transparency log
    /// certificate does not match"). Distinct from a genuine failure — honestly "couldn't verify
    /// against our trust root", not "forged". Calm-ish, never a trusted identity.
    UnverifiableHere,
    /// **Invalid** (RESERVED, the loud channel): a signature artifact is present and *genuinely*
    /// fails verification (tampered payload, or a Fulcio cert whose Rekor inclusion does not hold).
    /// Distinct from — and more alarming than — every other state. NOT used for a signing scheme we
    /// merely can't read.
    InvalidSignature,
    /// No signature at all.
    NotSigned,
    /// Transient: the registry / transparency log was unreachable, so the posture is not yet
    /// known. Resolves into one of the resting states on a later pass. Must never be rendered as a
    /// resting posture and never read as clean.
    Checking,
}

impl SigningPosture {
    /// A stable, low-cardinality word for the posture — for logs, metrics, and the
    /// admission/inventory column (the render itself is JEF-262; this is just the vocabulary
    /// those views read). The signer identity is NOT included here — it is untrusted text the
    /// caller escapes separately.
    pub fn status(&self) -> &'static str {
        match self {
            SigningPosture::Signed(_) => "signed",
            SigningPosture::SignedKeyBased => "signed-key-based",
            SigningPosture::UnverifiableHere => "unverifiable",
            SigningPosture::InvalidSignature => "invalid-signature",
            SigningPosture::NotSigned => "not-signed",
            SigningPosture::Checking => "checking",
        }
    }

    /// The signer, when this posture is [`Signed`](Self::Signed).
    pub fn signer(&self) -> Option<&Signer> {
        match self {
            SigningPosture::Signed(signer) => Some(signer),
            _ => None,
        }
    }

    /// Whether this is a definitive resting state (one of the three), as opposed to the
    /// transient [`Checking`](Self::Checking). Only resting postures are worth caching.
    pub fn is_resting(&self) -> bool {
        !matches!(self, SigningPosture::Checking)
    }
}

/// Reads an image's signing posture by observation, with NO trusted-identity config
/// (ADR-0020 §1). Abstracted behind a trait — exactly like
/// [`SignatureChecker`](super::SignatureChecker) — so the observation + caching + sweep
/// logic is unit-testable with a fake, without reaching a registry or the sigstore TUF root.
#[async_trait]
pub trait SignatureObserver: Send + Sync {
    /// Observe `image`'s posture. Never errors: an infrastructure failure is the transient
    /// [`Checking`](SigningPosture::Checking) state, not an `Err` — the caller must always be
    /// handed a posture, never forced to invent one.
    async fn observe(&self, image: &str) -> SigningPosture;
}

/// The in-memory record of the latest observed posture per image (ADR-0020 Stage 1).
/// Keyed by image ref, last-write-wins. This is the *per-pass* posture map the ticket calls
/// for — deliberately ephemeral: the durable, repo-keyed signing baseline is JEF-263 and is
/// NOT built here. Cheap to snapshot for the (future) inventory view.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct PostureMap {
    images: HashMap<String, SigningPosture>,
}

impl PostureMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `image`'s observed posture (last-write-wins). A later definitive posture
    /// overwrites an earlier `Checking`, so a resolved state always supersedes the transient.
    pub fn record(&mut self, image: impl Into<String>, posture: SigningPosture) {
        self.images.insert(image.into(), posture);
    }

    /// The posture recorded for `image`, if any.
    pub fn get(&self, image: &str) -> Option<&SigningPosture> {
        self.images.get(image)
    }

    /// Number of distinct images observed.
    pub fn len(&self) -> usize {
        self.images.len()
    }

    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }

    /// All observed `(image, posture)` pairs — the inventory the (future) Admission view
    /// renders. Order is unspecified.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &SigningPosture)> {
        self.images.iter().map(|(k, v)| (k.as_str(), v))
    }
}

/// Drives signing-posture observation for the engine and the webhook off a SHARED, bounded
/// verification budget (ADR-0020 §1; ADR-0015 zero-egress carve-out). It fronts a
/// [`SignatureObserver`] with:
///
///   * a **TTL + image-keyed cache** of *resting* postures, so re-observing the same image
///     (a replica, a later pass, the webhook after the engine swept it) adds ZERO outbound
///     calls until the entry ages past the TTL — the same TOCTOU-bounding discipline the
///     gated cache uses. The transient `Checking` state is deliberately NOT cached, so a
///     registry blip is retried next pass instead of being frozen.
///   * a **`max_images` cap** on distinct images verified per [`sweep`](Self::sweep), so a
///     burst of distinct images (a big rollout, a Pod with many init/ephemeral containers)
///     can't amplify outbound verification into a DoS.
///
/// The cache + cap are exactly the [`SignaturePolicy`](super::SignaturePolicy)'s bounds,
/// applied to the inventory path so observing every image stays within the same
/// already-sanctioned outbound envelope.
pub struct SigningObserver {
    observer: Arc<dyn SignatureObserver>,
    /// Upper bound on distinct images verified per sweep.
    max_images: usize,
    /// How long a cached resting posture stays valid.
    cache_ttl: Duration,
    /// image ref → (resting posture, when-cached). Only resting postures are cached.
    cache: Mutex<HashMap<String, (SigningPosture, Instant)>>,
}

impl SigningObserver {
    pub fn new(
        observer: Arc<dyn SignatureObserver>,
        max_images: usize,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            observer,
            max_images,
            cache_ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Observe one image, serving a fresh cached resting posture without an outbound call.
    /// A `Checking` result is never cached (so the next observation retries the registry);
    /// a resting result is cached under the image ref with the current instant.
    pub async fn observe(&self, image: &str) -> SigningPosture {
        if let Some((posture, cached_at)) = self.cache.lock().await.get(image).cloned()
            && cached_at.elapsed() < self.cache_ttl
        {
            return posture;
        }
        let posture = self.observer.observe(image).await;
        if posture.is_resting() {
            self.cache
                .lock()
                .await
                .insert(image.to_string(), (posture.clone(), Instant::now()));
        }
        posture
    }

    /// Observe a set of images (an admitted Pod's containers, or the running-Pod sweep),
    /// returning a [`PostureMap`] of what was observed this pass. Distinct images only, and
    /// at most `max_images` of them are verified — the surplus is left unobserved (no posture
    /// recorded) rather than spending unbounded outbound calls, exactly as the gated policy
    /// caps a Pod's gated images. Cached images cost nothing, so a steady cluster re-sweeps
    /// for free.
    pub async fn sweep<I, S>(&self, images: I) -> PostureMap
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut distinct: Vec<String> = Vec::new();
        for image in images {
            let image = image.as_ref();
            if !distinct.iter().any(|d| d == image) {
                distinct.push(image.to_string());
            }
        }
        let mut map = PostureMap::new();
        for image in distinct.into_iter().take(self.max_images) {
            let posture = self.observe(&image).await;
            map.record(image, posture);
        }
        map
    }
}
