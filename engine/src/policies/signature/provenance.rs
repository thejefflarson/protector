//! SLSA **build-provenance** observation (ADR-0020 §5, JEF-275) — the second supply-chain
//! continuity axis, alongside signature continuity.
//!
//! A cosign *signature* proves *who* signed an image (the signer identity — JEF-261). SLSA
//! **provenance** proves *how it was built*: the source repository and the builder/workflow that
//! produced it. Protector already observes signer identity; this module adds the missing axis —
//! observe every image's provenance posture into one of four definitive resting states (never
//! n/a; mirroring the [`SigningPosture`](super::posture::SigningPosture) honest split):
//!
//!   * [`Verified`](ProvenancePosture::Verified) — a cosign-attest SLSA provenance attestation
//!     whose DSSE envelope + Fulcio cert chained to the trusted root and whose Rekor inclusion
//!     verified, AND whose in-toto/SLSA predicate yielded a builder identity. The only posture
//!     that confers a trusted `(source, builder)`.
//!   * [`Unverifiable`](ProvenancePosture::Unverifiable) — a SLSA provenance attestation artifact
//!     is present but could not be verified against our trust root, or verified but carried no
//!     extractable builder identity. Honest "present but not trusted here" — never read as trusted.
//!   * [`Absent`](ProvenancePosture::Absent) — no provenance attestation at all. The common case
//!     today (few images carry cosign-attest provenance): calm, NOT an alarm — exactly like a
//!     never-signed image — but never a green "trusted build" either.
//!   * a transient [`Checking`](ProvenancePosture::Checking) for a registry/Rekor-unreachable blip,
//!     which resolves into a resting state on a later pass — never a resting n/a, never a false
//!     clean.
//!
//! Trust anchor: the Fulcio/Rekor chain of the attestation, NOT a caller identity — we learn the
//! `(source, builder)` by observation, with nothing configured, exactly as signing posture learns
//! the signer. The per-repo TOFU provenance baseline, drift findings, and the inventory render
//! consume the [`ProvenancePosture`] this exposes.
//!
//! ## Reuse, not a second verifier (JEF-275 technical note)
//!
//! The production observer ([`CosignChecker`](super::CosignChecker)) fetches the attestation on
//! the SAME sanctioned registry/sigstore round trip as signature verification (ADR-0015) —
//! `trusted_signature_layers` already returns any attached in-toto/DSSE attestation layer — and
//! classifies it here. There is no second verifier and no new egress path.

/// The SLSA v0.2 in-toto predicate type (the `cosign attest --type slsaprovenance` default and the
/// original SLSA generator output).
pub const SLSA_PROVENANCE_V02: &str = "https://slsa.dev/provenance/v0.2";
/// The SLSA v1 in-toto predicate type (GitHub's `actions/attest-build-provenance` output).
pub const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";

/// Whether an in-toto predicate type is a SLSA build-provenance predicate we know how to read. A
/// DSSE attestation layer carrying any OTHER predicate type is not build provenance and is ignored
/// by provenance observation (it may still be a signature, handled by the signing axis).
pub fn is_slsa_predicate_type(predicate_type: &str) -> bool {
    matches!(predicate_type, SLSA_PROVENANCE_V02 | SLSA_PROVENANCE_V1)
}

/// The build provenance learned from a verified SLSA predicate (ADR-0020 §5). Both fields are
/// UNTRUSTED third-party text — they come from an attacker-influenceable attestation predicate — so
/// every consumer MUST escape them at render. Recorded purely as observed inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// The source repository the image was built from, cleaned to a stable identity
    /// (`github.com/org/repo`) from the predicate's config-source / workflow / material URI.
    /// UNTRUSTED — escape at render.
    pub source_repo: String,
    /// The builder identity: the SLSA `builder.id` — a GitHub Actions OIDC workflow URI
    /// (`https://github.com/org/repo/.github/workflows/x.yml@refs/...`) or another builder URI.
    /// UNTRUSTED — escape at render.
    pub builder: String,
}

/// An image's observed build-provenance posture (ADR-0020 §5, JEF-275). Four definitive resting
/// states plus one transient. Never `NotApplicable`: observation always reaches a posture, and a
/// registry blip is the explicit [`Checking`](Self::Checking), not a fake clean.
///
/// SECURITY: only [`Verified`](Self::Verified) confers a trusted `(source, builder)`. Every other
/// state — including the common [`Absent`](Self::Absent) — is calm-but-NOT-trusted; a consumer must
/// never read absent/unverifiable provenance as a trusted build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenancePosture {
    /// **Verified**: a SLSA provenance attestation is present, its DSSE envelope + Fulcio cert
    /// chained to the trusted root and its Rekor inclusion verified, and its predicate yielded a
    /// builder identity. The only posture that confers a trusted build.
    Verified(Provenance),
    /// **Present but unverifiable here**: a provenance attestation artifact is present but could not
    /// be verified against our trust root (a Rekor/TUF variance), or it verified but carried no
    /// extractable builder identity. Honest "present, not trusted here" — never trusted.
    Unverifiable,
    /// **No provenance**: no SLSA provenance attestation at all — the common case today. Calm (like
    /// a never-signed image), never an alarm, but never a trusted build either.
    Absent,
    /// Transient: the registry / transparency log was unreachable, so the posture is not yet known.
    /// Resolves into a resting state on a later pass. Never rendered as resting, never read as clean.
    Checking,
}

impl ProvenancePosture {
    /// A stable, low-cardinality word for the posture — for logs, metrics, and the inventory column.
    /// The `(source, builder)` are NOT included here — they are untrusted text the caller escapes
    /// separately.
    pub fn status(&self) -> &'static str {
        match self {
            ProvenancePosture::Verified(_) => "provenance-verified",
            ProvenancePosture::Unverifiable => "provenance-unverifiable",
            ProvenancePosture::Absent => "no-provenance",
            ProvenancePosture::Checking => "provenance-checking",
        }
    }

    /// The provenance, when this posture is [`Verified`](Self::Verified).
    pub fn provenance(&self) -> Option<&Provenance> {
        match self {
            ProvenancePosture::Verified(p) => Some(p),
            _ => None,
        }
    }

    /// Whether this is a definitive resting state, as opposed to the transient
    /// [`Checking`](Self::Checking). Only resting postures are worth caching.
    pub fn is_resting(&self) -> bool {
        !matches!(self, ProvenancePosture::Checking)
    }
}

/// The verification-relevant facts extracted from one fetched attestation layer (JEF-275),
/// decoupled from sigstore's type so [`classify_provenance`] is exhaustively unit-testable without
/// synthesising a full Fulcio cert + DSSE envelope. Built ONLY for layers whose in-toto predicate
/// type [`is_slsa_predicate_type`]; a plain signature layer never produces one.
#[derive(Debug, Clone)]
pub struct ProvenanceFacts {
    /// The in-toto predicate type from the attestation (`https://slsa.dev/provenance/v1`, …).
    pub predicate_type: String,
    /// The parsed SLSA predicate object, if the DSSE payload could be decoded. `None` when the
    /// payload was absent/unparseable — a present-but-opaque attestation.
    pub predicate: Option<serde_json::Value>,
    /// Whether sigstore populated a verified Fulcio signer for this layer — i.e. the attestation's
    /// cert chained to the trusted root AND its Rekor inclusion verified. Only a `true` here can
    /// confer a trusted build.
    pub keyless_verified: bool,
}

/// Classify a build-provenance posture from fetched attestation facts (ADR-0020 §5, JEF-275). Pure
/// classification — the Fulcio/Rekor chain is the trust anchor, no config required. Precedence:
///   1. a **keyless-verified** SLSA layer whose predicate yields a builder identity ⇒
///      [`Verified`](ProvenancePosture::Verified) — the one trusted-build posture;
///   2. else any SLSA attestation layer present (unverified, or verified-but-no-builder) ⇒
///      [`Unverifiable`](ProvenancePosture::Unverifiable) — honest "present, not trusted here";
///   3. no SLSA attestation at all ⇒ [`Absent`](ProvenancePosture::Absent).
///
/// The transient [`Checking`](ProvenancePosture::Checking) is produced by the observer on a fetch
/// error, never here. SECURITY: nothing below step 1 is ever read as a trusted build.
pub fn classify_provenance(facts: &[ProvenanceFacts]) -> ProvenancePosture {
    if let Some(provenance) = facts.iter().find_map(|f| {
        if !f.keyless_verified {
            return None;
        }
        let predicate = f.predicate.as_ref()?;
        parse_slsa_predicate(&f.predicate_type, predicate)
    }) {
        return ProvenancePosture::Verified(provenance);
    }
    if facts.is_empty() {
        ProvenancePosture::Absent
    } else {
        ProvenancePosture::Unverifiable
    }
}

/// Parse the source repo + builder identity out of a SLSA provenance predicate (ADR-0020 §5). Total
/// and side-effect-free, so it is exhaustively unit-testable. Handles both SLSA v0.2 and v1 shapes.
/// Returns `None` when no builder identity can be read — a verified attestation with no builder is
/// not a trusted build (it downgrades to [`Unverifiable`](ProvenancePosture::Unverifiable)).
///
/// Every extracted string is UNTRUSTED — the caller escapes it at render.
pub fn parse_slsa_predicate(
    predicate_type: &str,
    predicate: &serde_json::Value,
) -> Option<Provenance> {
    let (builder, source_uri) = match predicate_type {
        SLSA_PROVENANCE_V1 => {
            // v1: builder under runDetails.builder.id; source under
            // buildDefinition.externalParameters.workflow.repository (GitHub's shape), falling back
            // to the first resolvedDependencies URI.
            let builder = predicate
                .pointer("/runDetails/builder/id")
                .and_then(|v| v.as_str());
            let source = predicate
                .pointer("/buildDefinition/externalParameters/workflow/repository")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    predicate
                        .pointer("/buildDefinition/resolvedDependencies/0/uri")
                        .and_then(|v| v.as_str())
                });
            (builder, source)
        }
        SLSA_PROVENANCE_V02 => {
            // v0.2: builder under builder.id; source under invocation.configSource.uri, falling back
            // to the first materials URI.
            let builder = predicate.pointer("/builder/id").and_then(|v| v.as_str());
            let source = predicate
                .pointer("/invocation/configSource/uri")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    predicate
                        .pointer("/materials/0/uri")
                        .and_then(|v| v.as_str())
                });
            (builder, source)
        }
        _ => (None, None),
    };

    let builder = builder.map(str::to_string).filter(|s| !s.is_empty())?;
    let source_repo = source_uri
        .map(clean_source_uri)
        .filter(|s| !s.is_empty())
        // A builder id can double as the source when the predicate carried no explicit source URI:
        // the builder URI's `org/repo` is the honest fallback, never fabricated.
        .unwrap_or_else(|| clean_source_uri(&builder));
    Some(Provenance {
        source_repo,
        builder,
    })
}

/// Normalize a SLSA source/material URI to a stable repo identity for baseline keying + display.
/// Strips a `git+` scheme prefix, an `https://`/`http://` scheme, and a trailing `@<ref>` git ref,
/// leaving e.g. `github.com/org/repo`. Any other shape is returned trimmed (still UNTRUSTED).
fn clean_source_uri(uri: &str) -> String {
    let without_git = uri.strip_prefix("git+").unwrap_or(uri);
    let without_scheme = without_git
        .strip_prefix("https://")
        .or_else(|| without_git.strip_prefix("http://"))
        .unwrap_or(without_git);
    // Drop a trailing git ref (`@refs/tags/v1`, `@<sha>`), keeping the repo path.
    without_scheme
        .split_once('@')
        .map(|(before, _)| before)
        .unwrap_or(without_scheme)
        .trim_end_matches('/')
        .to_string()
}

use async_trait::async_trait;

/// Reads an image's build-provenance posture by observation, with NO trusted-identity config
/// (ADR-0020 §5). Abstracted behind a trait — exactly like
/// [`SignatureObserver`](super::posture::SignatureObserver) — so the observation + caching + sweep
/// logic is unit-testable with a fake, without reaching a registry or the sigstore TUF root.
#[async_trait]
pub trait ProvenanceObserver: Send + Sync {
    /// Observe `image`'s provenance posture. Never errors: an infrastructure failure is the
    /// transient [`Checking`](ProvenancePosture::Checking) state, not an `Err` — the caller must
    /// always be handed a posture, never forced to invent one.
    async fn observe_provenance(&self, image: &str) -> ProvenancePosture;
}

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// The in-memory record of the latest observed provenance posture per image (ADR-0020 §5). Keyed by
/// image ref, last-write-wins — the per-pass provenance map, mirroring
/// [`PostureMap`](super::posture::PostureMap).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ProvenanceMap {
    images: HashMap<String, ProvenancePosture>,
}

impl ProvenanceMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `image`'s observed provenance posture (last-write-wins).
    pub fn record(&mut self, image: impl Into<String>, posture: ProvenancePosture) {
        self.images.insert(image.into(), posture);
    }

    /// The posture recorded for `image`, if any.
    pub fn get(&self, image: &str) -> Option<&ProvenancePosture> {
        self.images.get(image)
    }

    pub fn len(&self) -> usize {
        self.images.len()
    }

    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }

    /// All observed `(image, posture)` pairs — what the inventory render + baseline learning read.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &ProvenancePosture)> {
        self.images.iter().map(|(k, v)| (k.as_str(), v))
    }
}

/// Drives build-provenance observation off a bounded, cached verification budget (ADR-0020 §5;
/// ADR-0015 sanctioned-egress path). Mirrors [`SigningObserver`](super::posture::SigningObserver)
/// exactly — a TTL + image-keyed cache of *resting* postures (a `Checking` blip is never cached, so
/// it retries next pass) and a `max_images` cap per [`sweep`](Self::sweep) — so observing every
/// image's provenance stays within the same already-sanctioned outbound envelope and adds ZERO
/// outbound calls for an image observed again within the TTL.
pub struct ProvenanceScanner {
    observer: Arc<dyn ProvenanceObserver>,
    max_images: usize,
    cache_ttl: Duration,
    cache: Mutex<HashMap<String, (ProvenancePosture, Instant)>>,
}

impl ProvenanceScanner {
    pub fn new(
        observer: Arc<dyn ProvenanceObserver>,
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

    /// Observe one image, serving a fresh cached resting posture without an outbound call. A
    /// `Checking` result is never cached (so the next observation retries the registry).
    pub async fn observe(&self, image: &str) -> ProvenancePosture {
        if let Some((posture, cached_at)) = self.cache.lock().await.get(image).cloned()
            && cached_at.elapsed() < self.cache_ttl
        {
            return posture;
        }
        let posture = self.observer.observe_provenance(image).await;
        if posture.is_resting() {
            self.cache
                .lock()
                .await
                .insert(image.to_string(), (posture.clone(), Instant::now()));
        }
        posture
    }

    /// Observe a set of images, returning a [`ProvenanceMap`] of what was observed this pass.
    /// Distinct images only, at most `max_images` verified — the surplus is left unobserved rather
    /// than spending unbounded outbound calls, exactly as the signing sweep caps a Pod's images.
    pub async fn sweep<I, S>(&self, images: I) -> ProvenanceMap
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
        let mut map = ProvenanceMap::new();
        for image in distinct.into_iter().take(self.max_images) {
            let posture = self.observe(&image).await;
            map.record(image, posture);
        }
        map
    }
}

#[cfg(test)]
#[path = "provenance_tests.rs"]
mod tests;
