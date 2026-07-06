//! Image-signature admission policy ([`SignaturePolicy`]) and the cosign verifier behind
//! it, split into a module directory (repo CLAUDE.md's 1,000-line cap) ahead of ADR-0020's
//! signing-posture work:
//!
//!   * [`cosign`] — the production [`CosignChecker`] (the one verifier that reaches the
//!     registry + Rekor).
//!   * [`posture`] — ADR-0020 Stage 1 signing-posture observation ([`SigningPosture`],
//!     [`SignatureObserver`], [`SigningObserver`], [`PostureMap`]).
//!   * this file — the gated [`SignaturePolicy`] (behavior-identical to before the split)
//!     and the shared image-extraction / host-normalization helpers.

mod auth;
pub mod continuity;
mod cosign;
pub mod posture;
pub mod provenance;
pub mod rekor;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use kube::core::DynamicObject;
use kube::core::admission::AdmissionRequest;
use tokio::sync::Mutex;

use crate::policy::{Decision, EnforceScope, Policy, ShadowVerdict};

pub use auth::registry_auth;
pub use continuity::{ContinuityGate, SigningExceptions, SigningPin};
pub use cosign::CosignChecker;
pub use posture::{
    PostureMap, PostureRank, SignatureObserver, Signer, SigningObserver, SigningPosture,
    canonical_identity,
};
pub use provenance::{
    Provenance, ProvenanceMap, ProvenanceObserver, ProvenancePosture, ProvenanceScanner,
};
pub use rekor::{HttpRekorClient, RekorClient, RekorConfig, RekorHistory, RekorLane};

/// Decides whether a single image reference carries a trusted signature.
///
/// Abstracted behind a trait so the policy's decision logic (gating, audit vs
/// enforce, caching) can be unit-tested with a fake, without reaching out to a
/// registry or the sigstore TUF root.
#[async_trait]
pub trait SignatureChecker: Send + Sync {
    /// `Ok(true)` if `image` carries a signature from the trusted identity,
    /// `Ok(false)` if it is unsigned or signed by an untrusted identity, and
    /// `Err` only on an infrastructure failure (registry/network/TUF) — which
    /// the caller treats differently from a definitive "unsigned".
    async fn is_signed(&self, image: &str) -> Result<bool>;
}

/// Rejects Pods whose container images aren't cosign-signed by a trusted
/// identity. This is the one policy that genuinely needs admission-time
/// enforcement — a CI audit can't stop an unsigned image from being pulled.
///
/// Only images whose ref starts with one of `gated_prefixes` are checked;
/// third-party images (postgres, linkerd, …) aren't signed by us and are out of
/// scope. With `enforce = false` the policy logs violations but allows them, so
/// it can be deployed in audit mode and flipped on once the logs are clean.
pub struct SignaturePolicy {
    checker: Arc<dyn SignatureChecker>,
    gated_prefixes: Vec<String>,
    /// Where this policy denies vs audits. Audit everywhere by default.
    enforce: EnforceScope,
    /// Upper bound on distinct gated images verified per admission, so a Pod
    /// with hundreds of (init/ephemeral) containers can't amplify outbound
    /// verification work into a DoS.
    max_images: usize,
    /// How long a cached verdict stays valid. Bounds the mutable-tag TOCTOU: a
    /// re-pointed tag is re-verified once its entry ages past the TTL, instead
    /// of being trusted forever.
    cache_ttl: Duration,
    /// image ref → (verified, when-cached). Avoids re-hitting the registry/Rekor
    /// for an image we recently judged.
    cache: Mutex<HashMap<String, (bool, Instant)>>,
    /// The ADR-0020 Stage-3 signing-CONTINUITY gate (JEF-265): denies (in enforced scope) on a
    /// signing regression against the engine-learned, read-only baseline, with a scoped
    /// "exception accepted" opt-out + back-compat pins. `None` ⇒ continuity is unwired, so the
    /// policy behaves EXACTLY as the pre-JEF-265 gated gate (unconfigured = byte-identical shadow).
    continuity: Option<ContinuityGate>,
}

impl SignaturePolicy {
    pub fn new(
        checker: Arc<dyn SignatureChecker>,
        gated_prefixes: Vec<String>,
        enforce: EnforceScope,
        max_images: usize,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            checker,
            gated_prefixes,
            enforce,
            max_images,
            cache_ttl,
            cache: Mutex::new(HashMap::new()),
            continuity: None,
        }
    }

    /// Attach the ADR-0020 Stage-3 signing-continuity gate (JEF-265). Builder-style so `new` stays
    /// the minimal constructor the existing tests + the pre-JEF-265 gated deploy use unchanged.
    /// Without this, `continuity` is `None` and the policy is byte-identical shadow.
    pub fn with_continuity(mut self, continuity: ContinuityGate) -> Self {
        self.continuity = Some(continuity);
        self
    }

    /// Whether this image is in scope for signature enforcement. The registry
    /// host is normalized first so a case variant (`GHCR.IO/…`) — which a
    /// container runtime resolves to the same image — can't slip past the gate.
    fn gated(&self, image: &str) -> bool {
        let normalized = normalize_registry_host(image);
        self.gated_prefixes
            .iter()
            .any(|p| normalized.starts_with(p.as_str()))
    }

    /// `is_signed` with a TTL-bounded memoized result. Only definitive verdicts
    /// are cached; infrastructure errors propagate so a transient registry blip
    /// isn't frozen into a verdict.
    async fn is_signed_cached(&self, image: &str) -> Result<bool> {
        if let Some((verified, cached_at)) = self.cache.lock().await.get(image).copied()
            && cached_at.elapsed() < self.cache_ttl
        {
            return Ok(verified);
        }
        let verified = self.checker.is_signed(image).await?;
        self.cache
            .lock()
            .await
            .insert(image.to_string(), (verified, Instant::now()));
        Ok(verified)
    }

    /// The legacy gated single-identity gate's decision for `req` (the pre-JEF-265 behavior,
    /// unchanged): every distinct gated image must be signed by the trusted identity, else deny
    /// (in scope) / audit (out of scope). Extracted so [`evaluate`](Policy::evaluate) can combine
    /// it with the continuity gate without duplicating the gating logic.
    async fn gated_decision(
        &self,
        req: &AdmissionRequest<DynamicObject>,
        obj: &DynamicObject,
    ) -> Decision {
        // Collect the distinct gated images once, so duplicates don't double the
        // work and the count can be bounded.
        let mut gated: Vec<String> = Vec::new();
        for image in pod_images(obj) {
            if self.gated(&image) && !gated.contains(&image) {
                gated.push(image);
            }
        }

        if gated.len() > self.max_images {
            return self.enforce.decide(
                req,
                format!(
                    "Pod references {} gated images (max {})",
                    gated.len(),
                    self.max_images
                ),
            );
        }

        let mut unsigned = Vec::new();
        for image in &gated {
            match self.is_signed_cached(image).await {
                Ok(true) => {}
                Ok(false) => unsigned.push(image.clone()),
                Err(err) => {
                    // Couldn't reach the registry/TUF to decide. Where enforcing,
                    // we must not silently admit a gated image; where auditing, we
                    // allow but log.
                    tracing::warn!(%image, error = %err, "signature verification errored");
                    if self.enforce.enforces(req) {
                        return Decision::deny(format!(
                            "could not verify signature for {image}: {err}"
                        ));
                    }
                }
            }
        }

        if unsigned.is_empty() {
            return Decision::Allow;
        }
        self.enforce.decide(
            req,
            format!("unsigned or untrusted image(s): {}", unsigned.join(", ")),
        )
    }
}

/// Combine two outcomes from the same policy (the legacy gated gate + the continuity gate) into the
/// single most-severe one: `Deny` beats `Audit` beats `Allow`. A `Deny` is already short-circuited
/// before this is reached; this resolves the `Audit`/`Allow` cases so an out-of-scope block still
/// records as an audit and a clean pass stays `Allow`.
fn more_severe(a: Decision, b: Decision) -> Decision {
    fn rank(d: &Decision) -> u8 {
        match d {
            Decision::Deny { .. } => 2,
            Decision::Audit { .. } => 1,
            Decision::Allow => 0,
        }
    }
    if rank(&b) > rank(&a) { b } else { a }
}

#[async_trait]
impl Policy for SignaturePolicy {
    fn name(&self) -> &'static str {
        "image-signature"
    }

    fn applies(&self, req: &AdmissionRequest<DynamicObject>) -> bool {
        req.kind.kind == "Pod"
    }

    async fn evaluate(&self, req: &AdmissionRequest<DynamicObject>) -> Decision {
        let Some(obj) = req.object.as_ref() else {
            return Decision::Allow;
        };

        // The legacy gated single-identity gate (now understood as the ADR-0020 pinned special
        // case). Its decision is authoritative on a hard deny — a gated-image failure short-circuits
        // exactly as before, so back-compat is byte-identical when continuity is unwired.
        let gated = self.gated_decision(req, obj).await;
        if matches!(gated, Decision::Deny { .. }) {
            return gated;
        }

        // The ADR-0020 Stage-3 continuity gate (JEF-265): deny (in enforced scope) on a signing
        // regression against the read-only, engine-learned baseline. Unwired ⇒ nothing added, so an
        // unconfigured deploy is byte-identical shadow. Consults ALL container images (continuity is
        // per-repo, not gated-prefix scoped), classified against the shared baseline.
        let continuity = match &self.continuity {
            Some(gate) => match gate.evaluate(&pod_images(obj)).await {
                Some(reason) => self.enforce.decide(req, reason),
                None => Decision::Allow,
            },
            None => Decision::Allow,
        };

        more_severe(gated, continuity)
    }

    async fn shadow_evaluate(&self, req: &AdmissionRequest<DynamicObject>) -> ShadowVerdict {
        // The counterfactual (JEF-246): what this gate WOULD do for `req` if it were in scope and
        // enforced — computed for EVERY request, even out of scope. It shares enforcement's exact
        // verification mechanism: the SAME digest-bounded `is_signed_cached`, so a shadow eval of
        // an image already verified (this pass or a recent one — and so for every replica/pass)
        // hits the cache and adds NO outbound calls. Zero-egress is preserved: shadow-verifying
        // every request never reaches the registry/Rekor more than enforcement already does.
        let Some(obj) = req.object.as_ref() else {
            return ShadowVerdict::NotApplicable;
        };
        let enforced = self.enforce.enforces(req);

        let mut gated: Vec<String> = Vec::new();
        for image in pod_images(obj) {
            if self.gated(&image) && !gated.contains(&image) {
                gated.push(image);
            }
        }
        // No gated images ⇒ the legacy gate has no opinion. The continuity gate (JEF-265) still
        // might — a would-block regression on ANY repo is an honest would-fail even out of gated
        // scope — so consult it before reporting NotApplicable. This escalates only (a continuity
        // block becomes would-fail); it never fabricates a green pass for an ungated Pod.
        if gated.is_empty() {
            if let Some(reason) = self.continuity_block(obj).await {
                return ShadowVerdict::fail(enforced, reason);
            }
            return ShadowVerdict::NotApplicable;
        }
        if gated.len() > self.max_images {
            return ShadowVerdict::fail(
                enforced,
                format!(
                    "Pod references {} gated images (max {})",
                    gated.len(),
                    self.max_images
                ),
            );
        }

        // An image is a what-if FAIL if it's unsigned OR couldn't be verified: enforcing would
        // deny either way, so the counterfactual must report would-fail (never a false green).
        let mut failed = Vec::new();
        for image in &gated {
            match self.is_signed_cached(image).await {
                Ok(true) => {}
                Ok(false) => failed.push(image.clone()),
                Err(_) => failed.push(image.clone()),
            }
        }
        if !failed.is_empty() {
            return ShadowVerdict::fail(
                enforced,
                format!("unsigned or untrusted image(s): {}", failed.join(", ")),
            );
        }
        // The gated images all pass; a continuity regression on any image is still a would-fail.
        if let Some(reason) = self.continuity_block(obj).await {
            return ShadowVerdict::fail(enforced, reason);
        }
        ShadowVerdict::pass(enforced)
    }
}

impl SignaturePolicy {
    /// The continuity gate's would-block reason for `obj`'s images, or `None` when continuity is
    /// unwired or nothing blocks. Shares the gate's `observe` cache with [`evaluate`](Policy::evaluate)
    /// (no extra egress). Used by the shadow what-if so the recorded signature column honestly reads
    /// would-fail for a regression even out of enforced scope.
    async fn continuity_block(&self, obj: &DynamicObject) -> Option<String> {
        match &self.continuity {
            Some(gate) => gate.evaluate(&pod_images(obj)).await,
            None => None,
        }
    }
}

/// Canonicalize the registry host (the segment before the first `/`) so cosmetic
/// variants a container runtime resolves to the *same* image can't slip past the
/// gated-prefix check:
///
/// - lowercase the host (`GHCR.IO/…` → `ghcr.io/…`),
/// - strip a fully-qualified-domain trailing dot (`ghcr.io./…` → `ghcr.io/…`),
/// - strip an explicit default port (`ghcr.io:443/…`, `ghcr.io:80/…` →
///   `ghcr.io/…`).
///
/// A bare Docker Hub shorthand (`postgres:16`, `library/postgres`) has no host
/// segment and is left untouched.
pub(crate) fn normalize_registry_host(image: &str) -> String {
    match image.split_once('/') {
        // A registry host has a dot (domain) or a colon (port); a leading path
        // segment without either is a Docker Hub repo, not a host.
        Some((host, rest)) if host.contains('.') || host.contains(':') => {
            format!("{}/{}", canonical_host(host), rest)
        }
        _ => image.to_string(),
    }
}

/// The canonical **repository** key for an image ref (JEF-263, ADR-0020): the registry
/// host canonicalized exactly as the gate does (via [`normalize_registry_host`]), then the
/// mutable `:tag` and/or `@digest` stripped so every tag/digest under one source folds to a
/// single key. This is the TOFU baseline key — signing history is learned per *repository*
/// (`ghcr.io/org/app`), never per tag/digest, so a new tag under an established repo is the
/// same key (not a new baseline, not drift).
///
/// The tag is stripped only from the LAST path segment, so a registry `host:port`
/// (`localhost:5000/app`) is preserved. A bare Docker Hub shorthand (`postgres:16`) has no
/// host segment and folds to its repo (`postgres`).
pub fn repo_key(image: &str) -> String {
    let normalized = normalize_registry_host(image);
    // Strip a `@sha256:…` digest first (it can itself contain a colon).
    let without_digest = normalized
        .split_once('@')
        .map(|(before, _)| before)
        .unwrap_or(&normalized);
    // Strip the `:tag`, but only within the final path segment — a `host:port` earlier in
    // the ref is part of the repo identity and must survive.
    let cut = match without_digest.rfind('/') {
        Some(slash) => match without_digest[slash + 1..].rfind(':') {
            Some(colon) => slash + 1 + colon,
            None => without_digest.len(),
        },
        None => without_digest.rfind(':').unwrap_or(without_digest.len()),
    };
    without_digest[..cut].to_string()
}

/// Canonicalize a single registry-host segment: lowercase, drop an explicit
/// default port (`:443`/`:80`), and drop a FQDN trailing dot. The port is split
/// off the end first, then the trailing dot, so `ghcr.io.:443` reduces to
/// `ghcr.io`. A non-default port is part of the registry identity and is kept.
fn canonical_host(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    let without_port = match host.rsplit_once(':') {
        Some((h, "443" | "80")) => h,
        _ => host.as_str(),
    };
    without_port
        .strip_suffix('.')
        .unwrap_or(without_port)
        .to_string()
}

/// Collect every container image referenced by a Pod object: regular, init, and
/// ephemeral containers.
fn pod_images(obj: &DynamicObject) -> Vec<String> {
    let spec = &obj.data["spec"];
    let mut images = Vec::new();
    for field in ["containers", "initContainers", "ephemeralContainers"] {
        if let Some(containers) = spec.get(field).and_then(|v| v.as_array()) {
            for container in containers {
                if let Some(image) = container.get("image").and_then(|v| v.as_str()) {
                    images.push(image.to_string());
                }
            }
        }
    }
    images
}
