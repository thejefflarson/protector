use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;
use kube::core::DynamicObject;
use kube::core::admission::AdmissionRequest;
use regex::Regex;
use sigstore::cosign::signature_layers::CertificateSubject;
use sigstore::cosign::verification_constraint::VerificationConstraint;
use sigstore::cosign::{ClientBuilder, CosignCapabilities, SignatureLayer, verify_constraints};
use sigstore::registry::{Auth, OciReference};
use sigstore::trust::sigstore::SigstoreTrustRoot;
use tokio::sync::{Mutex, OnceCell};

use crate::policy::{Decision, EnforceScope, Policy, ShadowVerdict};

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
        }
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
        // No gated images ⇒ the signature gate has no opinion about this Pod.
        if gated.is_empty() {
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
        if failed.is_empty() {
            ShadowVerdict::pass(enforced)
        } else {
            ShadowVerdict::fail(
                enforced,
                format!("unsigned or untrusted image(s): {}", failed.join(", ")),
            )
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
fn normalize_registry_host(image: &str) -> String {
    match image.split_once('/') {
        // A registry host has a dot (domain) or a colon (port); a leading path
        // segment without either is a Docker Hub repo, not a host.
        Some((host, rest)) if host.contains('.') || host.contains(':') => {
            format!("{}/{}", canonical_host(host), rest)
        }
        _ => image.to_string(),
    }
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

/// The production [`SignatureChecker`]: verifies keyless cosign signatures with
/// sigstore-rs against the public-good sigstore TUF root.
pub struct CosignChecker {
    /// Regex the signing cert's SAN identity must match (start-anchored in
    /// [`new`](CosignChecker::new) so it can't match mid-string).
    identity: Regex,
    /// OIDC issuer expected in the signing cert.
    oidc_issuer: String,
    /// Registry credentials, when the gated images are private.
    auth: Auth,
    /// Writable directory for the sigstore TUF cache (an emptyDir in-cluster).
    cache_dir: PathBuf,
    /// Per-image wall-clock budget for the registry/Rekor round trip, so a slow
    /// or hung registry can't stall admission indefinitely.
    verify_timeout: Duration,
    /// The TUF trust root, fetched lazily once (network I/O we don't want to
    /// block webhook startup on). A fresh, cheap cosign `Client` is built from
    /// it per verification — so no shared lock is held across registry I/O and
    /// one slow image can't block unrelated admissions.
    trust_root: OnceCell<SigstoreTrustRoot>,
}

impl CosignChecker {
    pub fn new(
        identity_regexp: &str,
        oidc_issuer: String,
        auth: Auth,
        cache_dir: PathBuf,
        verify_timeout: Duration,
    ) -> Result<Self> {
        // Force a start anchor that binds the *whole* pattern. Wrapping the
        // alternation in a group is essential: a bare `^a|b` parses as
        // `(^a)|(b)`, leaving the second branch unanchored so it matches a
        // trusted prefix mid-string in a cert SAN. Always emit `^(?:…)`,
        // stripping one redundant leading `^` first so a pre-anchored pattern
        // doesn't become `^(?:^…)` (which `regex` rejects).
        let inner = identity_regexp.strip_prefix('^').unwrap_or(identity_regexp);
        let anchored = format!("^(?:{inner})");
        // sigstore-rs reads/writes the TUF trust-root cache in `cache_dir` but does
        // not create it. Under readOnlyRootFilesystem the cache points into a /tmp
        // emptyDir subdir that doesn't exist yet, so without this every verification
        // failed with `No such file or directory (os error 2)` — surfacing as a
        // spurious "signature verification errored" rather than a real verdict.
        std::fs::create_dir_all(&cache_dir)
            .with_context(|| format!("creating sigstore TUF cache dir {}", cache_dir.display()))?;
        Ok(Self {
            identity: Regex::new(&anchored)?,
            oidc_issuer,
            auth,
            cache_dir,
            verify_timeout,
            trust_root: OnceCell::new(),
        })
    }

    /// Get (or lazily fetch) the sigstore TUF trust root.
    async fn trust_root(&self) -> Result<&SigstoreTrustRoot> {
        self.trust_root
            .get_or_try_init(|| async {
                anyhow::Ok(SigstoreTrustRoot::new(Some(self.cache_dir.as_path())).await?)
            })
            .await
    }
}

#[async_trait]
impl SignatureChecker for CosignChecker {
    async fn is_signed(&self, image: &str) -> Result<bool> {
        let image_ref: OciReference = image.parse()?;
        let trust_root = self.trust_root().await?;
        // A fresh client per call — build() is local (TUF was already fetched),
        // so verifications run concurrently with no shared lock.
        let mut client = ClientBuilder::default()
            .with_trust_repository(trust_root)?
            .build()?;

        // trusted_signature_layers triangulates internally and returns only the
        // layers whose embedded cert chains to the trusted Fulcio root and whose
        // Rekor bundle checks out — so an attacker-attached, unverifiable layer
        // never reaches the constraints below. Bounded so a slow registry can't
        // stall admission.
        let layers = tokio::time::timeout(
            self.verify_timeout,
            client.trusted_signature_layers(&self.auth, &image_ref),
        )
        .await
        .map_err(|_| anyhow::anyhow!("verification timed out after {:?}", self.verify_timeout))??;

        let constraints: Vec<Box<dyn VerificationConstraint>> = vec![Box::new(IdentityVerifier {
            identity: self.identity.clone(),
            issuer: self.oidc_issuer.clone(),
        })];

        // Ok only if some trusted layer satisfies the identity+issuer constraint;
        // empty layers (unsigned) yield Err, which we map to "not signed".
        Ok(verify_constraints(&layers, constraints.iter()).is_ok())
    }
}

/// A [`VerificationConstraint`] that admits a signing cert whose SAN identity
/// matches a (start-anchored) regex and whose OIDC issuer matches exactly.
/// sigstore-rs ships only an exact-match URL verifier; our identity is a
/// per-repo GitHub Actions workflow URL, so we need the regex (mirroring
/// cosign's `--certificate-identity-regexp`).
#[derive(Debug)]
struct IdentityVerifier {
    identity: Regex,
    issuer: String,
}

impl VerificationConstraint for IdentityVerifier {
    fn verify(&self, signature_layer: &SignatureLayer) -> sigstore::errors::Result<bool> {
        let Some(cert) = signature_layer.certificate_signature.as_ref() else {
            return Ok(false);
        };
        let issuer_ok = cert.issuer.as_deref() == Some(self.issuer.as_str());
        let identity_ok = match &cert.subject {
            CertificateSubject::Uri(uri) => self.identity.is_match(uri),
            CertificateSubject::Email(_) => false,
        };
        Ok(issuer_ok && identity_ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashSet;

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
        assert!(
            !checker
                .identity
                .is_match("https://evil.example/prefix-https://gitlab.com/org/-suffix"),
            "second alternation branch matched mid-string — not anchored"
        );
        // The legitimate identities still match at the start.
        assert!(checker.identity.is_match("https://github.com/org/repo"));
        assert!(checker.identity.is_match("https://gitlab.com/org/repo"));
        // And a SAN that merely starts with a near-miss does not match.
        assert!(!checker.identity.is_match("https://gitlab.com/other/repo"));
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
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl SignatureChecker for CountingChecker {
        async fn is_signed(&self, _image: &str) -> Result<bool> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
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
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the image is verified once; replica/pass + shadow re-use the digest cache"
        );
    }
}
