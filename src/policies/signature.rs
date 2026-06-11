use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
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

use crate::policy::{Decision, Policy};

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
    enforce: bool,
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
        enforce: bool,
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

    /// Apply the audit/enforce decision to a human-readable violation message.
    fn violation(&self, msg: String) -> Decision {
        if self.enforce {
            Decision::deny(msg)
        } else {
            tracing::warn!(audit = true, "{msg} — allowing (audit mode)");
            Decision::Allow
        }
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
            return self.violation(format!(
                "Pod references {} gated images (max {})",
                gated.len(),
                self.max_images
            ));
        }

        let mut unsigned = Vec::new();
        for image in &gated {
            match self.is_signed_cached(image).await {
                Ok(true) => {}
                Ok(false) => unsigned.push(image.clone()),
                Err(err) => {
                    // Couldn't reach the registry/TUF to decide. In enforce mode
                    // we must not silently admit a gated image; in audit mode we
                    // allow but log.
                    tracing::warn!(%image, error = %err, "signature verification errored");
                    if self.enforce {
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
        self.violation(format!(
            "unsigned or untrusted image(s): {}",
            unsigned.join(", ")
        ))
    }
}

/// Lowercase the registry host (the segment before the first `/`) so a case
/// variant like `GHCR.IO/thejefflarson/app` — which container runtimes resolve
/// case-insensitively to the same image — normalizes to the gated form. A bare
/// Docker Hub shorthand (`postgres:16`, `library/postgres`) has no host segment
/// and is left untouched.
fn normalize_registry_host(image: &str) -> String {
    match image.split_once('/') {
        // A registry host has a dot (domain) or a colon (port); a leading path
        // segment without either is a Docker Hub repo, not a host.
        Some((host, rest)) if host.contains('.') || host.contains(':') => {
            format!("{}/{}", host.to_ascii_lowercase(), rest)
        }
        _ => image.to_string(),
    }
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
        // Force a start anchor: an operator-supplied pattern without `^` would
        // otherwise match anywhere in the SAN URI, accepting a cert whose
        // subject merely *contains* the trusted prefix.
        let anchored = if identity_regexp.starts_with('^') {
            identity_regexp.to_string()
        } else {
            format!("^(?:{identity_regexp})")
        };
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
            enforce,
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
            Decision::Allow => panic!("expected deny"),
        }
    }

    #[tokio::test]
    async fn allows_unsigned_gated_image_in_audit_mode() {
        let p = policy(&[("ghcr.io/thejefflarson/app:1", false)], false);
        assert!(matches!(
            p.evaluate(&pod_request(&["ghcr.io/thejefflarson/app:1"]))
                .await,
            Decision::Allow
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
            Decision::Allow => panic!("case-variant host evaded the gate"),
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
            true,
            32,
            Duration::from_secs(300),
        );
        let refs: Vec<String> = (0..40)
            .map(|i| format!("ghcr.io/thejefflarson/app{i}:1"))
            .collect();
        let refs: Vec<&str> = refs.iter().map(|s| s.as_str()).collect();
        match p.evaluate(&pod_request(&refs)).await {
            Decision::Deny { reason } => assert!(reason.contains("max 32")),
            Decision::Allow => panic!("expected deny on too many gated images"),
        }
    }
}
