use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use kube::core::DynamicObject;
use kube::core::admission::AdmissionRequest;
use regex::Regex;
use sigstore::cosign::signature_layers::CertificateSubject;
use sigstore::cosign::verification_constraint::VerificationConstraint;
use sigstore::cosign::{
    Client, ClientBuilder, CosignCapabilities, SignatureLayer, verify_constraints,
};
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
    /// image ref → verified. Avoids re-hitting the registry/Rekor for an image
    /// we've already judged. NOTE: keyed on the ref as written, so a moved tag
    /// isn't re-checked until restart — digest-pinning is the follow-up that
    /// closes that TOCTOU window.
    cache: Mutex<HashMap<String, bool>>,
}

impl SignaturePolicy {
    pub fn new(
        checker: Arc<dyn SignatureChecker>,
        gated_prefixes: Vec<String>,
        enforce: bool,
    ) -> Self {
        Self {
            checker,
            gated_prefixes,
            enforce,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Whether this image is in scope for signature enforcement.
    fn gated(&self, image: &str) -> bool {
        self.gated_prefixes.iter().any(|p| image.starts_with(p))
    }

    /// `is_signed` with a memoized result. Only definitive verdicts are cached;
    /// infrastructure errors propagate so a transient registry blip isn't
    /// frozen into a permanent "unsigned".
    async fn is_signed_cached(&self, image: &str) -> Result<bool> {
        if let Some(&verified) = self.cache.lock().await.get(image) {
            return Ok(verified);
        }
        let verified = self.checker.is_signed(image).await?;
        self.cache.lock().await.insert(image.to_string(), verified);
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

        let mut unsigned = Vec::new();
        for image in pod_images(obj) {
            if !self.gated(&image) {
                continue;
            }
            match self.is_signed_cached(&image).await {
                Ok(true) => {}
                Ok(false) => unsigned.push(image),
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

        let msg = format!("unsigned or untrusted image(s): {}", unsigned.join(", "));
        if self.enforce {
            Decision::deny(msg)
        } else {
            tracing::warn!(audit = true, "{msg} — allowing (audit mode)");
            Decision::Allow
        }
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
    /// Regex the signing cert's SAN identity must match (e.g. our org's
    /// GitHub Actions workflow URLs).
    identity: Regex,
    /// OIDC issuer expected in the signing cert.
    oidc_issuer: String,
    /// Registry credentials, when the gated images are private.
    auth: Auth,
    /// Writable directory for the sigstore TUF cache (an emptyDir in-cluster).
    cache_dir: PathBuf,
    /// Built lazily on first verification: the TUF fetch is network I/O we don't
    /// want to block webhook startup on. `&mut self` methods on the client mean
    /// it lives behind a Mutex.
    client: OnceCell<Mutex<Client>>,
}

impl CosignChecker {
    pub fn new(
        identity_regexp: &str,
        oidc_issuer: String,
        auth: Auth,
        cache_dir: PathBuf,
    ) -> Result<Self> {
        Ok(Self {
            identity: Regex::new(identity_regexp)?,
            oidc_issuer,
            auth,
            cache_dir,
            client: OnceCell::new(),
        })
    }

    /// Get (or lazily build) the cosign client backed by the sigstore TUF root.
    async fn client(&self) -> Result<&Mutex<Client>> {
        self.client
            .get_or_try_init(|| async {
                let trust_root = SigstoreTrustRoot::new(Some(self.cache_dir.as_path())).await?;
                let client = ClientBuilder::default()
                    .with_trust_repository(&trust_root)?
                    .build()?;
                anyhow::Ok(Mutex::new(client))
            })
            .await
    }
}

#[async_trait]
impl SignatureChecker for CosignChecker {
    async fn is_signed(&self, image: &str) -> Result<bool> {
        let image_ref: OciReference = image.parse()?;
        // trusted_signature_layers triangulates internally and returns only the
        // layers whose embedded cert chains to the trusted Fulcio root and whose
        // Rekor bundle checks out — so an attacker-attached, unverifiable layer
        // never reaches the constraints below.
        let layers = {
            let client = self.client().await?;
            let mut client = client.lock().await;
            client
                .trusted_signature_layers(&self.auth, &image_ref)
                .await?
        };

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
/// matches a regex and whose OIDC issuer matches exactly. sigstore-rs ships only
/// an exact-match URL verifier; our identity is a per-repo GitHub Actions
/// workflow URL, so we need the regex (mirroring cosign's
/// `--certificate-identity-regexp`).
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
}
