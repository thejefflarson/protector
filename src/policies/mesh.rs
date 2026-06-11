use async_trait::async_trait;
use kube::core::DynamicObject;
use kube::core::admission::AdmissionRequest;

use crate::policy::{Decision, Policy};

/// Rejects workloads that aren't Linkerd-meshed.
///
/// GitOps already enforces the mesh for everything declared in charts, so this
/// policy earns its keep on workloads that *aren't* in git — above all the
/// untrusted GitHub Actions PR-build Pods, which are the cluster's main threat
/// model. It checks for the `linkerd.io/inject` annotation rather than trusting
/// the network alone.
///
/// Currently a stub that allows everything; the annotation check lands once the
/// namespace-exemption set (kube-system, argocd, the webhook's own namespace)
/// is settled so it can never block the control plane.
pub struct MeshInjectionPolicy;

#[async_trait]
impl Policy for MeshInjectionPolicy {
    fn name(&self) -> &'static str {
        "mesh-injection"
    }

    fn applies(&self, req: &AdmissionRequest<DynamicObject>) -> bool {
        req.kind.kind == "Pod"
    }

    async fn evaluate(&self, _req: &AdmissionRequest<DynamicObject>) -> Decision {
        // TODO: require `linkerd.io/inject: enabled` (or an injected proxy)
        // unless the namespace is exempt.
        Decision::Allow
    }
}
