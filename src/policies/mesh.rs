use std::collections::HashSet;

use async_trait::async_trait;
use kube::core::DynamicObject;
use kube::core::admission::AdmissionRequest;

use crate::policy::{Decision, Policy};

/// Rejects Pods that aren't Linkerd-meshed, outside an exempt set of namespaces.
///
/// GitOps already enforces the mesh for everything declared in charts, so this
/// policy earns its keep on workloads that *aren't* in git. Linkerd's mutating
/// proxy-injector runs *before* validating webhooks, so by the time protector
/// sees a Pod an opted-in workload already carries the `linkerd-proxy` sidecar —
/// we check for that injected container (the post-injection truth) rather than
/// trusting the network alone.
///
/// Namespace exemptions are essential, not optional: this cluster *deliberately*
/// leaves the runner namespace unmeshed so untrusted runners have no mesh
/// identity. Enforcing injection there would break that design — so the runner
/// namespace (and the control plane) must be exempt. Ships with `enforce =
/// false` (audit) like the signature policy.
pub struct MeshInjectionPolicy {
    enforce: bool,
    exempt_namespaces: HashSet<String>,
}

impl MeshInjectionPolicy {
    pub fn new(enforce: bool, exempt_namespaces: HashSet<String>) -> Self {
        Self {
            enforce,
            exempt_namespaces,
        }
    }
}

#[async_trait]
impl Policy for MeshInjectionPolicy {
    fn name(&self) -> &'static str {
        "mesh-injection"
    }

    fn applies(&self, req: &AdmissionRequest<DynamicObject>) -> bool {
        req.kind.kind == "Pod"
    }

    async fn evaluate(&self, req: &AdmissionRequest<DynamicObject>) -> Decision {
        // The runner namespace and the control plane are intentionally unmeshed.
        if let Some(ns) = req.namespace.as_deref()
            && self.exempt_namespaces.contains(ns)
        {
            return Decision::Allow;
        }

        let Some(obj) = req.object.as_ref() else {
            return Decision::Allow;
        };
        if pod_is_meshed(obj) {
            return Decision::Allow;
        }

        let msg = "Pod is not Linkerd-meshed (no injected linkerd-proxy) and its \
                   namespace is not exempt"
            .to_string();
        if self.enforce {
            Decision::deny(msg)
        } else {
            tracing::warn!(audit = true, "{msg} — allowing (audit mode)");
            Decision::Allow
        }
    }
}

/// Whether the Pod carries Linkerd's injected sidecar. Checks for the
/// `linkerd-proxy` container (added by the mutating injector, which runs before
/// this validating webhook), falling back to an explicit `linkerd.io/inject`
/// annotation requesting injection.
fn pod_is_meshed(obj: &DynamicObject) -> bool {
    let spec = &obj.data["spec"];
    for field in ["containers", "initContainers"] {
        if let Some(containers) = spec.get(field).and_then(|v| v.as_array())
            && containers
                .iter()
                .any(|c| c.get("name").and_then(|v| v.as_str()) == Some("linkerd-proxy"))
        {
            return true;
        }
    }
    obj.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get("linkerd.io/inject"))
        .is_some_and(|v| v == "enabled" || v == "ingress")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pod_request(namespace: &str, spec: serde_json::Value) -> AdmissionRequest<DynamicObject> {
        let review: kube::core::admission::AdmissionReview<DynamicObject> =
            serde_json::from_value(json!({
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "request": {
                    "uid": "u",
                    "kind": {"group": "", "version": "v1", "kind": "Pod"},
                    "resource": {"group": "", "version": "v1", "resource": "pods"},
                    "name": "demo",
                    "namespace": namespace,
                    "operation": "CREATE",
                    "userInfo": {},
                    "object": {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {"name": "demo", "namespace": namespace},
                        "spec": spec
                    }
                }
            }))
            .expect("valid review");
        review.try_into().expect("has request")
    }

    fn policy(enforce: bool) -> MeshInjectionPolicy {
        MeshInjectionPolicy::new(enforce, HashSet::from(["dev".to_string()]))
    }

    #[tokio::test]
    async fn allows_meshed_pod() {
        let p = policy(true);
        let spec = json!({"containers": [
            {"name": "app", "image": "x"},
            {"name": "linkerd-proxy", "image": "cr.l5d.io/linkerd/proxy"}
        ]});
        assert!(matches!(
            p.evaluate(&pod_request("public", spec)).await,
            Decision::Allow
        ));
    }

    #[tokio::test]
    async fn denies_unmeshed_pod_when_enforcing() {
        let p = policy(true);
        let spec = json!({"containers": [{"name": "app", "image": "x"}]});
        assert!(matches!(
            p.evaluate(&pod_request("public", spec)).await,
            Decision::Deny { .. }
        ));
    }

    #[tokio::test]
    async fn allows_unmeshed_pod_in_exempt_namespace() {
        // The runner namespace is deliberately unmeshed.
        let p = policy(true);
        let spec = json!({"containers": [{"name": "runner", "image": "x"}]});
        assert!(matches!(
            p.evaluate(&pod_request("dev", spec)).await,
            Decision::Allow
        ));
    }

    #[tokio::test]
    async fn allows_unmeshed_pod_in_audit_mode() {
        let p = policy(false);
        let spec = json!({"containers": [{"name": "app", "image": "x"}]});
        assert!(matches!(
            p.evaluate(&pod_request("public", spec)).await,
            Decision::Allow
        ));
    }
}
