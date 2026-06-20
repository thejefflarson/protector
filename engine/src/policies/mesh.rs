use async_trait::async_trait;
use kube::core::DynamicObject;
use kube::core::admission::AdmissionRequest;

use crate::policy::{Decision, EnforceScope, Policy};

/// Rejects Pods that aren't Linkerd-meshed, where enforcement is in scope.
///
/// GitOps already enforces the mesh for everything declared in charts, so this
/// policy earns its keep on workloads that *aren't* in git. Linkerd's mutating
/// proxy-injector runs *before* validating webhooks, so by the time protector
/// sees a Pod an opted-in workload already carries the `linkerd-proxy` sidecar —
/// we check for that injected container (the post-injection truth) rather than
/// trusting the network alone.
///
/// Audit-by-default is essential here, not just cautious: this cluster
/// *deliberately* leaves the runner namespace unmeshed so untrusted runners have
/// no mesh identity. Because enforcement is opt-in via [`EnforceScope`], you
/// simply never add the runner namespace to the mesh enforce allowlist — it (and
/// everything else not listed) is audited, never blocked.
pub struct MeshInjectionPolicy {
    enforce: EnforceScope,
}

impl MeshInjectionPolicy {
    pub fn new(enforce: EnforceScope) -> Self {
        Self { enforce }
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
        let Some(obj) = req.object.as_ref() else {
            return Decision::Allow;
        };
        // Mesh is for long-running, traffic-serving workloads. One-shot pods — Jobs,
        // CronJobs, and ephemeral helper/task pods (`restartPolicy` Never/OnFailure,
        // e.g. local-path-provisioner's PVC helpers) — don't serve traffic and
        // shouldn't carry a mesh identity (Linkerd's own guidance), so they're out of
        // scope. The webhook is blind to reachability — the engine's domain — and
        // `restartPolicy` is the signal available at admission that separates a
        // service from a task.
        if !pod_is_long_running(obj) {
            return Decision::Allow;
        }
        if pod_is_meshed(obj) {
            return Decision::Allow;
        }

        // Unmeshed: deny where enforcement is in scope, audit everywhere else.
        // Namespaces not on the enforce allowlist (the runner ns, by design) are
        // still reported, so an unexpectedly-unmeshed workload is discoverable.
        self.enforce.decide(
            req,
            "Pod is not Linkerd-meshed (no injected linkerd-proxy)".to_string(),
        )
    }
}

/// A long-running, traffic-serving workload — the only kind mesh applies to.
/// `restartPolicy` defaults to `Always` (the only value Deployments/StatefulSets/
/// DaemonSets allow); Job, CronJob, and helper pods use `Never`/`OnFailure` and are
/// one-shot tasks that don't need a mesh identity.
fn pod_is_long_running(obj: &DynamicObject) -> bool {
    matches!(
        obj.data["spec"]
            .get("restartPolicy")
            .and_then(|v| v.as_str()),
        None | Some("Always")
    )
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

    /// Enforce mesh only in "public"; everything else (incl. the runner ns
    /// "dev") is audited.
    fn policy() -> MeshInjectionPolicy {
        use std::collections::HashSet;
        MeshInjectionPolicy::new(EnforceScope::new(
            HashSet::from(["public".to_string()]),
            vec![],
        ))
    }

    #[tokio::test]
    async fn allows_meshed_pod() {
        let p = policy();
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
    async fn denies_unmeshed_pod_in_enforced_namespace() {
        let p = policy();
        let spec = json!({"containers": [{"name": "app", "image": "x"}]});
        assert!(matches!(
            p.evaluate(&pod_request("public", spec)).await,
            Decision::Deny { .. }
        ));
    }

    #[tokio::test]
    async fn audits_unmeshed_pod_outside_enforce_scope() {
        // The runner namespace isn't on the enforce allowlist: never denied, but
        // still reported so it's discoverable.
        let p = policy();
        let spec = json!({"containers": [{"name": "runner", "image": "x"}]});
        assert!(matches!(
            p.evaluate(&pod_request("dev", spec)).await,
            Decision::Audit { .. }
        ));
    }

    #[tokio::test]
    async fn one_shot_pods_are_out_of_scope_for_mesh() {
        // A one-shot helper/Job pod (restartPolicy != Always, e.g. local-path's PVC
        // helper) serves no traffic and is never flagged, even unmeshed in an
        // enforced namespace — no deny, no audit noise.
        let p = policy();
        for restart in ["Never", "OnFailure"] {
            let spec = json!({
                "restartPolicy": restart,
                "containers": [{"name": "helper", "image": "x"}]
            });
            assert!(
                matches!(
                    p.evaluate(&pod_request("public", spec)).await,
                    Decision::Allow
                ),
                "restartPolicy={restart} should be out of mesh scope"
            );
        }
        // A long-running service (default restartPolicy) is still enforced.
        let svc = json!({"containers": [{"name": "app", "image": "x"}]});
        assert!(matches!(
            p.evaluate(&pod_request("public", svc)).await,
            Decision::Deny { .. }
        ));
    }
}
