use async_trait::async_trait;
use kube::core::DynamicObject;
use kube::core::admission::AdmissionRequest;

/// Outcome of evaluating a single policy against one admission request.
#[derive(Debug, Clone)]
pub enum Decision {
    /// The request satisfies the policy.
    Allow,
    /// The request violates the policy. `reason` is surfaced to the API caller
    /// (e.g. shown in `kubectl apply` output), so keep it human-actionable.
    Deny { reason: String },
}

impl Decision {
    /// Convenience for the common `Deny { reason }` construction.
    pub fn deny(reason: impl Into<String>) -> Self {
        Decision::Deny {
            reason: reason.into(),
        }
    }
}

/// A single admission rule.
///
/// Implementations are cheap to keep in a [`Engine`] for the process lifetime,
/// so they should hold only the state they need (a trusted identity, a client),
/// not capture large environments.
#[async_trait]
pub trait Policy: Send + Sync {
    /// Stable identifier, surfaced in deny messages, logs, and metrics.
    fn name(&self) -> &'static str;

    /// Cheap pre-filter: does this policy have an opinion about `req`? Returning
    /// `false` skips [`evaluate`](Policy::evaluate) entirely, so a policy that
    /// only cares about Pods can bail before doing any real work.
    fn applies(&self, req: &AdmissionRequest<DynamicObject>) -> bool;

    /// Evaluate the request. Only called when [`applies`](Policy::applies)
    /// returned `true`.
    async fn evaluate(&self, req: &AdmissionRequest<DynamicObject>) -> Decision;
}

/// The ordered set of policies applied to every admission request.
///
/// Evaluation is fail-closed per policy: the first applicable policy that denies
/// short-circuits and the request is rejected. A request is allowed only when
/// every applicable policy allows it.
pub struct Engine {
    policies: Vec<Box<dyn Policy>>,
}

impl Engine {
    pub fn new(policies: Vec<Box<dyn Policy>>) -> Self {
        Self { policies }
    }

    /// Run every applicable policy in order, denying on the first violation.
    pub async fn evaluate(&self, req: &AdmissionRequest<DynamicObject>) -> Decision {
        for policy in &self.policies {
            if !policy.applies(req) {
                continue;
            }
            if let Decision::Deny { reason } = policy.evaluate(req).await {
                let name = policy.name();
                tracing::info!(policy = name, %reason, "admission denied");
                // Prefix with the policy name so the API caller can see which
                // rule rejected the request.
                return Decision::deny(format!("[{name}] {reason}"));
            }
        }
        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build a realistic `AdmissionRequest` for a Pod CREATE by round-tripping
    /// through the same decode path the webhook uses.
    fn pod_request() -> AdmissionRequest<DynamicObject> {
        let review: kube::core::admission::AdmissionReview<DynamicObject> =
            serde_json::from_value(json!({
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "request": {
                    "uid": "test-uid",
                    "kind": {"group": "", "version": "v1", "kind": "Pod"},
                    "resource": {"group": "", "version": "v1", "resource": "pods"},
                    "name": "demo",
                    "namespace": "default",
                    "operation": "CREATE",
                    "userInfo": {},
                    "object": {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {"name": "demo"}
                    }
                }
            }))
            .expect("valid AdmissionReview fixture");
        review.try_into().expect("review carries a request")
    }

    /// A test policy with a fixed verdict, so the engine's combination logic can
    /// be exercised without a real rule.
    struct Fixed {
        name: &'static str,
        applies: bool,
        decision: Decision,
    }

    #[async_trait]
    impl Policy for Fixed {
        fn name(&self) -> &'static str {
            self.name
        }
        fn applies(&self, _req: &AdmissionRequest<DynamicObject>) -> bool {
            self.applies
        }
        async fn evaluate(&self, _req: &AdmissionRequest<DynamicObject>) -> Decision {
            self.decision.clone()
        }
    }

    #[tokio::test]
    async fn allows_when_every_policy_allows() {
        let engine = Engine::new(vec![Box::new(Fixed {
            name: "a",
            applies: true,
            decision: Decision::Allow,
        })]);
        assert!(matches!(
            engine.evaluate(&pod_request()).await,
            Decision::Allow
        ));
    }

    #[tokio::test]
    async fn denies_on_first_violation_and_tags_with_policy_name() {
        let engine = Engine::new(vec![
            Box::new(Fixed {
                name: "first",
                applies: true,
                decision: Decision::Allow,
            }),
            Box::new(Fixed {
                name: "second",
                applies: true,
                decision: Decision::deny("nope"),
            }),
        ]);
        match engine.evaluate(&pod_request()).await {
            Decision::Deny { reason } => assert_eq!(reason, "[second] nope"),
            Decision::Allow => panic!("expected deny"),
        }
    }

    #[tokio::test]
    async fn skips_inapplicable_policies() {
        let engine = Engine::new(vec![Box::new(Fixed {
            name: "off",
            applies: false,
            decision: Decision::deny("should never run"),
        })]);
        assert!(matches!(
            engine.evaluate(&pod_request()).await,
            Decision::Allow
        ));
    }
}
