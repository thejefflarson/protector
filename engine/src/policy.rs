use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use kube::core::DynamicObject;
use kube::core::admission::AdmissionRequest;

use crate::engine::policy_log::{PolicyDecisionLog, PolicyDecisionRecord};
use crate::metrics::Metrics;

/// Outcome of evaluating a single policy against one admission request.
#[derive(Debug, Clone)]
pub enum Decision {
    /// The request satisfies the policy.
    Allow,
    /// The request violates the policy. `reason` is surfaced to the API caller
    /// (e.g. shown in `kubectl apply` output), so keep it human-actionable.
    Deny { reason: String },
    /// The request violates the policy, but the policy is in audit mode or the
    /// workload is exempt, so it is allowed anyway. Recorded (log + metric) as a
    /// would-deny so you can discover what enforcement *would* reject. `reason`
    /// is the same human-actionable text a `Deny` would carry.
    Audit { reason: String },
}

impl Decision {
    /// Convenience for the common `Deny { reason }` construction.
    pub fn deny(reason: impl Into<String>) -> Self {
        Decision::Deny {
            reason: reason.into(),
        }
    }

    /// Convenience for the `Audit { reason }` construction.
    pub fn audit(reason: impl Into<String>) -> Self {
        Decision::Audit {
            reason: reason.into(),
        }
    }
}

/// Where a policy enforces (denies) versus merely audits (logs + allows).
///
/// Audit is the default everywhere; enforcement is opt-in via an allowlist. A
/// request is enforced if its namespace is listed **or** the Pod carries one of
/// the listed `key=value` labels. Everything else is audited — so a workload can
/// never be *accidentally* blocked by a broad default; you add it to the
/// allowlist deliberately. There is intentionally no "enforce everywhere"
/// wildcard (it would be a footgun — e.g. blocking the deliberately-unmeshed
/// runner namespace); list the namespaces you mean.
#[derive(Default)]
pub struct EnforceScope {
    namespaces: HashSet<String>,
    labels: Vec<(String, String)>,
}

impl EnforceScope {
    pub fn new(namespaces: HashSet<String>, labels: Vec<(String, String)>) -> Self {
        Self { namespaces, labels }
    }

    /// True if this request should be **enforced** (deny on violation); false
    /// means **audit** (record + allow).
    pub fn enforces(&self, req: &AdmissionRequest<DynamicObject>) -> bool {
        if let Some(ns) = req.namespace.as_deref()
            && self.namespaces.contains(ns)
        {
            return true;
        }
        if self.labels.is_empty() {
            return false;
        }
        let pod_labels = req.object.as_ref().and_then(|o| o.metadata.labels.as_ref());
        pod_labels.is_some_and(|labels| {
            self.labels
                .iter()
                .any(|(k, v)| labels.get(k).is_some_and(|pv| pv == v))
        })
    }

    /// Turn a violation message into the right outcome for `req`: `Deny` where
    /// enforcement is in scope, `Audit` (recorded but allowed) everywhere else.
    pub fn decide(&self, req: &AdmissionRequest<DynamicObject>, reason: String) -> Decision {
        if self.enforces(req) {
            Decision::Deny { reason }
        } else {
            Decision::Audit { reason }
        }
    }

    /// True if nothing is enforced — audit everywhere.
    pub fn is_audit_only(&self) -> bool {
        self.namespaces.is_empty() && self.labels.is_empty()
    }

    /// Human-readable summary for startup logging.
    pub fn describe(&self) -> String {
        if self.is_audit_only() {
            return "audit-only (nothing enforced)".to_string();
        }
        let mut parts = Vec::new();
        if !self.namespaces.is_empty() {
            let mut ns: Vec<_> = self.namespaces.iter().cloned().collect();
            ns.sort();
            parts.push(format!("namespaces=[{}]", ns.join(",")));
        }
        if !self.labels.is_empty() {
            let labels: Vec<_> = self
                .labels
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            parts.push(format!("labels=[{}]", labels.join(",")));
        }
        format!("enforce {}", parts.join(" "))
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
/// every applicable policy allows (or merely audits) it. The engine owns the
/// recording of violations — both `Deny` and `Audit` outcomes are logged with
/// request context and metered — so policies just decide; they don't log.
pub struct Engine {
    policies: Vec<Box<dyn Policy>>,
    metrics: Arc<Metrics>,
    /// The bounded admission-decision ring (JEF-226): the per-event log the `/policy`
    /// dashboard view reads. Optional so the webhook can run without a dashboard (and so
    /// the engine's existing tests construct without one). When present, every recorded
    /// audit/deny is mirrored here alongside the metric + log.
    decisions: Option<Arc<PolicyDecisionLog>>,
}

impl Engine {
    pub fn new(policies: Vec<Box<dyn Policy>>, metrics: Arc<Metrics>) -> Self {
        Self {
            policies,
            metrics,
            decisions: None,
        }
    }

    /// Attach the admission-decision ring (JEF-226) so resolved audit/deny outcomes are
    /// recorded for the `/policy` view in addition to the metric + log. Builder-style so
    /// `new` stays the minimal constructor the existing tests use.
    pub fn with_decision_log(mut self, decisions: Arc<PolicyDecisionLog>) -> Self {
        self.decisions = Some(decisions);
        self
    }

    /// Run every applicable policy in order. Records every violation (deny or
    /// audit) with request context, returns `Deny` on the first hard denial,
    /// else `Allow`. Audit findings never deny — they're the discovery signal.
    pub async fn evaluate(&self, req: &AdmissionRequest<DynamicObject>) -> Decision {
        for policy in &self.policies {
            if !policy.applies(req) {
                continue;
            }
            match policy.evaluate(req).await {
                Decision::Allow => {}
                Decision::Audit { reason } => {
                    self.record(policy.name(), "audit", req, &reason);
                }
                Decision::Deny { reason } => {
                    self.record(policy.name(), "deny", req, &reason);
                    // Prefix with the policy name so the API caller can see which
                    // rule rejected the request.
                    return Decision::deny(format!("[{}] {reason}", policy.name()));
                }
            }
        }
        Decision::Allow
    }

    /// Log (with request context) and meter a policy violation. The structured
    /// fields — policy, namespace, name, kind — are what a discovery query keys
    /// on to find workloads that should be meshed or images that should be signed.
    fn record(
        &self,
        policy: &'static str,
        decision: &'static str,
        req: &AdmissionRequest<DynamicObject>,
        reason: &str,
    ) {
        self.metrics.record_violation(policy, decision);
        let namespace = req.namespace.as_deref().unwrap_or_default();
        tracing::warn!(
            policy,
            decision,
            namespace,
            name = %req.name,
            kind = %req.kind.kind,
            audit = decision == "audit",
            "{reason}"
        );
        // Mirror the resolved decision into the bounded ring the `/policy` view reads
        // (JEF-226). Low-cardinality, no secret values: the subject is the workload
        // `kind/name`; any image ref(s) live in the (already operator-facing) reason.
        if let Some(decisions) = &self.decisions {
            decisions.record(PolicyDecisionRecord::now(
                policy,
                decision,
                format!("{}/{}", req.kind.kind, req.name),
                namespace,
                reason,
            ));
        }
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

    /// Build an engine with a throwaway metrics sink.
    fn engine(policies: Vec<Box<dyn Policy>>) -> Engine {
        Engine::new(policies, Arc::new(Metrics::new()))
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
        let engine = engine(vec![Box::new(Fixed {
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
        let engine = engine(vec![
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
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn skips_inapplicable_policies() {
        let engine = engine(vec![Box::new(Fixed {
            name: "off",
            applies: false,
            decision: Decision::deny("should never run"),
        })]);
        assert!(matches!(
            engine.evaluate(&pod_request()).await,
            Decision::Allow
        ));
    }

    #[tokio::test]
    async fn records_each_resolved_decision_into_the_ring() {
        // JEF-226: a resolved audit/deny is mirrored into the bounded ring with the right
        // policy / decision / subject / namespace / reason. The pod fixture is Pod "demo"
        // in "default".
        let log = Arc::new(PolicyDecisionLog::new());
        let engine = Engine::new(
            vec![
                Box::new(Fixed {
                    name: "image-signature",
                    applies: true,
                    decision: Decision::audit("unsigned or untrusted image(s): ghcr.io/org/app:1"),
                }),
                Box::new(Fixed {
                    name: "mesh-injection",
                    applies: true,
                    decision: Decision::deny("not enrolled in the mesh"),
                }),
            ],
            Arc::new(Metrics::new()),
        )
        .with_decision_log(log.clone());

        let _ = engine.evaluate(&pod_request()).await;

        let snap = log.snapshot();
        // Newest-first: the mesh deny short-circuited evaluation after the signature audit,
        // so both were recorded, deny last (hence first in the snapshot).
        assert_eq!(snap.len(), 2, "both resolved decisions recorded");
        assert_eq!(snap[0].policy, "mesh-injection");
        assert_eq!(snap[0].decision, "deny");
        assert_eq!(snap[0].subject, "Pod/demo");
        assert_eq!(snap[0].namespace, "default");
        assert_eq!(snap[0].reason, "not enrolled in the mesh");

        assert_eq!(snap[1].policy, "image-signature");
        assert_eq!(snap[1].decision, "audit");
        assert_eq!(snap[1].subject, "Pod/demo");
        assert_eq!(snap[1].namespace, "default");
        assert_eq!(
            snap[1].reason,
            "unsigned or untrusted image(s): ghcr.io/org/app:1"
        );
    }

    #[tokio::test]
    async fn allow_decisions_are_not_recorded() {
        // An all-allow evaluation leaves the ring empty — the log is the would-deny /
        // deny discovery signal, complementing (not duplicating) the allow path.
        let log = Arc::new(PolicyDecisionLog::new());
        let engine = Engine::new(
            vec![Box::new(Fixed {
                name: "image-signature",
                applies: true,
                decision: Decision::Allow,
            })],
            Arc::new(Metrics::new()),
        )
        .with_decision_log(log.clone());
        let _ = engine.evaluate(&pod_request()).await;
        assert!(log.snapshot().is_empty(), "allow is not recorded");
    }

    #[tokio::test]
    async fn audit_findings_do_not_deny() {
        // An audit finding is recorded but the request is still allowed, even
        // when a later policy also audits.
        let engine = engine(vec![
            Box::new(Fixed {
                name: "a",
                applies: true,
                decision: Decision::audit("would deny"),
            }),
            Box::new(Fixed {
                name: "b",
                applies: true,
                decision: Decision::Allow,
            }),
        ]);
        assert!(matches!(
            engine.evaluate(&pod_request()).await,
            Decision::Allow
        ));
    }
}
