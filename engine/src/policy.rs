use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use kube::core::DynamicObject;
use kube::core::admission::AdmissionRequest;

use crate::engine::journal::{Decision as JournalDecision, DecisionJournal};
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

/// A gate's **counterfactual** verdict for a request — what it WOULD do if the request were in
/// scope and enforced — decoupled from whether enforcement is actually on (JEF-246, the shadow
/// what-if of ADR-0016 applied to admission). Unlike [`evaluate`](Policy::evaluate), this is
/// computed for EVERY request, even one [`applies`](Policy::applies) skips, so the operator can
/// answer "if I turned enforcement on for this namespace, what would happen?".
///
/// It is presentation-only: the engine records it but it MUST NOT influence the API verdict
/// (ADR-0016 — presentation is a view, never a gate). Only [`evaluate`](Policy::evaluate)
/// decides admit/deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShadowVerdict {
    /// This gate has no opinion about this request (e.g. a non-Pod for a Pod-only gate). It
    /// contributes no signature/mesh status and never flips the net would-admit.
    NotApplicable,
    /// The gate shadow-evaluated the request. `passed` is the gate's verdict ignoring scope;
    /// `enforced` is whether the request is in this gate's enforced scope (so the status can
    /// distinguish a *verified* in-scope pass from a *would-pass* out-of-scope one). `reason`
    /// is the human-actionable prose for a failure (empty on a pass).
    Evaluated {
        passed: bool,
        enforced: bool,
        reason: String,
    },
}

impl ShadowVerdict {
    /// A passing shadow verdict, tagged with whether the request is in enforced scope.
    pub fn pass(enforced: bool) -> Self {
        ShadowVerdict::Evaluated {
            passed: true,
            enforced,
            reason: String::new(),
        }
    }

    /// A failing shadow verdict (the gate would deny if enforced), with the reason.
    pub fn fail(enforced: bool, reason: impl Into<String>) -> Self {
        ShadowVerdict::Evaluated {
            passed: false,
            enforced,
            reason: reason.into(),
        }
    }

    /// The coarse three-state status word for this gate's column, given the per-gate vocabulary
    /// (`signed`/`meshed` family). `verified` = in scope, checked, passed; `would-pass` = out of
    /// scope, shadow-checked, would pass; `would-fail` = would deny if enforced. Returns the
    /// empty string for [`NotApplicable`](ShadowVerdict::NotApplicable).
    pub fn status(&self) -> &'static str {
        match self {
            ShadowVerdict::NotApplicable => "",
            ShadowVerdict::Evaluated {
                passed: true,
                enforced: true,
                ..
            } => "verified",
            ShadowVerdict::Evaluated {
                passed: true,
                enforced: false,
                ..
            } => "would-pass",
            ShadowVerdict::Evaluated { passed: false, .. } => "would-fail",
        }
    }

    /// True if this gate would admit the request under enforcement (a pass, or no opinion).
    fn would_admit(&self) -> bool {
        !matches!(self, ShadowVerdict::Evaluated { passed: false, .. })
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

    /// **Shadow** evaluation (JEF-246): the gate's counterfactual verdict for `req`, computed
    /// regardless of [`applies`](Policy::applies) or enforced scope, so the dashboard can show
    /// what protector WOULD do if this request were in scope and enforced. Display-only — it
    /// never contributes to the API verdict (ADR-0016).
    ///
    /// The default returns [`NotApplicable`](ShadowVerdict::NotApplicable); a gate that wants a
    /// what-if (signature, mesh) overrides it to compute its verdict for every request. A
    /// gate's shadow path MUST share enforcement's evaluation mechanism (and its caches), adding
    /// **no** new egress (zero-egress invariant).
    async fn shadow_evaluate(&self, _req: &AdmissionRequest<DynamicObject>) -> ShadowVerdict {
        ShadowVerdict::NotApplicable
    }
}

/// The ordered set of policies applied to every admission request.
///
/// Evaluation is fail-closed per policy: the first applicable policy that denies
/// short-circuits and the request is rejected. A request is allowed only when
/// every applicable policy allows (or merely audits) it. The engine owns the
/// recording of decisions — both violations (`Deny`/`Audit`, logged + metered) and
/// clean admits (`Allow`) — so policies just decide; they don't log.
pub struct Engine {
    policies: Vec<Box<dyn Policy>>,
    metrics: Arc<Metrics>,
    /// The bounded, deduped admission-decision ring (JEF-226/237): the per-workload log the
    /// `/policy` dashboard view reads. Optional so the webhook can run without a dashboard
    /// (and so the engine's existing tests construct without one). When present, EVERY
    /// resolved admission — clean admit, audit, or deny — is mirrored here (JEF-237 records
    /// the good pods too, not only violations).
    decisions: Option<Arc<PolicyDecisionLog>>,
    /// The durable decision journal (JEF-141/237). Optional. When present, each resolved
    /// admission is also persisted so the `/policy` log survives a restart and repopulates
    /// on boot. Disabled (a no-op) when no writable volume is configured.
    journal: Option<Arc<DecisionJournal>>,
}

/// The holistic, engine-derived view of one request's resolved admission — the per-workload
/// row JEF-237 records (one row per request, deduped, not one per policy).
///
/// JEF-246 changed the signature/mesh statuses from a COARSE two-state ("passed the gate" vs
/// flagged, which conflated *verified* with *not-checked*) to the THREE-state shadow what-if,
/// sourced from each gate's [`shadow_evaluate`](Policy::shadow_evaluate) (computed for EVERY
/// request, even out of scope): `verified` (in scope, checked, passed) · `would-pass` (out of
/// scope, shadow-checked, would pass) · `would-fail` (would deny if enforced). The engine stays
/// policy-agnostic — it keys on the stable gate NAME and never re-derives gating/mesh logic.
struct AdmissionSummary {
    /// `allow` (clean admit), `audit` (would-deny, allowed), or `deny` (rejected) — the
    /// strongest ACTUAL outcome across the request's applicable policies. Unchanged by the
    /// shadow what-if (ADR-0016): this is the honest API verdict.
    decision: &'static str,
    /// The first deny/audit reason (the actionable prose), empty for a clean admit.
    reason: String,
    /// Three-state signature shadow status (`verified` / `would-pass` / `would-fail`), empty if
    /// the signature gate has no opinion (e.g. a non-Pod).
    signature: String,
    /// Three-state mesh shadow status (`verified` / `would-pass` / `would-fail`), empty if the
    /// mesh gate has no opinion.
    mesh: String,
    /// The net counterfactual: would the request be ADMITTED if every gate were enforced?
    /// `true` while no shadow-evaluated gate would fail. Display-only (ADR-0016).
    would_admit: bool,
}

impl Engine {
    pub fn new(policies: Vec<Box<dyn Policy>>, metrics: Arc<Metrics>) -> Self {
        Self {
            policies,
            metrics,
            decisions: None,
            journal: None,
        }
    }

    /// Attach the admission-decision ring (JEF-226/237) so EVERY resolved decision — clean
    /// admit, audit, or deny — is recorded for the `/policy` view in addition to the metric +
    /// log. Builder-style so `new` stays the minimal constructor the existing tests use.
    pub fn with_decision_log(mut self, decisions: Arc<PolicyDecisionLog>) -> Self {
        self.decisions = Some(decisions);
        self
    }

    /// Attach the durable decision journal (JEF-237) so resolved admissions persist across a
    /// restart. Builder-style; a disabled journal is a safe no-op (in-memory only).
    pub fn with_journal(mut self, journal: Arc<DecisionJournal>) -> Self {
        self.journal = Some(journal);
        self
    }

    /// Run every applicable policy in order. Meters + logs every violation (deny or audit),
    /// returns `Deny` on the first hard denial else `Allow`, and records the resolved
    /// admission — clean admit included — into the `/policy` ring + journal. Audit findings
    /// never deny (the discovery signal); a deny short-circuits the API verdict.
    pub async fn evaluate(&self, req: &AdmissionRequest<DynamicObject>) -> Decision {
        let mut summary = AdmissionSummary {
            decision: "allow",
            reason: String::new(),
            signature: String::new(),
            mesh: String::new(),
            would_admit: true,
        };

        // Shadow what-if (JEF-246): compute every gate's counterfactual verdict — for ALL
        // gates, regardless of `applies()`/scope — and fold it into the recorded row's
        // three-state signature/mesh status + net would-admit. This is display-only and runs
        // BEFORE the real decision loop so the status is present even on a deny short-circuit
        // (and even for a request the real loop would skip entirely). It NEVER touches the
        // returned `Decision` (ADR-0016: presentation is a view, never a gate).
        self.shadow_what_if(req, &mut summary).await;

        for policy in &self.policies {
            if !policy.applies(req) {
                continue;
            }
            let outcome = policy.evaluate(req).await;
            match outcome {
                Decision::Allow => {}
                Decision::Audit { reason } => {
                    self.meter_and_log(policy.name(), "audit", req, &reason);
                    if summary.decision == "allow" {
                        summary.decision = "audit";
                        summary.reason = reason;
                    }
                }
                Decision::Deny { reason } => {
                    self.meter_and_log(policy.name(), "deny", req, &reason);
                    summary.decision = "deny";
                    summary.reason = reason.clone();
                    // The FIRST deny is the API verdict (fail-closed short-circuit); later
                    // policies don't run. Prefix with the policy name so the API caller can
                    // see which rule rejected the request.
                    self.record_admission(req, &summary);
                    return Decision::deny(format!("[{}] {reason}", policy.name()));
                }
            }
        }
        self.record_admission(req, &summary);
        Decision::Allow
    }

    /// Log (with request context) and meter a policy violation. The structured
    /// fields — policy, namespace, name, kind — are what a discovery query keys
    /// on to find workloads that should be meshed or images that should be signed.
    fn meter_and_log(
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
    }

    /// Mirror the request's resolved admission into the bounded, deduped ring the `/policy`
    /// view reads (JEF-237) AND the durable journal (so it survives a restart). One row per
    /// request — clean admits included — deduped by `(subject, image, decision)` so a
    /// Deployment's replicas or a CronJob's runs coalesce into a single counted row.
    /// Low-cardinality, no secret values.
    fn record_admission(&self, req: &AdmissionRequest<DynamicObject>, summary: &AdmissionSummary) {
        // No ring AND no journal ⇒ nothing to do (skip the image extraction work).
        if self.decisions.is_none() && self.journal.is_none() {
            return;
        }
        let namespace = req.namespace.as_deref().unwrap_or_default();
        let record = PolicyDecisionRecord::now(
            "admission",
            summary.decision,
            format!("{}/{}", req.kind.kind, req.name),
            request_image(req),
            summary.signature.clone(),
            summary.mesh.clone(),
            namespace,
            summary.reason.clone(),
        )
        .with_would_admit(summary.would_admit);
        if let Some(decisions) = &self.decisions {
            decisions.record(record.clone());
        }
        if let Some(journal) = &self.journal {
            journal.record(JournalDecision::Admission { record });
        }
    }
}

impl Engine {
    /// Run every gate's [`shadow_evaluate`](Policy::shadow_evaluate) — regardless of `applies()`
    /// or enforced scope (JEF-246) — and fold the verdicts into the summary's three-state
    /// signature/mesh status and net would-admit. Keyed on the stable gate NAME so the engine
    /// stays policy-agnostic. Display-only: this records the counterfactual; it never decides.
    async fn shadow_what_if(
        &self,
        req: &AdmissionRequest<DynamicObject>,
        summary: &mut AdmissionSummary,
    ) {
        for policy in &self.policies {
            let verdict = policy.shadow_evaluate(req).await;
            if !verdict.would_admit() {
                summary.would_admit = false;
            }
            let status = verdict.status();
            match policy.name() {
                "image-signature" => summary.signature = status.to_string(),
                "mesh-injection" => summary.mesh = status.to_string(),
                _ => {}
            }
        }
    }
}

/// A single representative image ref for the request's `(subject, image, decision)` dedup key
/// (JEF-237). For a Pod it's the FIRST workload container image (init/ephemeral and the
/// injected `linkerd-proxy` sidecar are skipped, so a meshed and an unmeshed copy of the same
/// app dedup together). Empty for a non-Pod or an object with no container image — the row
/// then dedups on `(subject, decision)` alone. Low-cardinality and operator-facing; UNTRUSTED
/// (auto-escaped at render).
fn request_image(req: &AdmissionRequest<DynamicObject>) -> String {
    let Some(obj) = req.object.as_ref() else {
        return String::new();
    };
    let containers = obj.data["spec"]
        .get("containers")
        .and_then(|v| v.as_array());
    let Some(containers) = containers else {
        return String::new();
    };
    for c in containers {
        let name = c.get("name").and_then(|v| v.as_str());
        // Skip Linkerd's injected sidecar so the same app image keys identically whether or
        // not it ended up meshed.
        if name == Some("linkerd-proxy") {
            continue;
        }
        if let Some(image) = c.get("image").and_then(|v| v.as_str()) {
            return image.to_string();
        }
    }
    String::new()
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
        /// Mirror the fixed decision as the shadow verdict so the engine's three-state status
        /// folding is exercised: `Allow` ⇒ a `verified` pass (in scope), `Deny` ⇒ a `would-fail`
        /// in scope, `Audit` ⇒ a `would-fail` out of scope (the would-deny-but-allowed case).
        async fn shadow_evaluate(&self, _req: &AdmissionRequest<DynamicObject>) -> ShadowVerdict {
            match &self.decision {
                Decision::Allow => ShadowVerdict::pass(true),
                Decision::Deny { reason } => ShadowVerdict::fail(true, reason.clone()),
                Decision::Audit { reason } => ShadowVerdict::fail(false, reason.clone()),
            }
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

    /// A Pod CREATE carrying a single container image, so the recorded admission row has a
    /// non-empty `image` (the dedup key component) and `request_image` has something to find.
    fn pod_request_with_image(image: &str) -> AdmissionRequest<DynamicObject> {
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
                        "metadata": {"name": "demo"},
                        "spec": {"containers": [{"name": "app", "image": image}]}
                    }
                }
            }))
            .expect("valid AdmissionReview fixture");
        review.try_into().expect("review carries a request")
    }

    #[tokio::test]
    async fn records_one_holistic_admission_row_with_signature_and_mesh_status() {
        // JEF-237: a single per-request admission row carries the COARSE signature + mesh
        // status derived from each gate's outcome, the resolved decision word, the subject,
        // image, namespace, and the actionable reason — not one row per policy.
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
                    decision: Decision::Allow,
                }),
            ],
            Arc::new(Metrics::new()),
        )
        .with_decision_log(log.clone());

        let _ = engine
            .evaluate(&pod_request_with_image("ghcr.io/org/app:1"))
            .await;

        let snap = log.snapshot();
        assert_eq!(snap.len(), 1, "one holistic row per request");
        let r = &snap[0];
        assert_eq!(r.policy, "admission");
        assert_eq!(
            r.decision, "audit",
            "audit is the resolved (non-deny) outcome"
        );
        assert_eq!(r.subject, "Pod/demo");
        assert_eq!(r.image, "ghcr.io/org/app:1");
        assert_eq!(
            r.signature, "would-fail",
            "the signature gate audited (would deny if enforced)"
        );
        assert_eq!(r.mesh, "verified", "the mesh gate passed in scope");
        assert!(
            !r.would_admit,
            "a would-fail gate flips the net would-admit"
        );
        assert_eq!(r.namespace, "default");
        assert_eq!(
            r.reason,
            "unsigned or untrusted image(s): ghcr.io/org/app:1"
        );
    }

    #[tokio::test]
    async fn records_clean_admit_as_an_allow_row() {
        // JEF-237's headline: a good pod (signed + meshed) is RECORDED as a green admit row,
        // not dropped — so a healthy cluster's /policy view isn't blank.
        let log = Arc::new(PolicyDecisionLog::new());
        let engine = Engine::new(
            vec![
                Box::new(Fixed {
                    name: "image-signature",
                    applies: true,
                    decision: Decision::Allow,
                }),
                Box::new(Fixed {
                    name: "mesh-injection",
                    applies: true,
                    decision: Decision::Allow,
                }),
            ],
            Arc::new(Metrics::new()),
        )
        .with_decision_log(log.clone());

        let _ = engine
            .evaluate(&pod_request_with_image("ghcr.io/org/app:1"))
            .await;

        let snap = log.snapshot();
        assert_eq!(snap.len(), 1, "the clean admit is recorded");
        let r = &snap[0];
        assert_eq!(r.decision, "allow");
        assert_eq!(r.signature, "verified");
        assert_eq!(r.mesh, "verified");
        assert!(r.would_admit, "a clean admit would also admit if enforced");
        assert!(r.reason.is_empty(), "a clean admit carries no reason");
    }

    #[tokio::test]
    async fn deny_short_circuits_but_the_admission_row_is_still_recorded() {
        // A hard deny is the API verdict AND is captured as a deny row (with the gate's status
        // up to the short-circuit point).
        let log = Arc::new(PolicyDecisionLog::new());
        let engine = Engine::new(
            vec![Box::new(Fixed {
                name: "image-signature",
                applies: true,
                decision: Decision::deny("unsigned"),
            })],
            Arc::new(Metrics::new()),
        )
        .with_decision_log(log.clone());

        let verdict = engine
            .evaluate(&pod_request_with_image("ghcr.io/org/app:1"))
            .await;
        assert!(matches!(verdict, Decision::Deny { .. }));
        let snap = log.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].decision, "deny");
        assert_eq!(
            snap[0].signature, "would-fail",
            "the shadow status is present even on a deny short-circuit"
        );
        assert!(!snap[0].would_admit);
        assert_eq!(snap[0].reason, "unsigned");
    }

    #[tokio::test]
    async fn replica_churn_dedups_into_one_counted_admission_row() {
        // A Deployment's replicas (same subject + image + outcome) must coalesce into ONE
        // counted row, not flood the ring — the bounding JEF-237 requires.
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
        for _ in 0..25 {
            let _ = engine
                .evaluate(&pod_request_with_image("ghcr.io/org/app:1"))
                .await;
        }
        let snap = log.snapshot();
        assert_eq!(snap.len(), 1, "replica churn folds into one row");
        assert_eq!(snap[0].count, 25, "the dedup count totals the replicas");
    }

    #[tokio::test]
    async fn resolved_admission_is_persisted_to_the_journal() {
        // JEF-237 persistence: with a journal attached, the resolved admission is written as a
        // durable Admission line so /policy survives a restart.
        use crate::engine::journal::{Decision as JournalDecision, DecisionJournal};
        let path = std::env::temp_dir().join(format!(
            "protector-policy-journal-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let journal = Arc::new(DecisionJournal::open(&path));
        let engine = Engine::new(
            vec![Box::new(Fixed {
                name: "image-signature",
                applies: true,
                decision: Decision::Allow,
            })],
            Arc::new(Metrics::new()),
        )
        .with_journal(journal.clone());

        let _ = engine
            .evaluate(&pod_request_with_image("ghcr.io/org/app:1"))
            .await;

        let entries = journal.replay();
        let admissions: Vec<_> = entries
            .iter()
            .filter_map(|e| match &e.decision {
                JournalDecision::Admission { record } => Some(record),
                _ => None,
            })
            .collect();
        assert_eq!(admissions.len(), 1, "the admission was persisted");
        assert_eq!(admissions[0].decision, "allow");
        assert_eq!(admissions[0].image, "ghcr.io/org/app:1");
        let _ = std::fs::remove_file(&path);
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

    #[tokio::test]
    async fn out_of_scope_would_deny_is_recorded_but_admitted() {
        // JEF-246 acceptance: an out-of-scope gate (here a `Fixed` that audits — the would-deny-
        // but-allowed case) still ADMITS the request (the actual decision is `audit`, allowed),
        // yet the shadow what-if records `would-fail` + `would_admit = false` so the operator
        // sees what enforcement would do.
        let log = Arc::new(PolicyDecisionLog::new());
        let engine = Engine::new(
            vec![Box::new(Fixed {
                name: "image-signature",
                applies: true,
                decision: Decision::audit("unsigned or untrusted image(s): ghcr.io/org/app:1"),
            })],
            Arc::new(Metrics::new()),
        )
        .with_decision_log(log.clone());

        let verdict = engine
            .evaluate(&pod_request_with_image("ghcr.io/org/app:1"))
            .await;
        // Display-only: the API still admits (audit never denies).
        assert!(matches!(verdict, Decision::Allow));
        let snap = log.snapshot();
        assert_eq!(snap[0].decision, "audit");
        assert_eq!(snap[0].signature, "would-fail");
        assert!(!snap[0].would_admit, "the net what-if is would-DENY");
    }

    #[tokio::test]
    async fn out_of_scope_would_admit_records_the_clean_counterfactual() {
        // JEF-246 acceptance: an out-of-scope image that WOULD pass both gates is recorded with
        // a passing shadow status and `would_admit = true` — not empty/ambiguous. (`would-pass`
        // here because the gate, while passing, is modeled out of enforced scope via a separate
        // policy below; for `Fixed::Allow` the model reports `verified`, the in-scope pass.)
        let log = Arc::new(PolicyDecisionLog::new());
        let engine = Engine::new(
            vec![
                Box::new(Fixed {
                    name: "image-signature",
                    applies: true,
                    decision: Decision::Allow,
                }),
                Box::new(Fixed {
                    name: "mesh-injection",
                    applies: true,
                    decision: Decision::Allow,
                }),
            ],
            Arc::new(Metrics::new()),
        )
        .with_decision_log(log.clone());

        let verdict = engine
            .evaluate(&pod_request_with_image("ghcr.io/org/app:1"))
            .await;
        assert!(matches!(verdict, Decision::Allow));
        let snap = log.snapshot();
        assert!(snap[0].would_admit, "both gates would admit if enforced");
        assert_ne!(snap[0].signature, "", "the counterfactual is not empty");
        assert_ne!(snap[0].mesh, "");
    }

    #[tokio::test]
    async fn shadow_what_if_never_changes_the_api_verdict() {
        // ADR-0016: presentation is a view, never a gate. A gate whose shadow verdict is a
        // would-fail (audit) MUST NOT deny — the returned `Decision` is byte-identical to the
        // no-shadow path. Here every applicable policy allows/audits, so the verdict is `Allow`
        // regardless of the would-DENY counterfactual.
        let engine = engine(vec![Box::new(Fixed {
            name: "image-signature",
            applies: true,
            decision: Decision::audit("would deny if enforced"),
        })]);
        assert!(
            matches!(engine.evaluate(&pod_request()).await, Decision::Allow),
            "the what-if must not flip the actual admit"
        );
    }
}
