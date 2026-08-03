//! The cluster-facing glue for `ProposedAction::ContainNode`: cordon/uncordon the target
//! `Node`, and drive the co-resident default-deny sweep through the SAME
//! [`IsolationActuator`] the chain-based workload quarantine already uses. Thin and
//! exercised only against a real cluster — like the `kube` module's live actuators — with
//! [`super::render_cordon`]/[`super::render_uncordon`] as the unit-tested pure half.
//!
//! [`Self::revert`] is the break-glass/self-revert call site's real revert to call
//! ([`crate::engine::node_containment_revert`]), self-gated on [`super::revert_decision`]
//! regardless of caller discipline. **[`Self::apply`] has NO call site in `Engine`** —
//! ADR-0040 §5 makes a node cut propose-first by construction (never auto-applied, at any
//! arming rung), so nothing in the engine's per-pass loop ever reaches it; it exists,
//! tested in isolation, for a future human-approval-to-apply flow.

use crate::engine::respond::Mitigation;
use crate::engine::respond::actuator::{Actuation, Actuator, IsolationActuator, cut_label};

use super::{NodeFact, render_cordon, render_uncordon, revert_decision};

/// The revert half of [`NodeContainmentActuator`]'s contract, pulled into a trait purely so
/// the break-glass/self-revert loop ([`crate::engine::Engine::process`]) can hold either the
/// live cluster-facing actuator or a test double — mirroring how [`Actuator`] lets
/// [`crate::engine::respond::actuator::KubeActuator`] and a recording double stand in for
/// each other there. `NodeContainmentActuator` itself deliberately does not implement
/// `Actuator` (this module's own doc: one `ContainNode` mitigation maps to MANY cluster
/// objects, a shape `Actuator`'s single-mitigation signature can't express) — this trait
/// keeps that multi-object shape (mitigation + observed [`NodeFact`] + the co-resident set)
/// while still giving the engine a swappable seam onto it.
#[async_trait::async_trait]
pub trait NodeContainmentRevert: Send + Sync {
    async fn revert(
        &self,
        mitigation: &Mitigation,
        target: &NodeFact,
        co_resident: &[Mitigation],
    ) -> Actuation;
}

#[async_trait::async_trait]
impl NodeContainmentRevert for NodeContainmentActuator {
    async fn revert(
        &self,
        mitigation: &Mitigation,
        target: &NodeFact,
        co_resident: &[Mitigation],
    ) -> Actuation {
        NodeContainmentActuator::revert(self, mitigation, target, co_resident).await
    }
}

/// A dynamic `Api` for the cluster-scoped core `Node` resource.
fn node_api(client: &kube::Client) -> kube::Api<kube::core::DynamicObject> {
    let gvk = kube::core::GroupVersionKind::gvk("", "v1", "Node");
    let ar = kube::core::ApiResource::from_gvk(&gvk);
    kube::Api::all_with(client.clone(), &ar)
}

/// Applies/reverts a `ProposedAction::ContainNode` mitigation: the cordon patch on the
/// target `Host`, plus the co-resident default-deny sweep ([`super::co_resident_denies`])
/// via the shared [`IsolationActuator`] path. Unlike every other [`Actuator`]
/// implementation, this one action maps to MANY cluster objects (one cordon, one
/// `NetworkPolicy` per co-resident labelled pod), so it deliberately does not implement the
/// single-mitigation [`Actuator`] trait — its methods take the co-resident set explicitly
/// instead.
pub struct NodeContainmentActuator {
    client: kube::Client,
}

impl NodeContainmentActuator {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }

    /// Cordon `mitigation`'s target host and default-deny every co-resident mitigation in
    /// `co_resident` (built by [`super::co_resident_denies`]). Best-effort: a co-resident
    /// deny failure is logged by [`IsolationActuator`] and does not roll back the cordon — a
    /// partial containment (node cordoned, some pods still reachable) is safer than none.
    pub async fn apply(&self, mitigation: &Mitigation, co_resident: &[Mitigation]) -> Actuation {
        let Some(manifest) = render_cordon(mitigation) else {
            tracing::warn!(cut = %cut_label(mitigation), "not a ContainNode mitigation; nothing to cordon");
            return Actuation::DryRun;
        };
        let host_name = mitigation.cut.from.short();
        if !self.patch_node(host_name, &manifest, "cordon").await {
            return Actuation::DryRun;
        }
        tracing::info!(node = %host_name, "cordoned node (ADR-0040 containment)");
        let isolation = IsolationActuator::new(self.client.clone());
        for co_resident_mitigation in co_resident {
            isolation.apply(co_resident_mitigation).await;
        }
        Actuation::Applied
    }

    /// Uncordon `mitigation`'s target host and lift every co-resident deny in
    /// `co_resident`. Self-gated on [`super::revert_decision`]: `target` is the observed
    /// [`NodeFact`] for the host, and this method short-circuits to [`Actuation::DryRun`]
    /// unless protector owns the cordon — the ownership rail cannot be bypassed by a
    /// forgetful caller, so the highest-blast action is safe by construction rather than by
    /// caller discipline. The break-glass/self-revert path built on this (ADR-0040 §6) calls
    /// exactly this method, so the gate lives here, not only in a doc-comment contract.
    pub async fn revert(
        &self,
        mitigation: &Mitigation,
        target: &NodeFact,
        co_resident: &[Mitigation],
    ) -> Actuation {
        if let Err(refusal) = revert_decision(target) {
            tracing::warn!(
                node = %target.name,
                reason = refusal.metric_reason(),
                "revert refused by ownership rail; not uncordoning",
            );
            return Actuation::DryRun;
        }
        let Some(manifest) = render_uncordon(mitigation) else {
            tracing::warn!(cut = %cut_label(mitigation), "not a ContainNode mitigation; nothing to uncordon");
            return Actuation::DryRun;
        };
        let host_name = mitigation.cut.from.short();
        if !self.patch_node(host_name, &manifest, "uncordon").await {
            return Actuation::DryRun;
        }
        tracing::info!(node = %host_name, "uncordoned node (ADR-0040 revert)");
        let isolation = IsolationActuator::new(self.client.clone());
        for co_resident_mitigation in co_resident {
            isolation.revert(co_resident_mitigation).await;
        }
        Actuation::Reverted
    }

    /// Server-side-apply `manifest` (a [`super::render_cordon`]/[`super::render_uncordon`]
    /// patch for `host_name`) against the target `Node`, under the `protector` field
    /// manager so cordon and uncordon never contend with any other field the object
    /// carries. Returns whether the patch succeeded.
    async fn patch_node(
        &self,
        host_name: &str,
        manifest: &serde_json::Value,
        verb: &'static str,
    ) -> bool {
        let object: kube::core::DynamicObject = match serde_json::from_value(manifest.clone()) {
            Ok(o) => o,
            Err(error) => {
                tracing::error!(%error, verb, "failed to build Node patch");
                return false;
            }
        };
        let params = kube::api::PatchParams::apply("protector").force();
        match node_api(&self.client)
            .patch(host_name, &params, &kube::api::Patch::Apply(&object))
            .await
        {
            Ok(_) => true,
            Err(error) => {
                tracing::error!(%error, node = %host_name, verb, "failed to patch node");
                false
            }
        }
    }
}
