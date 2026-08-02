//! The cluster-facing glue for `ProposedAction::ContainNode`: cordon/uncordon the target
//! `Node`, and drive the co-resident default-deny sweep through the SAME
//! [`IsolationActuator`] the chain-based workload quarantine already uses. Thin and
//! exercised only against a real cluster — like the `kube` module's live actuators — with
//! [`super::render_cordon`]/[`super::render_uncordon`] as the unit-tested pure half.
//!
//! **Not wired into anything live in this ticket.** No `node` arming rung exists yet
//! (ADR-0040 §6, a separate ticket) and `ContainNode`'s `is_additive_live() == false` means
//! [`super::super::decide`] never routes here through the generic auto-apply path either —
//! this exists so a future human-approval/break-glass-revert path has a real apply/revert to
//! call, callable and testable in isolation today.

use crate::engine::respond::Mitigation;
use crate::engine::respond::actuator::{Actuation, Actuator, IsolationActuator, cut_label};

use super::{render_cordon, render_uncordon};

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
    /// `co_resident`. Callers MUST gate this on [`super::revert_decision`] first — this
    /// method itself does not re-check ownership; it is the mechanical half, the rail is the
    /// decision half (mirroring [`super::super::decide`]/[`Actuator::revert`]'s own split).
    pub async fn revert(&self, mitigation: &Mitigation, co_resident: &[Mitigation]) -> Actuation {
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
