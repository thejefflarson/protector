//! The cluster-facing live actuators: [`KubeActuator`] (the ADR-0007 additive
//! `AdminNetworkPolicy` deny) and [`IsolationActuator`] (the ADR-0010 default-deny
//! `NetworkPolicy` quarantine). Split out of the actuator module root purely to keep
//! every file under the 1,000-line cap (repo CLAUDE.md). This is the thin apply/revert
//! glue against the cluster — exercised only against a real cluster; the rendering it
//! drives ([`super::render`]) is the unit-tested part.

use super::super::{Mitigation, ProposedAction};
use super::render::{object_name, render_deny, render_isolation, workload_namespace};
use super::{Actuation, Actuator, cut_label};

/// A dynamic `Api` for the namespaced `NetworkPolicy` the isolation quarantine
/// applies/deletes. Standard `NetworkPolicy` is honored by every CNI (flannel,
/// kube-router, Cilium, Calico), so both live actuators share this path for the
/// default-deny quarantine.
fn np_api(client: &kube::Client, ns: &str) -> kube::Api<kube::core::DynamicObject> {
    let gvk = kube::core::GroupVersionKind::gvk("networking.k8s.io", "v1", "NetworkPolicy");
    let ar = kube::core::ApiResource::from_gvk(&gvk);
    kube::Api::namespaced_with(client.clone(), ns, &ar)
}

/// Apply the default-deny isolation `NetworkPolicy` (ADR-0010) for `mitigation` —
/// the shared quarantine glue behind both the flannel [`IsolationActuator`] and the
/// [`QuarantineEntry`](ProposedAction::QuarantineEntry) default containment on the
/// ANP [`KubeActuator`]. Isolates `cut.from` (the entry, for a quarantine).
async fn apply_isolation(client: &kube::Client, mitigation: &Mitigation) -> Actuation {
    let (Some(manifest), Some(ns)) = (
        render_isolation(mitigation),
        workload_namespace(&mitigation.cut.from),
    ) else {
        tracing::warn!(cut = %cut_label(mitigation), "no isolation NetworkPolicy to apply");
        return Actuation::DryRun;
    };
    let name = object_name("protector-isolate", mitigation);
    let object: kube::core::DynamicObject = match serde_json::from_value(manifest) {
        Ok(o) => o,
        Err(error) => {
            tracing::error!(%error, "failed to build isolation NetworkPolicy");
            return Actuation::DryRun;
        }
    };
    let params = kube::api::PatchParams::apply("protector").force();
    match np_api(client, ns)
        .patch(&name, &params, &kube::api::Patch::Apply(&object))
        .await
    {
        Ok(_) => {
            tracing::info!(cut = %cut_label(mitigation), %name, %ns, "isolated workload (default-deny NetworkPolicy)");
            Actuation::Applied
        }
        Err(error) => {
            tracing::error!(%error, %name, "failed to isolate workload");
            Actuation::DryRun
        }
    }
}

/// Revert (delete) the default-deny isolation `NetworkPolicy` for `mitigation`.
async fn revert_isolation(client: &kube::Client, mitigation: &Mitigation) -> Actuation {
    let Some(ns) = workload_namespace(&mitigation.cut.from) else {
        return Actuation::DryRun;
    };
    let name = object_name("protector-isolate", mitigation);
    match np_api(client, ns)
        .delete(&name, &kube::api::DeleteParams::default())
        .await
    {
        Ok(_) => {
            tracing::info!(cut = %cut_label(mitigation), %name, "lifted workload isolation");
            Actuation::Reverted
        }
        Err(error) => {
            tracing::error!(%error, %name, "failed to lift isolation");
            Actuation::DryRun
        }
    }
}

/// Live actuator: applies/reverts the rendered `AdminNetworkPolicy` against the
/// cluster (ADR-0007). This is the cluster-facing glue — exercised only against a
/// real cluster; [`render_deny`] is the unit-tested part.
pub struct KubeActuator {
    client: kube::Client,
}

impl KubeActuator {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }

    fn anp_api(&self) -> kube::Api<kube::core::DynamicObject> {
        let gvk = kube::core::GroupVersionKind::gvk(
            "policy.networking.k8s.io",
            "v1alpha1",
            "AdminNetworkPolicy",
        );
        let ar = kube::core::ApiResource::from_gvk(&gvk);
        kube::Api::all_with(self.client.clone(), &ar)
    }
}

#[async_trait::async_trait]
impl Actuator for KubeActuator {
    async fn apply(&self, mitigation: &Mitigation) -> Actuation {
        // The default containment (ADR-0010) is a full default-deny NetworkPolicy on
        // the entry, not a surgical ANP edge-cut — standard NetworkPolicy is honored
        // by Cilium/Calico too, so apply it via the shared isolation glue.
        if mitigation.action == ProposedAction::QuarantineEntry {
            return apply_isolation(&self.client, mitigation).await;
        }
        let Some(manifest) = render_deny(mitigation) else {
            // Not an additive-live action; decide() should already have filtered
            // these out, so reaching here means a renderer gap.
            tracing::warn!(cut = %cut_label(mitigation), "no additive object to apply");
            return Actuation::DryRun;
        };
        let name = object_name("protector-deny", mitigation);
        let object: kube::core::DynamicObject = match serde_json::from_value(manifest) {
            Ok(o) => o,
            Err(error) => {
                tracing::error!(%error, "failed to build AdminNetworkPolicy");
                return Actuation::DryRun;
            }
        };
        let params = kube::api::PatchParams::apply("protector").force();
        match self
            .anp_api()
            .patch(&name, &params, &kube::api::Patch::Apply(&object))
            .await
        {
            Ok(_) => {
                tracing::info!(cut = %cut_label(mitigation), %name, "applied deny AdminNetworkPolicy");
                Actuation::Applied
            }
            Err(error) => {
                tracing::error!(%error, %name, "failed to apply mitigation");
                Actuation::DryRun
            }
        }
    }

    async fn revert(&self, mitigation: &Mitigation) -> Actuation {
        if mitigation.action == ProposedAction::QuarantineEntry {
            return revert_isolation(&self.client, mitigation).await;
        }
        let name = object_name("protector-deny", mitigation);
        match self
            .anp_api()
            .delete(&name, &kube::api::DeleteParams::default())
            .await
        {
            Ok(_) => {
                tracing::info!(cut = %cut_label(mitigation), %name, "reverted mitigation");
                Actuation::Reverted
            }
            Err(error) => {
                tracing::error!(%error, %name, "failed to revert mitigation");
                Actuation::DryRun
            }
        }
    }
}

/// Isolation actuator (ADR-0010): applies/reverts the default-deny `NetworkPolicy`
/// that quarantines the cut's source workload. Works on flannel/kube-router — no
/// ANP needed. Cluster-facing glue; [`render_isolation`] is the tested part.
pub struct IsolationActuator {
    client: kube::Client,
}

impl IsolationActuator {
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl Actuator for IsolationActuator {
    async fn apply(&self, mitigation: &Mitigation) -> Actuation {
        apply_isolation(&self.client, mitigation).await
    }

    async fn revert(&self, mitigation: &Mitigation) -> Actuation {
        revert_isolation(&self.client, mitigation).await
    }
}
