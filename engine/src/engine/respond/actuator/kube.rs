//! The cluster-facing live actuators: [`KubeActuator`] (the ADR-0007 additive
//! `AdminNetworkPolicy` deny) and [`IsolationActuator`] (the ADR-0010 default-deny
//! `NetworkPolicy` quarantine). Split out of the actuator module root purely to keep
//! every file under the 1,000-line cap (repo CLAUDE.md). This is the thin apply/revert
//! glue against the cluster — exercised only against a real cluster; the rendering it
//! drives ([`super::render`]) is the unit-tested part.

use super::super::Mitigation;
use super::render::{object_name, render_deny, render_isolation, workload_namespace};
use super::{Actuation, Actuator, cut_label};

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

    /// A dynamic `Api` for the namespaced `NetworkPolicy` we apply/delete.
    fn np_api(&self, ns: &str) -> kube::Api<kube::core::DynamicObject> {
        let gvk = kube::core::GroupVersionKind::gvk("networking.k8s.io", "v1", "NetworkPolicy");
        let ar = kube::core::ApiResource::from_gvk(&gvk);
        kube::Api::namespaced_with(self.client.clone(), ns, &ar)
    }
}

#[async_trait::async_trait]
impl Actuator for IsolationActuator {
    async fn apply(&self, mitigation: &Mitigation) -> Actuation {
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
        let api = self.np_api(ns);
        let params = kube::api::PatchParams::apply("protector").force();
        match api
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

    async fn revert(&self, mitigation: &Mitigation) -> Actuation {
        let Some(ns) = workload_namespace(&mitigation.cut.from) else {
            return Actuation::DryRun;
        };
        let name = object_name("protector-isolate", mitigation);
        let api = self.np_api(ns);
        match api.delete(&name, &kube::api::DeleteParams::default()).await {
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
}
