//! The Observer: the engine's window onto **observed** cluster state (ADR-0002).
//!
//! A [`Snapshot`] is the raw material the capability adapters map into the graph
//! vocabulary. This first slice observes by **listing** the objects the adapters
//! need; ADR-0004's `list`+`watch` is the incremental optimization that lands
//! next, but a periodic full list is the resync path the ADR already calls the
//! source of truth, so it is the honest v0.

pub mod adapter;
pub mod advisory;
pub mod exec_class;
pub mod exploit_intel;
pub mod health;
pub mod ingest_guard;
pub mod linkerd;
pub mod runtime;
pub mod trivy;

use k8s_openapi::api::core::v1::{Pod, Secret, Service};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, Role, RoleBinding};
use kube::Api;
use kube::api::ListParams;
use kube::core::{ApiResource, DynamicObject, GroupVersionKind};

use super::graph::Vulnerability;

/// Just enough of a Secret to reason about: its identity. We deliberately **do
/// not** retain secret *values* — the engine reasons about which identities can
/// reach which secrets, never about their contents (VISION: sensitive data stays
/// minimal and in-cluster).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMeta {
    pub namespace: String,
    pub name: String,
}

/// Normalized vulnerability findings for one image, keyed by the image reference
/// as deployed. This is the Vulnerability port's input shape — a scanner adapter
/// (trivy, grype, …) maps its reports into this; the graph never sees a vendor
/// type.
#[derive(Debug, Clone, PartialEq)]
pub struct ImageVulnerabilities {
    /// Image reference (must match how a workload names it, so it lands on the
    /// right Image node).
    pub image: String,
    pub vulnerabilities: Vec<Vulnerability>,
}

/// The behavioral port's input shape (ADR-0014), defined in the shared
/// [`protector_behavior`] crate so the engine and the first-party agent share one
/// definition rather than a hand-synced duplicate. Re-exported here because the Observer
/// and adapters refer to it as `observe::RuntimeObservation`. [`Attribution`] (how an
/// observation is attributed to a workload) is re-exported alongside it for the same reason.
pub use protector_behavior::{Attribution, RuntimeObservation};

/// A point-in-time view of the cluster objects this slice's adapters consume.
#[derive(Debug, Default, Clone)]
pub struct Snapshot {
    pub pods: Vec<Pod>,
    pub network_policies: Vec<NetworkPolicy>,
    pub services: Vec<Service>,
    pub secrets: Vec<SecretMeta>,
    pub roles: Vec<Role>,
    pub role_bindings: Vec<RoleBinding>,
    pub cluster_roles: Vec<ClusterRole>,
    pub cluster_role_bindings: Vec<ClusterRoleBinding>,
    /// Vulnerability findings per image (Vulnerability port). Populated from a
    /// scanner; see `observe`'s note on the live source.
    pub image_vulns: Vec<ImageVulnerabilities>,
    /// Live runtime events per workload (RuntimeEvidence port). Populated from a
    /// runtime sensor; see `observe`'s note on the live source.
    pub runtime_events: Vec<RuntimeObservation>,
    /// Linkerd authorization-policy inputs — the mesh-native reachability source
    /// (`Server` + `AuthorizationPolicy` + `MeshTLSAuthentication`). Empty when the
    /// policy CRDs aren't present. See [`self::linkerd`].
    pub linkerd_servers: Vec<self::linkerd::LinkerdServer>,
    pub linkerd_authz_policies: Vec<self::linkerd::LinkerdAuthzPolicy>,
    pub linkerd_mtls_auths: Vec<self::linkerd::LinkerdMeshTlsAuth>,
}

impl Snapshot {
    /// List the observed objects across all namespaces. This is the cluster-facing
    /// half of the engine and is exercised against a real cluster, not in unit
    /// tests; the adapters that interpret a `Snapshot` are what the tests cover.
    pub async fn observe(client: kube::Client) -> anyhow::Result<Self> {
        let lp = ListParams::default();

        // The lists are independent, so fire them concurrently (one round-trip of
        // latency, not nine) and fail the whole observe on the first error — same
        // semantics the sequential `?` chain had. Image vulns are best-effort
        // (return empty on absence), so they ride along without failing the join.
        let (
            pods,
            network_policies,
            services,
            secrets,
            roles,
            role_bindings,
            cluster_roles,
            cluster_role_bindings,
            image_vulns,
            linkerd,
        ) = tokio::try_join!(
            async { anyhow::Ok(Api::<Pod>::all(client.clone()).list(&lp).await?.items) },
            async {
                anyhow::Ok(
                    Api::<NetworkPolicy>::all(client.clone())
                        .list(&lp)
                        .await?
                        .items,
                )
            },
            async { anyhow::Ok(Api::<Service>::all(client.clone()).list(&lp).await?.items) },
            // Secrets are listed for their metadata only; values are dropped here and
            // never enter the graph.
            async {
                anyhow::Ok(
                    Api::<Secret>::all(client.clone())
                        .list(&lp)
                        .await?
                        .items
                        .into_iter()
                        .filter_map(|s| {
                            Some(SecretMeta {
                                namespace: s.metadata.namespace?,
                                name: s.metadata.name?,
                            })
                        })
                        .collect::<Vec<_>>(),
                )
            },
            async { anyhow::Ok(Api::<Role>::all(client.clone()).list(&lp).await?.items) },
            async {
                anyhow::Ok(
                    Api::<RoleBinding>::all(client.clone())
                        .list(&lp)
                        .await?
                        .items,
                )
            },
            async {
                anyhow::Ok(
                    Api::<ClusterRole>::all(client.clone())
                        .list(&lp)
                        .await?
                        .items,
                )
            },
            async {
                anyhow::Ok(
                    Api::<ClusterRoleBinding>::all(client.clone())
                        .list(&lp)
                        .await?
                        .items,
                )
            },
            async { anyhow::Ok(list_image_vulns(&client).await) },
            async { anyhow::Ok(list_linkerd_authz(&client).await) },
        )?;
        let (linkerd_servers, linkerd_authz_policies, linkerd_mtls_auths) = linkerd;

        // Runtime events come from a runtime sensor (Falco/Tetragon) — typically a
        // stream, not a list. Wiring that source is the remaining cluster-facing
        // glue for the RuntimeEvidence port; until it lands this is empty and the
        // RuntimeAdapter contributes nothing. The adapter and the action-bar
        // corroboration it drives are unit-tested against `RuntimeObservation`.
        let runtime_events = Vec::new();

        Ok(Self {
            pods,
            network_policies,
            services,
            secrets,
            roles,
            role_bindings,
            cluster_roles,
            cluster_role_bindings,
            image_vulns,
            runtime_events,
            linkerd_servers,
            linkerd_authz_policies,
            linkerd_mtls_auths,
        })
    }
}

/// Best-effort list of normalized image vulnerabilities from trivy-operator's
/// `VulnerabilityReport` CRDs. Empty if the CRD isn't installed or unreadable. The
/// report→graph mapping is unit-tested in [`self::trivy`]; this is the
/// cluster-facing list, shared by the poll observer and the watch assembler.
pub async fn list_image_vulns(client: &kube::Client) -> Vec<ImageVulnerabilities> {
    let gvk = GroupVersionKind::gvk("aquasecurity.github.io", "v1alpha1", "VulnerabilityReport");
    let ar = ApiResource::from_gvk(&gvk);
    match Api::<DynamicObject>::all_with(client.clone(), &ar)
        .list(&ListParams::default())
        .await
    {
        Ok(list) => list
            .items
            .iter()
            .filter_map(self::trivy::parse_report)
            .collect(),
        Err(error) => {
            tracing::debug!(%error, "no VulnerabilityReports (trivy-operator absent?)");
            Vec::new()
        }
    }
}

/// Best-effort list of the Linkerd policy CRDs the reachability adapter consumes
/// (`Server` v1beta3, `AuthorizationPolicy`/`MeshTLSAuthentication` v1alpha1). Empty
/// if Linkerd's policy CRDs aren't installed. The CRD→input mapping is unit-tested in
/// [`self::linkerd`]; this is the cluster-facing list, shared by the poll observer
/// and the watch assembler.
pub async fn list_linkerd_authz(
    client: &kube::Client,
) -> (
    Vec<self::linkerd::LinkerdServer>,
    Vec<self::linkerd::LinkerdAuthzPolicy>,
    Vec<self::linkerd::LinkerdMeshTlsAuth>,
) {
    let servers = list_dynamic(client, "v1beta3", "Server", self::linkerd::parse_server).await;
    let policies = list_dynamic(
        client,
        "v1alpha1",
        "AuthorizationPolicy",
        self::linkerd::parse_authz_policy,
    )
    .await;
    let mtls = list_dynamic(
        client,
        "v1alpha1",
        "MeshTLSAuthentication",
        self::linkerd::parse_mtls_auth,
    )
    .await;
    (servers, policies, mtls)
}

/// List a `policy.linkerd.io` kind as `DynamicObject` and parse each item, dropping
/// the ones that don't parse. Empty (with a debug log) when the CRD is absent.
async fn list_dynamic<T>(
    client: &kube::Client,
    version: &str,
    kind: &str,
    parse: fn(&DynamicObject) -> Option<T>,
) -> Vec<T> {
    let gvk = GroupVersionKind::gvk("policy.linkerd.io", version, kind);
    let ar = ApiResource::from_gvk(&gvk);
    match Api::<DynamicObject>::all_with(client.clone(), &ar)
        .list(&ListParams::default())
        .await
    {
        Ok(list) => list.items.iter().filter_map(parse).collect(),
        Err(error) => {
            tracing::debug!(%error, kind, "no Linkerd policy CRDs (linkerd absent?)");
            Vec::new()
        }
    }
}
