//! The Observer: the engine's window onto **observed** cluster state (ADR-0002).
//!
//! A [`Snapshot`] is the raw material the capability adapters map into the graph
//! vocabulary. This first slice observes by **listing** the objects the adapters
//! need; ADR-0004's `list`+`watch` is the incremental optimization that lands
//! next, but a periodic full list is the resync path the ADR already calls the
//! source of truth, so it is the honest v0.

pub mod adapter;
pub mod audit;
pub mod epss;
pub mod exec_class;
pub mod exploit_intel;
pub mod health;
pub mod ingest_guard;
pub mod ip_index;
pub mod linkerd;
pub mod runtime;
pub mod trivy;
pub mod trivy_config;
pub mod trivy_rbac;
pub mod trivy_secret;

use k8s_openapi::api::core::v1::{Pod, Secret, Service};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, Role, RoleBinding};
use kube::Api;
use kube::api::ListParams;
use kube::core::{ApiResource, DynamicObject, GroupVersionKind};
use serde_json::Value;

use super::graph::{ScanFinding, Severity, Vulnerability};

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

/// Normalized exposed-secret findings for one image (JEF-244), keyed by the image
/// reference as deployed — the [`trivy_secret`] adapter maps trivy-operator's
/// `ExposedSecretReport` into this, and it lands on the same Image node as the CVEs.
#[derive(Debug, Clone, PartialEq)]
pub struct ImageScanFindings {
    /// Image reference (must match how a workload names it — see [`ImageVulnerabilities`]).
    pub image: String,
    pub findings: Vec<ScanFinding>,
}

/// The identity of the workload a config-audit report describes (JEF-244) — the
/// `trivy-operator.resource.*` coordinates the report is stamped with. The kind is carried
/// for fidelity, but the misconfig adapter attaches by namespace + name to the matching
/// Pod workload node(s), since the graph models workloads as Pods (owner-reference
/// resolution to a Deployment/ReplicaSet is out of scope — see JEF-244 notes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadRef {
    pub namespace: String,
    pub kind: String,
    pub name: String,
}

/// Misconfiguration findings for one audited resource (JEF-244) — the [`trivy_config`]
/// adapter maps trivy-operator's `ConfigAuditReport` into this.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkloadFindings {
    pub resource: WorkloadRef,
    pub findings: Vec<ScanFinding>,
}

/// RBAC-assessment findings scoped to a namespace (JEF-244) — the [`trivy_rbac`] adapter maps
/// trivy-operator's namespaced `RbacAssessmentReport` into this. Attached to the workloads in
/// that namespace as structural RBAC-exposure evidence (it INFORMS the model's JEF-79
/// authorization reasoning, it does not re-implement it).
#[derive(Debug, Clone, PartialEq)]
pub struct RbacFindings {
    pub namespace: String,
    pub findings: Vec<ScanFinding>,
}

/// A non-empty string field from a report entry, or `None`. Empty strings (trivy
/// omits a field by emitting `""`, not by dropping the key) collapse to `None`. Shared by
/// the trivy report adapters ([`trivy`], [`trivy_secret`], [`trivy_config`], [`trivy_rbac`]).
pub(crate) fn opt_str(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Map trivy's severity label to the graph [`Severity`] band — shared by every trivy
/// report adapter so the mapping can't drift between report kinds.
pub(crate) fn severity(label: &str) -> Severity {
    match label {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        _ => Severity::Low,
    }
}

/// Map one trivy-operator report entry — a `checks[]` entry (config-audit / RBAC) or a
/// `secrets[]` entry (exposed-secret) — into a [`ScanFinding`]. One shared builder so the
/// three adapters can't drift on the redaction/escaping discipline they all owe their
/// untrusted free-text (the `title` is fenced/escaped downstream exactly like a CVE title).
///
/// The two axes that differ per report kind are passed in:
///   * `id_key` — the entry's stable id field (`checkID` for checks, `ruleID` for secrets);
///     an entry without it is malformed and dropped (`None`).
///   * `title_fallback` — the field used when `title` is absent (`description` for checks,
///     trivy's already-**redacted** `match` for secrets).
///
/// A `success: true` entry is a passing check and is dropped — config-audit / RBAC reports
/// carry that flag; an exposed-secret entry has no `success` field, so the gate is a no-op
/// there and the entry is kept (behavior identical to the per-adapter versions this
/// replaces). `target` is read uniformly from `target`; a config-audit check carries no
/// `target`, so it collapses to `None` — the same value the config adapter hard-coded.
pub(crate) fn scan_finding(
    value: &Value,
    source: &str,
    id_key: &str,
    title_fallback: &str,
) -> Option<ScanFinding> {
    use std::time::SystemTime;

    use super::graph::Provenance;

    // Default-failed: a malformed entry missing `success` is treated as a finding rather
    // than silently swallowed, but an explicit `success: true` is dropped.
    if value.get("success").and_then(Value::as_bool) == Some(true) {
        return None;
    }
    let id = opt_str(value, id_key)?;
    // Prefer the short `title`; fall back to the kind-specific field. Both untrusted
    // free-text — fenced/escaped downstream like a CVE title.
    let title = opt_str(value, "title").or_else(|| opt_str(value, title_fallback));
    Some(ScanFinding {
        id,
        severity: severity(
            value
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or("LOW"),
        ),
        category: opt_str(value, "category"),
        title,
        target: opt_str(value, "target"),
        sources: vec![Provenance::new(source, SystemTime::now())],
    })
}

/// Reconstruct the deployed image reference (`server/repository:tag`) from a trivy report's
/// `artifact`/`registry` fields so the finding lands on the right Image node. Best-effort:
/// digest-level matching would be canonical, but the report's artifact fields are what we
/// have. Shared by the vulnerability and exposed-secret adapters (both describe an image).
pub(crate) fn image_ref(report: &Value) -> Option<String> {
    let artifact = report.get("artifact")?;
    let repository = artifact.get("repository")?.as_str()?;
    let base = match report
        .get("registry")
        .and_then(|r| r.get("server"))
        .and_then(Value::as_str)
    {
        Some(server) => format!("{server}/{repository}"),
        None => repository.to_string(),
    };
    Some(match artifact.get("tag").and_then(Value::as_str) {
        Some(tag) => format!("{base}:{tag}"),
        None => base,
    })
}

/// Identify the resource a workload-scoped trivy report (`ConfigAuditReport` /
/// `RbacAssessmentReport`) describes, from the `trivy-operator.resource.*` labels the
/// operator stamps on every such CR (JEF-244). The namespace falls back to the CR's own
/// metadata namespace when the label is absent (trivy stamps both). Returns `None` — so the
/// report is skipped, never guessed — when the kind, name, or namespace can't be determined
/// (e.g. a cluster-scoped report with no namespace).
pub(crate) fn report_resource(object: &DynamicObject) -> Option<WorkloadRef> {
    let labels = object.metadata.labels.as_ref()?;
    let kind = labels.get("trivy-operator.resource.kind")?.clone();
    let name = labels.get("trivy-operator.resource.name")?.clone();
    let namespace = labels
        .get("trivy-operator.resource.namespace")
        .cloned()
        .or_else(|| object.metadata.namespace.clone())?;
    Some(WorkloadRef {
        namespace,
        kind,
        name,
    })
}

/// The behavioral port's input shape (ADR-0014), defined in the shared
/// [`protector_behavior`] crate so the engine and the first-party agent share one
/// definition rather than a hand-synced duplicate. Re-exported here because the Observer
/// and adapters refer to it as `observe::RuntimeObservation`. [`Attribution`] (how an
/// observation is attributed to a workload) is re-exported alongside it for the same reason.
pub use protector_behavior::{Attribution, RuntimeObservation};

/// The normalized API secret-read lifted from the apiserver audit log (JEF-269) — the
/// corroborating runtime signal the eBPF agent can't observe. Re-exported here because the
/// Observer and the audit adapter refer to it as `observe::AuditSecretRead`.
pub use self::audit::AuditSecretRead;

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
    /// Exposed-secret findings per image (JEF-244), from trivy-operator's
    /// `ExposedSecretReport`. Empty when the reports are absent.
    pub image_secrets: Vec<ImageScanFindings>,
    /// Misconfiguration findings per audited resource (JEF-244), from trivy-operator's
    /// `ConfigAuditReport`. Empty when the reports are absent.
    pub config_audits: Vec<WorkloadFindings>,
    /// RBAC-assessment findings per namespace (JEF-244), from trivy-operator's
    /// `RbacAssessmentReport`. Empty when the reports are absent.
    pub rbac_assessments: Vec<RbacFindings>,
    /// Live runtime events per workload (RuntimeEvidence port). Populated from a
    /// runtime sensor; see `observe`'s note on the live source.
    pub runtime_events: Vec<RuntimeObservation>,
    /// Live API secret-reads from the apiserver audit log (JEF-269) — the corroborating
    /// runtime signal for RBAC-granted secret access that eBPF can't see. Populated from
    /// the audit-webhook ingest ([`self::audit`]); empty when that feed isn't wired.
    pub audit_secret_reads: Vec<AuditSecretRead>,
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
            trivy_findings,
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
            // Secrets are listed METADATA-ONLY (JEF-268): `list_metadata` asks the
            // apiserver for `PartialObjectMeta<Secret>`, so `.data`/`stringData` never
            // cross the wire. Only identity (namespace + name) is retained, exactly what
            // `SecretMeta` and the graph's secret-objective nodes need. See the RBAC
            // caveat at the reflector watch site in `run_loop.rs`.
            async {
                anyhow::Ok(
                    Api::<Secret>::all(client.clone())
                        .list_metadata(&lp)
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
            async {
                anyhow::Ok(
                    list_parsed(
                        &client,
                        vulnerability_report_gvk(),
                        self::trivy::parse_report,
                    )
                    .await,
                )
            },
            // The other trivy-operator report kinds (JEF-244), best-effort like the CVE
            // report — empty when their CRDs are absent, so they never fail the join.
            async { anyhow::Ok(list_trivy_findings(&client).await) },
            async { anyhow::Ok(list_linkerd_authz(&client).await) },
        )?;
        let (image_secrets, config_audits, rbac_assessments) = trivy_findings;
        let (linkerd_servers, linkerd_authz_policies, linkerd_mtls_auths) = linkerd;

        // Runtime events come from a runtime sensor (Falco/Tetragon) — typically a
        // stream, not a list. Wiring that source is the remaining cluster-facing
        // glue for the RuntimeEvidence port; until it lands this is empty and the
        // RuntimeAdapter contributes nothing. The adapter and the action-bar
        // corroboration it drives are unit-tested against `RuntimeObservation`.
        let runtime_events = Vec::new();
        // API secret-reads come from the apiserver's audit webhook (JEF-269), a stream like
        // the runtime feed — never a list. Wired via the audit ingest in the run loop; this
        // full-list observe path leaves it empty and the AuditSecretReadAdapter contributes
        // nothing.
        let audit_secret_reads = Vec::new();

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
            image_secrets,
            config_audits,
            rbac_assessments,
            runtime_events,
            audit_secret_reads,
            linkerd_servers,
            linkerd_authz_policies,
            linkerd_mtls_auths,
        })
    }
}

/// Best-effort list of the other three trivy-operator report kinds (JEF-244):
/// `ExposedSecretReport`, `ConfigAuditReport`, and `RbacAssessmentReport`. Each is empty
/// when its CRD isn't installed or is unreadable, so the engine degrades to no data for that
/// signal rather than failing. The report→graph mappings are unit-tested in the respective
/// adapter modules; this is the cluster-facing list, shared by the poll observer and the
/// watch assembler.
pub async fn list_trivy_findings(
    client: &kube::Client,
) -> (
    Vec<ImageScanFindings>,
    Vec<WorkloadFindings>,
    Vec<RbacFindings>,
) {
    let secrets = list_parsed(
        client,
        trivy_report_gvk("ExposedSecretReport"),
        trivy_secret::parse_report,
    )
    .await;
    let configs = list_parsed(
        client,
        trivy_report_gvk("ConfigAuditReport"),
        trivy_config::parse_report,
    )
    .await;
    let rbac = list_parsed(
        client,
        trivy_report_gvk("RbacAssessmentReport"),
        trivy_rbac::parse_report,
    )
    .await;
    (secrets, configs, rbac)
}

/// The `aquasecurity.github.io/v1alpha1` GVK for a trivy-operator report `kind`.
fn trivy_report_gvk(kind: &str) -> GroupVersionKind {
    GroupVersionKind::gvk("aquasecurity.github.io", "v1alpha1", kind)
}

/// The GVK for trivy-operator's `VulnerabilityReport` — the source of normalized image
/// vulnerabilities. The report→graph mapping is unit-tested in [`self::trivy`].
pub(crate) fn vulnerability_report_gvk() -> GroupVersionKind {
    trivy_report_gvk("VulnerabilityReport")
}

/// List a CRD `kind` (named by its full [`GroupVersionKind`]) as `DynamicObject` and parse
/// each item, dropping the ones that don't parse. Empty (with a debug log) when the CRD is
/// absent or unreadable — the shared best-effort contract for every CRD list in this module
/// (trivy-operator reports and the Linkerd policy CRDs). The CRD's API group is the only
/// thing that varies between callers, so it rides in the GVK rather than as a separate axis.
pub(crate) async fn list_parsed<T>(
    client: &kube::Client,
    gvk: GroupVersionKind,
    parse: fn(&DynamicObject) -> Option<T>,
) -> Vec<T> {
    let ar = ApiResource::from_gvk(&gvk);
    match Api::<DynamicObject>::all_with(client.clone(), &ar)
        .list(&ListParams::default())
        .await
    {
        Ok(list) => list.items.iter().filter_map(parse).collect(),
        Err(error) => {
            tracing::debug!(%error, kind = %gvk.kind, "no CRD objects (operator/CRD absent?)");
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
    let linkerd_gvk = |version, kind| GroupVersionKind::gvk("policy.linkerd.io", version, kind);
    let servers = list_parsed(
        client,
        linkerd_gvk("v1beta3", "Server"),
        self::linkerd::parse_server,
    )
    .await;
    let policies = list_parsed(
        client,
        linkerd_gvk("v1alpha1", "AuthorizationPolicy"),
        self::linkerd::parse_authz_policy,
    )
    .await;
    let mtls = list_parsed(
        client,
        linkerd_gvk("v1alpha1", "MeshTLSAuthentication"),
        self::linkerd::parse_mtls_auth,
    )
    .await;
    (servers, policies, mtls)
}
