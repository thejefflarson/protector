//! Linkerd authorization-policy → reachability inputs.
//!
//! On a Linkerd-meshed cluster the east-west reachability intent often lives in
//! Linkerd's policy CRDs, not in `NetworkPolicy`: a [`Server`] selects the target
//! pods + port, an [`AuthorizationPolicy`] says who may reach it, and a
//! [`MeshTLSAuthentication`] names the client ServiceAccount identities. The engine
//! would otherwise be blind to all of it (it only reads `NetworkPolicy`).
//!
//! This module is the pure mapping from the CRDs' JSON into typed inputs; the
//! cluster-facing list lives in [`super::observe`] and the graph edges are minted by
//! the `LinkerdReachabilityAdapter`. Both are unit-tested without a cluster.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::core::DynamicObject;
use serde_json::Value;

/// A Linkerd `Server`: the target pods (by selector) and port it governs.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkerdServer {
    pub namespace: String,
    pub name: String,
    pub pod_selector: LabelSelector,
    /// The app port the Server governs. `None` for a named port we can't resolve to a
    /// number (the edge is still added, port-unspecified).
    pub port: Option<u16>,
}

/// A client identity an [`AuthorizationPolicy`] authorizes — resolved to the
/// ServiceAccount(s) whose workloads are allowed to reach the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthClient {
    /// A `MeshTLSAuthentication` (by name, in the policy's namespace) — its
    /// `identityRefs` ServiceAccounts are the authorized clients.
    MeshTls(String),
    /// A ServiceAccount named directly as the policy's `requiredAuthenticationRefs`
    /// or as the authorization subject.
    ServiceAccount { namespace: String, name: String },
}

/// A Linkerd `AuthorizationPolicy`: who (`clients`) may reach what (`target_server`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkerdAuthzPolicy {
    pub namespace: String,
    /// `targetRef` → a `Server` name in this namespace. `None` when the target is not
    /// a Server (e.g. a Namespace or HTTPRoute target — not modeled yet).
    pub target_server: Option<String>,
    pub clients: Vec<AuthClient>,
}

/// A Linkerd `MeshTLSAuthentication`: a named set of client ServiceAccount identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkerdMeshTlsAuth {
    pub namespace: String,
    pub name: String,
    pub identities: Vec<ServiceAccountRef>,
}

/// A `(namespace, name)` ServiceAccount reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccountRef {
    pub namespace: String,
    pub name: String,
}

fn namespace(obj: &DynamicObject) -> String {
    obj.metadata
        .namespace
        .clone()
        .unwrap_or_else(|| "default".to_string())
}

/// Parse a port that the CRD models as either an integer or a (possibly numeric)
/// string. A non-numeric named port yields `None`.
fn parse_port(value: &Value) -> Option<u16> {
    match value {
        Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Parse a Linkerd `Server`.
pub fn parse_server(obj: &DynamicObject) -> Option<LinkerdServer> {
    let name = obj.metadata.name.clone()?;
    let spec = obj.data.get("spec")?;
    let pod_selector: LabelSelector =
        serde_json::from_value(spec.get("podSelector")?.clone()).ok()?;
    Some(LinkerdServer {
        namespace: namespace(obj),
        name,
        pod_selector,
        port: spec.get("port").and_then(parse_port),
    })
}

/// Parse a Linkerd `AuthorizationPolicy` — its Server target and authorized clients.
pub fn parse_authz_policy(obj: &DynamicObject) -> Option<LinkerdAuthzPolicy> {
    let ns = namespace(obj);
    let spec = obj.data.get("spec")?;
    let target = spec.get("targetRef")?;
    let target_server = (target.get("kind").and_then(Value::as_str) == Some("Server"))
        .then(|| {
            target
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .flatten();

    let mut clients = Vec::new();
    for r in spec
        .get("requiredAuthenticationRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let kind = r.get("kind").and_then(Value::as_str).unwrap_or_default();
        let Some(name) = r.get("name").and_then(Value::as_str) else {
            continue;
        };
        match kind {
            "MeshTLSAuthentication" => clients.push(AuthClient::MeshTls(name.to_string())),
            "ServiceAccount" => clients.push(AuthClient::ServiceAccount {
                namespace: r
                    .get("namespace")
                    .and_then(Value::as_str)
                    .unwrap_or(&ns)
                    .to_string(),
                name: name.to_string(),
            }),
            _ => {}
        }
    }
    Some(LinkerdAuthzPolicy {
        namespace: ns,
        target_server,
        clients,
    })
}

/// Parse a Linkerd `MeshTLSAuthentication` — its authorized client ServiceAccounts.
pub fn parse_mtls_auth(obj: &DynamicObject) -> Option<LinkerdMeshTlsAuth> {
    let name = obj.metadata.name.clone()?;
    let ns = namespace(obj);
    let spec = obj.data.get("spec")?;
    let identities = spec
        .get("identityRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|r| r.get("kind").and_then(Value::as_str) == Some("ServiceAccount"))
        .filter_map(|r| {
            Some(ServiceAccountRef {
                namespace: r
                    .get("namespace")
                    .and_then(Value::as_str)
                    .unwrap_or(&ns)
                    .to_string(),
                name: r.get("name").and_then(Value::as_str)?.to_string(),
            })
        })
        .collect();
    Some(LinkerdMeshTlsAuth {
        namespace: ns,
        name,
        identities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(value: Value) -> DynamicObject {
        serde_json::from_value(value).expect("valid object")
    }

    #[test]
    fn parses_server_authz_and_mtls() {
        let server = parse_server(&obj(json!({
            "apiVersion": "policy.linkerd.io/v1beta3", "kind": "Server",
            "metadata": {"name": "watcher-db", "namespace": "watcher"},
            "spec": {
                "podSelector": {"matchLabels": {"application": "spilo", "cluster-name": "watcher-db"}},
                "port": 5432, "proxyProtocol": "opaque"
            }
        })))
        .expect("server");
        assert_eq!(server.name, "watcher-db");
        assert_eq!(server.port, Some(5432));

        let policy = parse_authz_policy(&obj(json!({
            "apiVersion": "policy.linkerd.io/v1alpha1", "kind": "AuthorizationPolicy",
            "metadata": {"name": "watcher-db-allow", "namespace": "watcher"},
            "spec": {
                "targetRef": {"group": "policy.linkerd.io", "kind": "Server", "name": "watcher-db"},
                "requiredAuthenticationRefs": [
                    {"group": "policy.linkerd.io", "kind": "MeshTLSAuthentication", "name": "watcher-db-clients"}
                ]
            }
        })))
        .expect("policy");
        assert_eq!(policy.target_server.as_deref(), Some("watcher-db"));
        assert_eq!(
            policy.clients,
            vec![AuthClient::MeshTls("watcher-db-clients".into())]
        );

        let mtls = parse_mtls_auth(&obj(json!({
            "apiVersion": "policy.linkerd.io/v1alpha1", "kind": "MeshTLSAuthentication",
            "metadata": {"name": "watcher-db-clients", "namespace": "watcher"},
            "spec": {"identityRefs": [
                {"kind": "ServiceAccount", "name": "watcher-server", "namespace": "watcher"},
                {"kind": "ServiceAccount", "name": "postgres-operator", "namespace": "data"}
            ]}
        })))
        .expect("mtls");
        assert_eq!(mtls.identities.len(), 2);
        assert_eq!(mtls.identities[0].name, "watcher-server");
        assert_eq!(mtls.identities[1].namespace, "data");
    }
}
