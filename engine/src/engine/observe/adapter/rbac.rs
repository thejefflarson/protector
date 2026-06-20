use super::*;

/// `can-do` edges from an Identity to a Secret it can read via RBAC.
///
/// Documented subset: ServiceAccount subjects, `Role`/`ClusterRole` refs, and the
/// read verbs (`get`/`list`/`watch`, or `*`) on `secrets` in the core group
/// (`""` or `*`). `resourceNames` restrictions are honored. A `RoleBinding`'s
/// grant is scoped to its own namespace; a `ClusterRoleBinding`'s applies in every
/// namespace. User/Group subjects, aggregation, and non-secret resources are not
/// modeled — this adapter answers exactly "which identity can read which secret",
/// which is what the proof layer needs to complete the privilege path to a secret.
pub struct PrivilegeAdapter;

impl PrivilegeAdapter {
    /// True if `rule` grants a read verb on secrets in the core API group.
    fn reads_secrets(rule: &PolicyRule) -> bool {
        let group_ok = rule
            .api_groups
            .as_ref()
            .is_some_and(|gs| gs.iter().any(|g| g.is_empty() || g == "*"));
        let resource_ok = rule
            .resources
            .as_ref()
            .is_some_and(|rs| rs.iter().any(|r| r == "secrets" || r == "*"));
        let verb_ok = rule
            .verbs
            .iter()
            .any(|v| matches!(v.as_str(), "get" | "list" | "watch" | "*"));
        group_ok && resource_ok && verb_ok
    }

    /// True if `rule` reaches the secret named `name` — either it lists no
    /// `resourceNames` (all secrets) or it names this one.
    fn names_secret(rule: &PolicyRule, name: &str) -> bool {
        match &rule.resource_names {
            Some(names) if !names.is_empty() => names.iter().any(|n| n == name),
            _ => true,
        }
    }

    /// Resolve a roleRef to the rules it carries, in `namespace` scope. A `Role`
    /// ref resolves against same-namespace Roles; a `ClusterRole` ref against
    /// ClusterRoles (whose rules then apply within `namespace`).
    fn rules_for<'a>(
        role_ref: &RoleRef,
        namespace: &str,
        snap: &'a Snapshot,
    ) -> Vec<&'a PolicyRule> {
        match role_ref.kind.as_str() {
            "Role" => snap
                .roles
                .iter()
                .find(|r| {
                    r.metadata.name.as_deref() == Some(&role_ref.name)
                        && r.metadata.namespace.as_deref() == Some(namespace)
                })
                .and_then(|r| r.rules.as_ref())
                .map(|rules| rules.iter().collect())
                .unwrap_or_default(),
            "ClusterRole" => Self::cluster_rules(&role_ref.name, snap),
            _ => Vec::new(),
        }
    }

    /// Rules of the named ClusterRole.
    fn cluster_rules<'a>(name: &str, snap: &'a Snapshot) -> Vec<&'a PolicyRule> {
        snap.cluster_roles
            .iter()
            .find(|cr| cr.metadata.name.as_deref() == Some(name))
            .and_then(|cr| cr.rules.as_ref())
            .map(|rules| rules.iter().collect())
            .unwrap_or_default()
    }

    /// The ServiceAccount identities `(namespace, name)` among `subjects`, with the
    /// binding's namespace as the default for subjects that omit one.
    fn service_accounts(
        subjects: Option<&Vec<Subject>>,
        default_ns: &str,
    ) -> Vec<(String, String)> {
        subjects
            .into_iter()
            .flatten()
            .filter(|s| s.kind == "ServiceAccount")
            .map(|s| {
                (
                    s.namespace
                        .clone()
                        .unwrap_or_else(|| default_ns.to_string()),
                    s.name.clone(),
                )
            })
            .collect()
    }
}

impl Adapter for PrivilegeAdapter {
    fn name(&self) -> &'static str {
        "rbac"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        // Both sets are deduped so a grant expressed by several rules or bindings
        // yields exactly one edge — duplicate edges would corrupt the proof
        // layer's single-edge-cut reasoning.
        //
        // Secret reads point at concrete Secret objects: (id_ns, id_name,
        // secret_ns, secret_name).
        let mut secret_grants: HashSet<(String, String, String, String)> = HashSet::new();
        // Dangerous capabilities point at Capability nodes: (id_ns, id_name, scope,
        // verb, resource).
        let mut cap_grants: HashSet<(String, String, Scope, &'static str, &'static str)> =
            HashSet::new();

        for rb in &snapshot.role_bindings {
            let ns = rb
                .metadata
                .namespace
                .clone()
                .unwrap_or_else(|| "default".to_string());
            let subjects = Self::service_accounts(rb.subjects.as_ref(), &ns);
            if subjects.is_empty() {
                continue;
            }
            for rule in Self::rules_for(&rb.role_ref, &ns, snapshot) {
                if Self::reads_secrets(rule) {
                    for secret in snapshot
                        .secrets
                        .iter()
                        .filter(|s| s.namespace == ns && Self::names_secret(rule, &s.name))
                    {
                        for (id_ns, id_name) in &subjects {
                            secret_grants.insert((
                                id_ns.clone(),
                                id_name.clone(),
                                secret.namespace.clone(),
                                secret.name.clone(),
                            ));
                        }
                    }
                }
                for cap in CAPABILITY_CATALOG.iter().filter(|c| Self::grants(rule, c)) {
                    for (id_ns, id_name) in &subjects {
                        cap_grants.insert((
                            id_ns.clone(),
                            id_name.clone(),
                            Scope::Namespace(ns.clone()),
                            cap.verb,
                            cap.resource,
                        ));
                    }
                }
            }
        }

        for crb in &snapshot.cluster_role_bindings {
            let subjects = Self::service_accounts(crb.subjects.as_ref(), "default");
            if subjects.is_empty() {
                continue;
            }
            for rule in Self::cluster_rules(&crb.role_ref.name, snapshot) {
                if Self::reads_secrets(rule) {
                    // Cluster-wide: every secret in every namespace.
                    for secret in snapshot
                        .secrets
                        .iter()
                        .filter(|s| Self::names_secret(rule, &s.name))
                    {
                        for (id_ns, id_name) in &subjects {
                            secret_grants.insert((
                                id_ns.clone(),
                                id_name.clone(),
                                secret.namespace.clone(),
                                secret.name.clone(),
                            ));
                        }
                    }
                }
                for cap in CAPABILITY_CATALOG.iter().filter(|c| Self::grants(rule, c)) {
                    for (id_ns, id_name) in &subjects {
                        cap_grants.insert((
                            id_ns.clone(),
                            id_name.clone(),
                            Scope::Cluster,
                            cap.verb,
                            cap.resource,
                        ));
                    }
                }
            }
        }

        for (id_ns, id_name, sec_ns, sec_name) in secret_grants {
            let id = graph.upsert_node(Node::Identity(Identity {
                namespace: id_ns,
                name: id_name,
            }));
            let secret = graph.upsert_node(Node::Secret(SecretRef {
                namespace: sec_ns,
                name: sec_name,
            }));
            graph.add_edge(
                id,
                secret,
                observed(
                    self.name(),
                    // Canonical read grant; get/list/watch all permit reading.
                    Relation::CanDo {
                        verb: "get".to_string(),
                        resource: "secrets".to_string(),
                    },
                ),
            );
        }

        for (id_ns, id_name, scope, verb, resource) in cap_grants {
            let id = graph.upsert_node(Node::Identity(Identity {
                namespace: id_ns,
                name: id_name,
            }));
            let capability = graph.upsert_node(Node::Capability(Capability {
                verb: verb.to_string(),
                resource: resource.to_string(),
                scope,
            }));
            graph.add_edge(
                id,
                capability,
                observed(
                    self.name(),
                    Relation::CanDo {
                        verb: verb.to_string(),
                        resource: resource.to_string(),
                    },
                ),
            );
        }
    }
}

impl PrivilegeAdapter {
    /// True if `rule` grants the dangerous capability `cap` — matching API group,
    /// resource (with `cap.resource == "*"` meaning any resource in the group),
    /// and verb, treating an RBAC `*` in the rule as matching anything.
    fn grants(rule: &PolicyRule, cap: &attack::DangerousCapability) -> bool {
        let group_ok = rule
            .api_groups
            .as_ref()
            .is_some_and(|gs| gs.iter().any(|g| g == cap.group || g == "*"));
        let resource_ok = cap.resource == "*"
            || rule
                .resources
                .as_ref()
                .is_some_and(|rs| rs.iter().any(|r| r == cap.resource || r == "*"));
        let verb_ok = rule.verbs.iter().any(|v| v == cap.verb || v == "*");
        group_ok && resource_ok && verb_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use petgraph::visit::EdgeRef;
    use serde_json::json;

    #[test]
    fn privilege_adapter_links_identity_to_readable_secret() {
        use crate::engine::observe::SecretMeta;
        use k8s_openapi::api::rbac::v1::{Role, RoleBinding};

        let role: Role = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
            "metadata": {"name": "secret-reader", "namespace": "app"},
            "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}]
        }))
        .unwrap();
        let binding: RoleBinding = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
            "metadata": {"name": "reader-binding", "namespace": "app"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "secret-reader"},
            "subjects": [{"kind": "ServiceAccount", "name": "reader-sa", "namespace": "app"}]
        }))
        .unwrap();

        let snap = Snapshot {
            secrets: vec![
                SecretMeta {
                    namespace: "app".into(),
                    name: "db-creds".into(),
                },
                // A secret in another namespace the Role does not reach.
                SecretMeta {
                    namespace: "other".into(),
                    name: "elsewhere".into(),
                },
            ],
            roles: vec![role],
            role_bindings: vec![binding],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());

        let id = g
            .index_of(
                &Node::Identity(Identity {
                    namespace: "app".into(),
                    name: "reader-sa".into(),
                })
                .key(),
            )
            .expect("identity node");
        let targets: Vec<_> = g
            .inner()
            .edges(id)
            .filter_map(|e| match &e.weight().relation {
                Relation::CanDo { resource, .. } if resource == "secrets" => {
                    g.key_of(e.target()).map(|k| k.0)
                }
                _ => None,
            })
            .collect();
        // Exactly the in-namespace secret is reachable; the RoleBinding is
        // namespace-scoped, so `other/elsewhere` is not granted.
        assert_eq!(targets, vec!["secret/app/db-creds".to_string()]);
    }

    #[test]
    fn privilege_adapter_mints_capability_nodes_for_cluster_admin() {
        use crate::engine::observe::SecretMeta;
        use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding};

        // A cluster-admin-style wildcard grant.
        let admin: ClusterRole = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
            "metadata": {"name": "cluster-admin"},
            "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
        }))
        .unwrap();
        let binding: ClusterRoleBinding = serde_json::from_value(json!({
            "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
            "metadata": {"name": "admin-binding"},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [{"kind": "ServiceAccount", "name": "ops-sa", "namespace": "ops"}]
        }))
        .unwrap();

        let snap = Snapshot {
            secrets: vec![SecretMeta {
                namespace: "ops".into(),
                name: "tok".into(),
            }],
            cluster_roles: vec![admin],
            cluster_role_bindings: vec![binding],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());

        let id = g
            .index_of(
                &Node::Identity(Identity {
                    namespace: "ops".into(),
                    name: "ops-sa".into(),
                })
                .key(),
            )
            .expect("identity node");
        let mut caps: Vec<String> = g
            .inner()
            .edges(id)
            .filter_map(|e| match &e.weight().relation {
                Relation::CanDo { verb, resource } if resource != "secrets" => {
                    Some(format!("{verb}/{resource}"))
                }
                _ => None,
            })
            .collect();
        caps.sort();
        // The wildcard grant mints every catalogued capability (cluster scope),
        // and no others.
        assert_eq!(
            caps,
            vec![
                "bind/*".to_string(),
                "create/clusterrolebindings".to_string(),
                "create/cronjobs".to_string(),
                "create/pods".to_string(),
                "create/pods/attach".to_string(),
                "create/pods/exec".to_string(),
                "create/rolebindings".to_string(),
                "delete/persistentvolumeclaims".to_string(),
                "escalate/*".to_string(),
            ]
        );
    }
}
