use super::*;

/// Secret nodes and `can-read` edges for secrets a pod can read directly, with no
/// API call: secret volumes, `secretKeyRef` env vars, and `envFrom` secret refs.
pub struct SecretMountAdapter;

impl SecretMountAdapter {
    /// Names of secrets `pod` reads directly, in its own namespace.
    fn mounted_secrets(pod: &Pod) -> Vec<String> {
        let mut names = Vec::new();
        let Some(spec) = pod.spec.as_ref() else {
            return names;
        };
        for vol in spec.volumes.iter().flatten() {
            if let Some(secret) = &vol.secret
                && let Some(n) = &secret.secret_name
            {
                names.push(n.clone());
            }
        }
        for c in spec
            .containers
            .iter()
            .chain(spec.init_containers.iter().flatten())
        {
            for env in c.env.iter().flatten() {
                if let Some(src) = &env.value_from
                    && let Some(sel) = &src.secret_key_ref
                {
                    names.push(sel.name.clone());
                }
            }
            for from in c.env_from.iter().flatten() {
                if let Some(sel) = &from.secret_ref {
                    names.push(sel.name.clone());
                }
            }
        }
        names.sort();
        names.dedup();
        names
    }
}

impl Adapter for SecretMountAdapter {
    fn name(&self) -> &'static str {
        "secret-mount"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for pod in &snapshot.pods {
            let Some(name) = pod.metadata.name.clone() else {
                continue;
            };
            let namespace = pod_namespace(pod);
            let secrets = Self::mounted_secrets(pod);
            if secrets.is_empty() {
                continue;
            }
            let wl = graph.ensure_node(workload_node(&namespace, &name));
            for secret in secrets {
                let sec = graph.upsert_node(Node::Secret(SecretRef {
                    namespace: namespace.clone(),
                    name: secret,
                }));
                graph.add_edge(wl, sec, observed(self.name(), Relation::CanRead));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::adapter::test_support::*;
    use serde_json::json;

    #[test]
    fn secret_mount_adapter_links_workload_to_secrets() {
        let snap = Snapshot {
            pods: vec![pod(json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "api", "namespace": "app"},
                "spec": {
                    "volumes": [{"name": "creds", "secret": {"secretName": "db-creds"}}],
                    "containers": [{
                        "name": "api",
                        "image": "ghcr.io/x/api:1",
                        "envFrom": [{"secretRef": {"name": "api-env"}}]
                    }]
                }
            }))],
            network_policies: vec![],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());
        let wl = g.index_of(&workload_node("app", "api").key()).unwrap();
        // Two can-read edges (db-creds volume, api-env envFrom).
        let can_read = g
            .inner()
            .edges(wl)
            .filter(|e| matches!(e.weight().relation, Relation::CanRead))
            .count();
        assert_eq!(can_read, 2);
    }
}
