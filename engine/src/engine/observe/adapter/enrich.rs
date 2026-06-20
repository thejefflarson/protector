use super::*;
use crate::engine::graph::Behavior;

/// Annotates Image nodes with vulnerability findings (Vulnerability port). Like
/// [`ExposureAdapter`], it enriches existing Image nodes, so it runs after the
/// structural adapters. The live scanner source is wired in the Observer; this
/// adapter just maps normalized findings onto the matching Image node.
pub struct VulnerabilityAdapter;

impl Adapter for VulnerabilityAdapter {
    fn name(&self) -> &'static str {
        "vulnerability"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for finding in &snapshot.image_vulns {
            // Canonicalize the finding's ref to match the Image node the workload
            // adapter keyed (a short pod ref vs a scanner's fully-qualified one) —
            // without this the CVE silently fails to attach (security fix [15]).
            let key = Node::Image(Image {
                digest: canonical_image(&finding.image),
                reference: None,
                trust: Trust::Unknown,
                vulnerabilities: vec![],
            })
            .key();
            graph.update_node(&key, |node| {
                if let Node::Image(img) = node {
                    img.vulnerabilities = finding.vulnerabilities.clone();
                }
            });
        }
    }
}

/// Live runtime signals (RuntimeEvidence port): annotate a Workload with the
/// runtime events observed against it — the "is it happening now" corroboration
/// that completes the action bar. Enriches existing Workload nodes, so it runs
/// after the structural adapters.
pub struct RuntimeAdapter;

impl Adapter for RuntimeAdapter {
    fn name(&self) -> &'static str {
        "runtime"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        if snapshot.runtime_events.is_empty() {
            return;
        }
        // UID → the Pod from the watch, so events a sensor attributed by cgroup UID (the
        // eBPF agent) resolve to a workload without the agent ever touching the cluster
        // API (ADR-0014). The full Pod (not just ns/name) is needed to refine a raw
        // FileRead into a SecretRead via its volumeMounts. Falco events carry namespace/
        // pod directly, so only build the map when something needs UID resolution.
        let by_uid: std::collections::HashMap<String, &Pod> =
            if snapshot.runtime_events.iter().any(|e| e.pod_uid.is_some()) {
                snapshot
                    .pods
                    .iter()
                    .filter_map(|p| Some((p.metadata.uid.clone()?, p)))
                    .collect()
            } else {
                std::collections::HashMap::new()
            };

        let (mut attached, mut unresolved, mut filtered) = (0usize, 0usize, 0usize);
        for event in &snapshot.runtime_events {
            let (ns, name, pod): (String, String, Option<&Pod>) = match &event.pod_uid {
                Some(uid) => match by_uid.get(uid) {
                    Some(p) => (
                        pod_namespace(p),
                        p.metadata.name.clone().unwrap_or_default(),
                        Some(*p),
                    ),
                    None => {
                        // Unknown UID (pod gone / not yet observed) — drop, don't guess.
                        unresolved += 1;
                        continue;
                    }
                },
                None => (event.namespace.clone(), event.pod.clone(), None),
            };
            // Refine a raw FileRead (a tmpfs open the credential-free agent couldn't
            // classify) into a SecretRead using the pod's secret volumeMounts — or drop
            // it if the path isn't under a Secret mount (most tmpfs reads aren't). Other
            // behaviors pass through unchanged.
            let behavior = match &event.behavior {
                Behavior::FileRead { path } => match pod.and_then(|p| secret_for_path(p, path)) {
                    Some(secret) => {
                        // Real secret reads are sparse — log each at info (operability +
                        // confirms the secret-read probe end-to-end on the nodes).
                        tracing::info!(%secret, namespace = %ns, pod = %name, "secret read");
                        Behavior::SecretRead { secret }
                    }
                    None => {
                        filtered += 1;
                        continue;
                    }
                },
                other => other.clone(),
            };
            // Carry the sensor's identity and observation time into the provenance:
            // which sensor (so two sensors agreeing is corroboration, not one opaque
            // "runtime" source) and *when it observed* (not when this pass ran, which
            // lags by a batch interval + a judging pass). Both fall back gracefully for
            // older agents that omit the fields (ADR-0014).
            let source = event.source.as_deref().unwrap_or(self.name());
            let observed_at = event
                .observed_at_ms
                .map(|ms| SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(ms))
                .unwrap_or_else(SystemTime::now);
            let key = NodeKey::workload(&ns, "Pod", &name);
            graph.update_node(&key, |node| {
                if let Node::Workload(w) = node {
                    w.runtime.push(RuntimeSignal {
                        behavior: behavior.clone(),
                        provenance: Provenance::new(source, observed_at),
                    });
                    attached += 1;
                }
            });
        }
        // One line per pass so the behavioral pipeline is observable: signals attached,
        // UIDs that didn't resolve (a persistent nonzero means the agent's cgroup UIDs
        // aren't matching pod metadata.uid), and FileReads dropped as non-secret tmpfs.
        tracing::info!(
            attached,
            unresolved,
            filtered,
            events = snapshot.runtime_events.len(),
            "runtime behavioral signals"
        );
    }
}

/// If `path` (a container-relative path from the agent) falls under one of `pod`'s
/// mounted **Secret** volumes, return `"<secretName>/<subpath>"` (the secret that was
/// read); else `None` (not a secret — e.g. a ConfigMap, projected SA token, or a /tmp
/// read that merely happens to be on tmpfs). The longest matching mountPath wins, so a
/// nested mount is attributed to the right volume.
///
/// Only plain `.secret` volumes are recognized for now; projected volumes with secret
/// sources are a follow-up.
fn secret_for_path(pod: &Pod, path: &str) -> Option<String> {
    let spec = pod.spec.as_ref()?;
    // volume name -> secret name, for plain Secret volumes.
    let secret_vols: std::collections::HashMap<&str, &str> = spec
        .volumes
        .iter()
        .flatten()
        .filter_map(|v| Some((v.name.as_str(), v.secret.as_ref()?.secret_name.as_deref()?)))
        .collect();
    if secret_vols.is_empty() {
        return None;
    }
    let mut best: Option<(usize, String)> = None;
    for m in spec
        .containers
        .iter()
        .chain(spec.init_containers.iter().flatten())
        .flat_map(|c| c.volume_mounts.iter().flatten())
    {
        let Some(&secret_name) = secret_vols.get(m.name.as_str()) else {
            continue;
        };
        let Some(sub) = under(path, &m.mount_path) else {
            continue;
        };
        let len = m.mount_path.len();
        if best.as_ref().is_none_or(|&(l, _)| len > l) {
            let id = if sub.is_empty() {
                secret_name.to_string()
            } else {
                format!("{secret_name}/{sub}")
            };
            best = Some((len, id));
        }
    }
    best.map(|(_, id)| id)
}

/// If `path` is `mount_path` itself or a file beneath it, return the sub-path (possibly
/// empty); else `None`. The boundary check stops `/etc/foo` matching `/etc/foobar`.
fn under<'a>(path: &'a str, mount_path: &str) -> Option<&'a str> {
    let mp = mount_path.trim_end_matches('/');
    if path == mp {
        return Some("");
    }
    path.strip_prefix(mp)?.strip_prefix('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pod(value: serde_json::Value) -> k8s_openapi::api::core::v1::Pod {
        serde_json::from_value(value).expect("valid Pod fixture")
    }

    /// A pod that mounts Secret `db-creds` at /etc/creds and ConfigMap `cfg` at /etc/cfg.
    fn fixture() -> k8s_openapi::api::core::v1::Pod {
        pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "web", "namespace": "app"},
            "spec": {
                "containers": [{
                    "name": "web", "image": "web:1",
                    "volumeMounts": [
                        {"name": "creds", "mountPath": "/etc/creds", "readOnly": true},
                        {"name": "cfg", "mountPath": "/etc/cfg"}
                    ]
                }],
                "volumes": [
                    {"name": "creds", "secret": {"secretName": "db-creds"}},
                    {"name": "cfg", "configMap": {"name": "cfg"}}
                ]
            }
        }))
    }

    #[test]
    fn secret_read_under_a_secret_mount_is_named() {
        let p = fixture();
        assert_eq!(
            secret_for_path(&p, "/etc/creds/password"),
            Some("db-creds/password".into())
        );
        // The mount path itself (no sub-key) → just the secret name.
        assert_eq!(secret_for_path(&p, "/etc/creds"), Some("db-creds".into()));
    }

    #[test]
    fn non_secret_tmpfs_reads_are_dropped() {
        let p = fixture();
        // ConfigMap mount — tmpfs, but not a Secret.
        assert_eq!(secret_for_path(&p, "/etc/cfg/app.conf"), None);
        // Unrelated tmpfs read (/tmp), and a path that only prefixes a mount.
        assert_eq!(secret_for_path(&p, "/tmp/scratch"), None);
        assert_eq!(secret_for_path(&p, "/etc/credentials/x"), None);
    }

    #[test]
    fn longest_mount_path_wins_for_nested_secret_mounts() {
        let p = pod(json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "web", "namespace": "app"},
            "spec": {
                "containers": [{
                    "name": "web", "image": "web:1",
                    "volumeMounts": [
                        {"name": "outer", "mountPath": "/etc"},
                        {"name": "inner", "mountPath": "/etc/creds"}
                    ]
                }],
                "volumes": [
                    {"name": "outer", "secret": {"secretName": "outer-sec"}},
                    {"name": "inner", "secret": {"secretName": "inner-sec"}}
                ]
            }
        }));
        assert_eq!(
            secret_for_path(&p, "/etc/creds/key"),
            Some("inner-sec/key".into())
        );
    }
}
