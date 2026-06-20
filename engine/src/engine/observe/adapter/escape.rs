use super::*;

/// Linux capabilities whose presence on a container is a strong container-escape
/// signal (the capability half of KubeHound's `CE_*` family) — each grants a
/// concrete path to host code execution: SYS_ADMIN (mounts/cgroups), SYS_MODULE
/// (load a kernel module), SYS_PTRACE (attach to host processes under hostPID),
/// DAC_READ_SEARCH / DAC_OVERRIDE (read/write arbitrary host files).
///
/// SYS_PTRACE is escape-enabling ONLY together with hostPID (see [`escape_vias`]);
/// on its own the container sees only its own PID namespace, so it is gated there.
///
/// Deliberately EXCLUDED, because none yields host code execution on its own —
/// flagging them as escape-to-host (T1611) is a false positive:
/// - NET_ADMIN: network-stack control (NetworkPolicy bypass / MITM / sniff).
/// - SYS_BOOT: reboot the node (impact / DoS).
/// - DAC_OVERRIDE: bypasses file *permission* checks but NOT the mount namespace, so
///   with no host path mounted it is container-local (unlike DAC_READ_SEARCH, whose
///   open_by_handle_at reaches the host fs directly — the `shocker` read).
const ESCAPE_CAPABILITIES: &[&str] = &["SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "DAC_READ_SEARCH"];

/// `escapes-to` edges from a Workload to the Host it can break out to (ATT&CK
/// Escape to Host, T1611).
///
/// Documented subset, derived from pod spec alone: `privileged` containers,
/// `hostPID`/`hostIPC`, `hostPath` mounts (a mounted container-runtime socket is
/// flagged distinctly), and escape-enabling Linux capabilities. Each detected
/// primitive becomes one edge whose `via` names it — mirroring KubeHound's split
/// of escape into specific techniques. These prove escape *potential* (a
/// precondition), not exploitation (ADR-0001/0005); the action bar still needs
/// runtime corroboration.
pub struct HostEscapeAdapter;

impl HostEscapeAdapter {
    /// The escape primitives a pod exposes, each as a `via` label.
    fn escape_vias(pod: &Pod) -> Vec<String> {
        let mut vias = Vec::new();
        let Some(spec) = pod.spec.as_ref() else {
            return vias;
        };
        let host_pid = spec.host_pid == Some(true);
        if host_pid {
            vias.push("hostPID".to_string());
        }
        if spec.host_ipc == Some(true) {
            vias.push("hostIPC".to_string());
        }
        for c in spec
            .containers
            .iter()
            .chain(spec.init_containers.iter().flatten())
        {
            if let Some(sc) = &c.security_context {
                if sc.privileged == Some(true) {
                    vias.push("privileged".to_string());
                }
                if let Some(caps) = &sc.capabilities {
                    for cap in caps.add.iter().flatten() {
                        // SYS_PTRACE only enables host escape WITH hostPID — without it
                        // the container can't see, let alone attach to, host processes.
                        if cap == "SYS_PTRACE" && !host_pid {
                            continue;
                        }
                        if ESCAPE_CAPABILITIES.contains(&cap.as_str()) {
                            vias.push(format!("cap:{cap}"));
                        }
                    }
                }
            }
        }
        for vol in spec.volumes.iter().flatten() {
            if let Some(host_path) = &vol.host_path {
                let path = host_path.path.as_str();
                if path.contains("docker.sock")
                    || path.contains("containerd.sock")
                    || path.contains("crio.sock")
                {
                    vias.push("runtime-socket".to_string());
                } else {
                    vias.push("hostPath".to_string());
                }
            }
        }
        vias.sort();
        vias.dedup();
        vias
    }
}

impl Adapter for HostEscapeAdapter {
    fn name(&self) -> &'static str {
        "host-escape"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for pod in &snapshot.pods {
            let Some(name) = pod.metadata.name.clone() else {
                continue;
            };
            let vias = Self::escape_vias(pod);
            if vias.is_empty() {
                continue;
            }
            // We can only point the escape at a concrete Host once the pod is
            // scheduled; an unscheduled pod's escape potential has no host yet.
            let Some(node_name) = pod.spec.as_ref().and_then(|s| s.node_name.clone()) else {
                continue;
            };
            let namespace = pod_namespace(pod);
            let wl = graph.ensure_node(workload_node(&namespace, &name));
            let host = graph.upsert_node(Node::Host(Host { name: node_name }));
            for via in vias {
                graph.add_edge(wl, host, observed(self.name(), Relation::EscapesTo { via }));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::observe::adapter::test_support::*;
    use serde_json::json;

    #[test]
    fn host_escape_adapter_detects_primitives_and_links_to_host() {
        let snap = Snapshot {
            pods: vec![pod(json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "runner", "namespace": "ci"},
                "spec": {
                    "nodeName": "node-1",
                    "hostPID": true,
                    "volumes": [{
                        "name": "sock",
                        "hostPath": {"path": "/run/containerd/containerd.sock"}
                    }],
                    "containers": [{
                        "name": "runner", "image": "runner:1",
                        "securityContext": {"capabilities": {"add": ["SYS_ADMIN", "NET_BIND_SERVICE"]}}
                    }]
                }
            }))],
            ..Default::default()
        };
        let g = build_graph(&snap, &default_adapters());

        let wl = g.index_of(&workload_node("ci", "runner").key()).unwrap();
        let mut vias: Vec<String> = g
            .inner()
            .edges(wl)
            .filter_map(|e| match &e.weight().relation {
                Relation::EscapesTo { via } => Some(via.clone()),
                _ => None,
            })
            .collect();
        vias.sort();
        // hostPID, the runtime socket, and SYS_ADMIN are flagged; NET_BIND_SERVICE
        // is not an escape capability and is ignored.
        assert_eq!(
            vias,
            vec![
                "cap:SYS_ADMIN".to_string(),
                "hostPID".to_string(),
                "runtime-socket".to_string()
            ]
        );
    }

    /// SYS_PTRACE is an escape primitive only WITH hostPID — without it the container
    /// sees only its own PID namespace, so it must not be flagged (false-positive
    /// guard, the NET_ADMIN class of bug). NET_ADMIN/SYS_BOOT/DAC_OVERRIDE are never
    /// escapes and never flagged.
    fn ptrace_pod(host_pid: bool) -> Snapshot {
        Snapshot {
            pods: vec![pod(json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "p", "namespace": "ci"},
                "spec": {
                    "nodeName": "node-1",
                    "hostPID": host_pid,
                    "containers": [{
                        "name": "c", "image": "c:1",
                        "securityContext": {"capabilities": {"add":
                            ["SYS_PTRACE", "NET_ADMIN", "SYS_BOOT", "DAC_OVERRIDE"]}}
                    }]
                }
            }))],
            ..Default::default()
        }
    }

    fn escape_vias_of(snap: &Snapshot) -> Vec<String> {
        let g = build_graph(snap, &default_adapters());
        let wl = g.index_of(&workload_node("ci", "p").key()).unwrap();
        let mut vias: Vec<String> = g
            .inner()
            .edges(wl)
            .filter_map(|e| match &e.weight().relation {
                Relation::EscapesTo { via } => Some(via.clone()),
                _ => None,
            })
            .collect();
        vias.sort();
        vias
    }

    #[test]
    fn sys_ptrace_is_an_escape_only_with_host_pid() {
        // No hostPID: SYS_PTRACE is not escape; NET_ADMIN/SYS_BOOT/DAC_OVERRIDE never
        // are → no escape edges at all.
        assert!(escape_vias_of(&ptrace_pod(false)).is_empty());
        // hostPID present: hostPID itself + the now-relevant SYS_PTRACE are flagged.
        assert_eq!(
            escape_vias_of(&ptrace_pod(true)),
            vec!["cap:SYS_PTRACE".to_string(), "hostPID".to_string()]
        );
    }
}
