use super::*;

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
        // UID → (namespace, name) from the pod watch, so events a sensor attributed by
        // cgroup UID (the eBPF agent) resolve to a workload without the agent ever
        // touching the cluster API (ADR-0014). Falco events carry namespace/pod directly,
        // so only build the map when something actually needs UID resolution.
        let by_uid: std::collections::HashMap<String, (String, String)> =
            if snapshot.runtime_events.iter().any(|e| e.pod_uid.is_some()) {
                snapshot
                    .pods
                    .iter()
                    .filter_map(|p| {
                        let uid = p.metadata.uid.clone()?;
                        let name = p.metadata.name.clone()?;
                        Some((uid, (pod_namespace(p), name)))
                    })
                    .collect()
            } else {
                std::collections::HashMap::new()
            };

        let (mut attached, mut unresolved) = (0usize, 0usize);
        for event in &snapshot.runtime_events {
            let resolved = match &event.pod_uid {
                Some(uid) => match by_uid.get(uid) {
                    Some(ns_name) => ns_name.clone(),
                    None => {
                        // Unknown UID (pod gone / not yet observed) — drop, don't guess.
                        unresolved += 1;
                        continue;
                    }
                },
                None => (event.namespace.clone(), event.pod.clone()),
            };
            let key = NodeKey::workload(&resolved.0, "Pod", &resolved.1);
            graph.update_node(&key, |node| {
                if let Node::Workload(w) = node {
                    w.runtime.push(RuntimeSignal {
                        behavior: event.behavior.clone(),
                        provenance: Provenance::new(self.name(), SystemTime::now()),
                    });
                    attached += 1;
                }
            });
        }
        // One line per pass so the behavioral pipeline is observable: how many signals
        // landed on a workload, and how many UIDs didn't resolve (a persistent nonzero
        // `unresolved` means the agent's cgroup UIDs aren't matching pod metadata.uid).
        tracing::info!(
            attached,
            unresolved,
            events = snapshot.runtime_events.len(),
            "runtime behavioral signals"
        );
    }
}
