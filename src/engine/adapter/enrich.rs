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
        for event in &snapshot.runtime_events {
            let key = NodeKey::workload(&event.namespace, "Pod", &event.pod);
            graph.update_node(&key, |node| {
                if let Node::Workload(w) = node {
                    w.runtime.push(RuntimeSignal {
                        behavior: event.behavior.clone(),
                        provenance: Provenance::new(self.name(), SystemTime::now()),
                    });
                }
            });
        }
    }
}
