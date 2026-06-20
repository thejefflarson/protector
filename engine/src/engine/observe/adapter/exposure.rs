use super::*;

/// True if `annotations` declares internet exposure via [`EXPOSURE_ANNOTATION`].
pub(super) fn declares_internet(annotations: Option<&BTreeMap<String, String>>) -> bool {
    annotations
        .and_then(|a| a.get(EXPOSURE_ANNOTATION))
        .is_some_and(|v| v.eq_ignore_ascii_case("internet"))
}

/// Sets a Workload's `exposure` fact — the entry side of the action bar — from the
/// Services that select it. A `LoadBalancer`/`NodePort` Service (or one with
/// `externalIPs`) makes its pods internet-reachable; any other selecting Service
/// makes them cluster-reachable. Exposure the engine can't *observe* — notably a
/// Cloudflare token tunnel fronting a `ClusterIP` Service — is declared with the
/// [`EXPOSURE_ANNOTATION`] on the Service or the pod (ADR-0012). Reads and rewrites
/// the Workload nodes the [`WorkloadAdapter`] created, so it must run after it.
pub struct ExposureAdapter;

impl ExposureAdapter {
    fn rank(exposure: Exposure) -> u8 {
        match exposure {
            Exposure::Internal => 0,
            Exposure::ClusterExposed => 1,
            Exposure::Internet => 2,
        }
    }

    fn service_exposure(service: &Service) -> Exposure {
        // A declared exposure wins — the tunnel/Ingress case the engine can't see.
        if declares_internet(service.metadata.annotations.as_ref()) {
            return Exposure::Internet;
        }
        let spec = service.spec.as_ref();
        let kind = spec.and_then(|s| s.type_.as_deref()).unwrap_or("ClusterIP");
        let has_external_ips = spec
            .and_then(|s| s.external_ips.as_ref())
            .is_some_and(|ips| !ips.is_empty());
        match kind {
            "LoadBalancer" | "NodePort" => Exposure::Internet,
            _ if has_external_ips => Exposure::Internet,
            _ => Exposure::ClusterExposed,
        }
    }
}

impl Adapter for ExposureAdapter {
    fn name(&self) -> &'static str {
        "exposure"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        for pod in &snapshot.pods {
            let Some(name) = pod.metadata.name.clone() else {
                continue;
            };
            let namespace = pod_namespace(pod);
            let labels = pod_labels(pod);

            let mut exposure = Exposure::Internal;
            for service in &snapshot.services {
                if service.metadata.namespace.as_deref() != Some(namespace.as_str()) {
                    continue;
                }
                let Some(selector) = service.spec.as_ref().and_then(|s| s.selector.as_ref()) else {
                    continue;
                };
                if selector.is_empty() {
                    continue;
                }
                if selector.iter().all(|(k, v)| labels.get(k) == Some(v)) {
                    let e = Self::service_exposure(service);
                    if Self::rank(e) > Self::rank(exposure) {
                        exposure = e;
                    }
                }
            }
            // A pod-level declaration also marks it internet-exposed (a workload
            // chart can annotate its own pod template for the tunnel case, ADR-0012).
            if declares_internet(pod.metadata.annotations.as_ref()) {
                exposure = Exposure::Internet;
            }
            if exposure == Exposure::Internal {
                continue;
            }

            // Layer the exposure fact onto the existing workload node, keeping its
            // identity and edges.
            let key = workload_node(&namespace, &name).key();
            graph.update_node(&key, |node| {
                if let Node::Workload(w) = node {
                    w.exposure = exposure;
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::observe::adapter::test_support::*;
    use serde_json::{Value, json};

    #[test]
    fn exposure_from_service_type_and_declared_annotation() {
        let workload_exposure = |snap: &Snapshot, ns: &str, name: &str| {
            let g = build_graph(snap, &default_adapters());
            match g.node(g.index_of(&workload_node(ns, name).key()).unwrap()) {
                Some(Node::Workload(w)) => w.exposure,
                _ => panic!("workload node"),
            }
        };
        let web = |annotations: Value| {
            pod(json!({
                "apiVersion": "v1", "kind": "Pod",
                "metadata": {"name": "web", "namespace": "app", "labels": {"app": "web"},
                             "annotations": annotations},
                "spec": {"containers": [{"name": "web", "image": "web:1"}]}
            }))
        };
        let svc = |type_: &str, annotations: Value| {
            serde_json::from_value::<Service>(json!({
                "apiVersion": "v1", "kind": "Service",
                "metadata": {"name": "web", "namespace": "app", "annotations": annotations},
                "spec": {"type": type_, "selector": {"app": "web"}}
            }))
            .unwrap()
        };

        // A plain ClusterIP Service → only cluster-exposed (the tunnel blind spot).
        let plain = Snapshot {
            pods: vec![web(json!({}))],
            services: vec![svc("ClusterIP", json!({}))],
            ..Default::default()
        };
        assert_eq!(
            workload_exposure(&plain, "app", "web"),
            Exposure::ClusterExposed
        );

        // The SAME ClusterIP Service, annotated as tunnel-fronted → Internet.
        let declared_svc = Snapshot {
            pods: vec![web(json!({}))],
            services: vec![svc(
                "ClusterIP",
                json!({"protector.jeffl.es/exposure": "internet"}),
            )],
            ..Default::default()
        };
        assert_eq!(
            workload_exposure(&declared_svc, "app", "web"),
            Exposure::Internet
        );

        // Declaring it on the pod works too, even with no Service at all.
        let declared_pod = Snapshot {
            pods: vec![web(json!({"protector.jeffl.es/exposure": "Internet"}))],
            ..Default::default()
        };
        assert_eq!(
            workload_exposure(&declared_pod, "app", "web"),
            Exposure::Internet
        );
    }
}
