//! Route-transitive internet exposure (ADR-0038): a backend Service that a live,
//! internet-exposed Ingress controller routes to inherits `Exposure::Internet`, so it
//! becomes a normal entry and flows through the *existing* edge-CVE promotion lane
//! (`reason/proof/chain.rs` derives every entry from `Workload.exposure`) with zero
//! change to proof, prompt, guards, or menu.
//!
//! **Controller-anchoring (D1).** Kubernetes has no object that names *which*
//! workload implements an `IngressClass`'s controller — `spec.controller` is an
//! opaque identifier string, not an object reference. Guessing via a naming/label
//! convention would risk exactly the over-promotion hazard ADR-0038 calls out. This
//! adapter instead uses the one piece of the API that *is* deterministic and
//! controller-agnostic: a live controller stamps `Ingress.status.loadBalancer` with
//! the address it is serving that Ingress from, and stamps the identical address on
//! its own fronting Service's `status.loadBalancer` (the "internet → LB → ingress →
//! backend" chain ADR-0038 names). Matching those two addresses finds the exact
//! controller workload with no naming convention and no fabrication risk — an
//! Ingress whose controller hasn't (yet, or ever) claimed it with a live address
//! simply never matches (fail-safe: under-promote).
//!
//! **Bounded fixpoint (D2).** "Chains compose" (ADR-0038): a backend just promoted to
//! `Exposure::Internet` can itself be the live, address-matched controller for a
//! *further* route it serves. [`IngressExposureAdapter::contribute`] therefore
//! re-scans every Ingress until a full pass makes no new promotion, bounded by the
//! graph's node count — the worst case for how many distinct workloads could ever
//! still be pending promotion, so a cycle can never spin the loop. In practice this
//! converges in one pass per hop of chaining (rare beyond 1-2).

use k8s_openapi::api::core::v1::LoadBalancerIngress;
use k8s_openapi::api::networking::v1::{Ingress, IngressClass, IngressLoadBalancerIngress};

use super::*;

/// The well-known, upstream Kubernetes annotation (not a protector convention) that
/// marks the single `IngressClass` new unclassed `Ingress` objects resolve to.
const DEFAULT_INGRESS_CLASS_ANNOTATION: &str = "ingressclass.kubernetes.io/is-default-class";

/// Sets a route-forwarded backend's `exposure` fact to `Exposure::Internet` when a
/// live, internet-exposed controller actually serves the route (ADR-0038). See the
/// module docs for the controller-anchoring and fixpoint rules. Reads and rewrites
/// the Workload nodes [`WorkloadAdapter`] created and [`ExposureAdapter`] already
/// stamped, so it must run after both.
pub struct IngressExposureAdapter;

impl Adapter for IngressExposureAdapter {
    fn name(&self) -> &'static str {
        "ingress_exposure"
    }

    fn contribute(&self, snapshot: &Snapshot, graph: &mut SecurityGraph) {
        // Bounded fixpoint (D2): see the module docs. `max(1)` so an empty graph still
        // runs one (no-op) pass rather than zero.
        for _ in 0..graph.node_count().max(1) {
            let mut changed = false;
            for ingress in &snapshot.ingresses {
                let Some(namespace) = ingress.metadata.namespace.as_deref() else {
                    continue;
                };
                if !controller_is_live(snapshot, graph, ingress) {
                    continue;
                }
                for service_name in ingress_backend_service_names(ingress) {
                    let Some(service) = snapshot.services.iter().find(|s| {
                        s.metadata.namespace.as_deref() == Some(namespace)
                            && s.metadata.name.as_deref() == Some(service_name)
                    }) else {
                        continue;
                    };
                    let Some(selector) = service.spec.as_ref().and_then(|s| s.selector.as_ref())
                    else {
                        continue;
                    };
                    for pod in selected_pods(snapshot, namespace, selector) {
                        let Some(pod_name) = pod.metadata.name.as_deref() else {
                            continue;
                        };
                        let key = workload_node(namespace, pod_name).key();
                        let mut promoted = false;
                        graph.update_node(&key, |node| {
                            if let Node::Workload(w) = node
                                && w.exposure != Exposure::Internet
                            {
                                w.exposure = Exposure::Internet;
                                promoted = true;
                            }
                        });
                        changed |= promoted;
                    }
                }
            }
            if !changed {
                break;
            }
        }
    }
}

/// Whether `ingress` is currently served by a live, internet-exposed controller
/// (ADR-0038 "controller-anchored"): its declared class must resolve to a real
/// `IngressClass`, and a Service's `status.loadBalancer` address must match the
/// Ingress's own — proof that a live controller actually claimed this specific
/// route — and that Service's selected pods must themselves be `Exposure::Internet`
/// in the graph (observed, declared, or promoted by an earlier fixpoint round).
fn controller_is_live(snapshot: &Snapshot, graph: &SecurityGraph, ingress: &Ingress) -> bool {
    let Some(ingress_lb) = ingress
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_ref())
        .filter(|lb| !lb.is_empty())
    else {
        return false;
    };
    // The referenced class must exist and carry a real controller identity — closes
    // the orphan/typo'd-class over-promotion path (an under-promote fail direction:
    // a route naming no resolvable class never propagates, ADR-0038).
    let Some(class) = resolve_ingress_class(snapshot, ingress) else {
        return false;
    };
    if class
        .spec
        .as_ref()
        .and_then(|s| s.controller.as_ref())
        .is_none()
    {
        return false;
    }

    snapshot.services.iter().any(|svc| {
        let Some(svc_lb) = svc
            .status
            .as_ref()
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_ref())
        else {
            return false;
        };
        if !lb_addresses_overlap(ingress_lb, svc_lb) {
            return false;
        }
        let Some(ns) = svc.metadata.namespace.as_deref() else {
            return false;
        };
        let Some(selector) = svc.spec.as_ref().and_then(|s| s.selector.as_ref()) else {
            return false;
        };
        selected_pods(snapshot, ns, selector).any(|pod| workload_is_internet(graph, ns, pod))
    })
}

/// True if any `(ip, hostname)` entry in `ingress_lb` shares a non-empty `ip` or
/// `hostname` with an entry in `svc_lb` — the same address a live controller
/// publishes both on the Ingress it serves and on its own fronting Service.
fn lb_addresses_overlap(
    ingress_lb: &[IngressLoadBalancerIngress],
    svc_lb: &[LoadBalancerIngress],
) -> bool {
    ingress_lb.iter().any(|il| {
        svc_lb.iter().any(|sl| {
            (il.ip.is_some() && il.ip == sl.ip)
                || (il.hostname.is_some() && il.hostname == sl.hostname)
        })
    })
}

/// Resolves `ingress`'s `IngressClass`: the explicitly named one, or — when
/// `ingressClassName` is unset — the cluster's single class carrying the upstream
/// [`DEFAULT_INGRESS_CLASS_ANNOTATION`]. Neither resolving is the orphan case
/// [`controller_is_live`] fails on.
fn resolve_ingress_class<'a>(
    snapshot: &'a Snapshot,
    ingress: &Ingress,
) -> Option<&'a IngressClass> {
    if let Some(name) = ingress
        .spec
        .as_ref()
        .and_then(|s| s.ingress_class_name.as_deref())
    {
        return snapshot
            .ingress_classes
            .iter()
            .find(|c| c.metadata.name.as_deref() == Some(name));
    }
    snapshot.ingress_classes.iter().find(|c| {
        c.metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(DEFAULT_INGRESS_CLASS_ANNOTATION))
            .is_some_and(|v| v == "true")
    })
}

/// Every backend Service name `ingress` routes to — its `defaultBackend` plus every
/// rule path's backend. A `resource` backend (not a Service) is skipped; it names a
/// non-Service object this adapter has no workload to promote. Always in the
/// Ingress's own namespace (the only namespace `IngressServiceBackend` can name).
fn ingress_backend_service_names(ingress: &Ingress) -> Vec<&str> {
    let Some(spec) = ingress.spec.as_ref() else {
        return Vec::new();
    };
    let mut names: Vec<&str> = spec
        .default_backend
        .as_ref()
        .and_then(|b| b.service.as_ref())
        .map(|s| s.name.as_str())
        .into_iter()
        .collect();
    for rule in spec.rules.iter().flatten() {
        let Some(http) = rule.http.as_ref() else {
            continue;
        };
        for path in &http.paths {
            if let Some(service) = path.backend.service.as_ref() {
                names.push(service.name.as_str());
            }
        }
    }
    names
}

/// Pods in `namespace` matching `selector` — the same "all key/value pairs present"
/// rule [`ExposureAdapter`] uses for Service→pod selection. An empty selector
/// matches nothing here (never "every pod in the namespace"), the same
/// over-promotion guard `ExposureAdapter::contribute` applies.
fn selected_pods<'a>(
    snapshot: &'a Snapshot,
    namespace: &str,
    selector: &BTreeMap<String, String>,
) -> impl Iterator<Item = &'a Pod> {
    snapshot.pods.iter().filter(move |pod| {
        !selector.is_empty() && pod_namespace(pod) == namespace && {
            // Hoisted out of the `all()` closure so a multi-key selector clones the
            // pod's labels once, not once per key.
            let labels = pod_labels(pod);
            selector.iter().all(|(k, v)| labels.get(k) == Some(v))
        }
    })
}

/// Whether the Workload node for `pod` (in `namespace`) is currently
/// `Exposure::Internet` in `graph`.
fn workload_is_internet(graph: &SecurityGraph, namespace: &str, pod: &Pod) -> bool {
    let Some(name) = pod.metadata.name.as_deref() else {
        return false;
    };
    let key = workload_node(namespace, name).key();
    matches!(
        graph.index_of(&key).and_then(|i| graph.node(i)),
        Some(Node::Workload(w)) if w.exposure == Exposure::Internet
    )
}

#[cfg(test)]
mod tests;
