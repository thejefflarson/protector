//! The ADR-0040 §5 `ContainNode` revert seam: the builders that attach a live
//! [`respond::actuator::node_containment::NodeContainmentRevert`] actuator and observed
//! [`respond::actuator::node_containment::NodeFact`]s, and
//! [`Engine::revert_contain_node`] — the call `Engine::process`'s self-revert loop makes for
//! a standing `ContainNode` reversion instead of the generic network `actuator`. Extracted
//! from the orchestrator purely to keep every file under the 1,000-line cap (repo
//! CLAUDE.md); this is a behavior-neutral code move, not a design change — see
//! `respond::actuator::node_containment`'s own doc for why the revert side is wired now
//! while the apply side (the `node` arming rung, node observation, RBAC) is a follow-up.

use super::{Engine, Mitigation, graph, respond};

impl Engine {
    /// Attach the live node-containment revert actuator (ADR-0040 §5): the cluster-facing
    /// cordon-lift + co-resident-deny-lift half of `ContainNode`'s closed loop, reached
    /// through [`respond::actuator::node_containment::NodeContainmentRevert`] so a test can
    /// substitute a double for the real, `kube::Client`-backed
    /// [`respond::actuator::node_containment::NodeContainmentActuator`]. Builder-style.
    /// Engines that never call this (every existing test, and any embedding that doesn't
    /// opt in) leave a standing `ContainNode` mitigation un-reverted — see
    /// [`Self::revert_contain_node`] for why that is the safe default rather than a silent
    /// no-op through the wrong-shaped generic `actuator`.
    pub fn with_node_containment_actuator(
        mut self,
        actuator: Box<dyn respond::actuator::node_containment::NodeContainmentRevert>,
    ) -> Self {
        self.node_containment_actuator = Some(actuator);
        self
    }

    /// Seed one observed [`respond::actuator::node_containment::NodeFact`] for the
    /// `ContainNode` revert ownership self-gate (ADR-0040 §5), keyed by its own
    /// `name`. Builder-style, chainable per node. A real node-observation adapter
    /// refreshing this fleet every pass is a follow-up
    /// (`respond::actuator::node_containment`'s own doc); until then the map is exactly
    /// what a caller (today, only tests) seeded it with.
    pub fn with_node_fact(mut self, fact: respond::actuator::node_containment::NodeFact) -> Self {
        self.node_facts.insert(fact.name.clone(), fact);
        self
    }

    /// Revert a standing `ContainNode` mitigation (ADR-0040 §5): uncordon `mitigation`'s
    /// target host and lift its co-resident denies, through
    /// [`respond::actuator::node_containment::NodeContainmentRevert`] — never through the
    /// generic network `actuator`, whose `revert()` speaks a different object shape entirely
    /// (an `AdminNetworkPolicy`/`NetworkPolicy` delete, meaningless for a cordoned `Node`)
    /// and would silently leave the node cordoned.
    ///
    /// Skips (rather than fabricates) when either half of this pass's `ContainNode`
    /// readiness is missing: no live actuator attached yet
    /// ([`Self::with_node_containment_actuator`], a node-observation follow-up), or no
    /// observed [`NodeFact`](respond::actuator::node_containment::NodeFact) for this host
    /// ([`Self::with_node_fact`]) — the same "no fabricated no-data pass" discipline
    /// [`respond::actuator::node_containment`]'s own doc already applies to the cordon
    /// rails. When both are present, the attached actuator's OWN ownership self-gate
    /// (`revert_decision`) is still what decides whether the uncordon actually happens —
    /// this call only ever REACHES that gate, never bypasses it.
    pub(super) async fn revert_contain_node(
        &self,
        mitigation: &Mitigation,
        graph: &graph::SecurityGraph,
    ) {
        let Some(actuator) = &self.node_containment_actuator else {
            tracing::warn!(
                cut = %mitigation.cut.from.0,
                "no node-containment actuator attached; standing ContainNode cut left in place"
            );
            return;
        };
        let host_name = mitigation.cut.from.short();
        let Some(target) = self.node_facts.get(host_name) else {
            tracing::warn!(
                node = %host_name,
                "no observed NodeFact for this host; ContainNode revert skipped (ownership \
                 cannot be verified)"
            );
            return;
        };
        let co_resident =
            respond::actuator::node_containment::co_resident_denies(graph, &mitigation.cut.from);
        actuator.revert(mitigation, target, &co_resident).await;
    }
}
