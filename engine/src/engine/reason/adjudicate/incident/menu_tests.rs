use super::super::fixtures::{
    direct_mount_chain, direct_mount_entry_chain, empty_health, entry_key, store_key,
    store_live_signal, web_reaches_pivot_store, web_to_store_chain,
};
use super::*;

/// The entry line resolves through the SAME `containment_for` ladder
/// `respond::MitigationLedger::reconcile` calls — here the `reaches` edge is a reversible
/// additive edge-cut, so the resolver picks the surgical `DenyNetworkPath`, not the
/// coarser `QuarantineEntry` fallback ("resolver picks edge-cut ⊂ quarantine correctly").
#[test]
fn resolver_picks_the_surgical_edge_cut_over_quarantine_entry_when_one_exists() {
    let (graph, chains) = web_reaches_pivot_store(Vec::new(), true);
    let chain = web_to_store_chain(&chains);
    let menu = build_menu(chain, &graph, &empty_health());

    let entry_line = menu
        .selectable
        .iter()
        .find(|l| l.node == entry_key())
        .expect("the entry is selectable");
    assert_eq!(entry_line.action, ProposedAction::DenyNetworkPath);

    // Byte-for-byte the SAME resolution `containment_for` itself would produce — the
    // menu never disagrees with the ledger's own precedence.
    let (cut, action) = containment_for(chain).expect("a containment exists");
    assert_eq!(entry_line.action, action);
    assert_eq!(
        entry_line.cut_signature,
        crate::engine::respond::cut_signature(&cut)
    );
}

/// The positive contrast: no `reaches` edge exists (a direct mount chain), so
/// `containment_for`'s only additive-live+reversible rung is `QuarantineEntry`.
#[test]
fn resolver_falls_back_to_quarantine_entry_when_no_surgical_cut_exists() {
    let (graph, chains) = direct_mount_entry_chain();
    let chain = direct_mount_chain(&chains);
    let menu = build_menu(chain, &graph, &empty_health());

    let entry_line = menu
        .selectable
        .iter()
        .find(|l| l.node.0 == "workload/edge/Pod/argocd-server")
        .expect("the entry is selectable via the QuarantineEntry fallback");
    assert_eq!(entry_line.action, ProposedAction::QuarantineEntry);
}

/// A downstream workload the proof layer marked `RemotelyExploitable`
/// (`quarantine_targets`) gets its own selectable menu line, mechanism
/// `QuarantineWorkload` — resolved through the SAME `quarantine_workload_link`
/// `respond::MitigationLedger::reconcile` uses.
#[test]
fn downstream_evidence_bearing_workload_is_selectable_via_quarantine_workload() {
    let (graph, chains) = web_reaches_pivot_store(Vec::new(), true);
    let chain = web_to_store_chain(&chains);
    let menu = build_menu(chain, &graph, &empty_health());

    let store_line = menu
        .selectable
        .iter()
        .find(|l| l.node == store_key())
        .expect("store is selectable");
    assert_eq!(store_line.action, ProposedAction::QuarantineWorkload);
}

/// An unlabeled downstream pivot is evidence-bearing (a `RemotelyExploitable` quarantine
/// candidate) but NOT containable — `quarantine_workload_link` declines rather than widen
/// to a whole namespace (ADR-0022) — so it must appear ONLY in `uncontainable`, never in
/// `selectable` (the model must not be baited into naming it).
#[test]
fn unlabeled_downstream_pivot_is_uncontainable_not_selectable() {
    let (graph, chains) = web_reaches_pivot_store(Vec::new(), false);
    let chain = web_to_store_chain(&chains);
    let menu = build_menu(chain, &graph, &empty_health());

    assert!(
        !menu.selectable.iter().any(|l| l.node == store_key()),
        "an unlabeled pivot must never be selectable"
    );
    assert!(
        menu.uncontainable.contains(&store_key()),
        "an unlabeled but evidence-bearing pivot is aggregated as uncontainable"
    );
}

/// An entry whose ONLY containment is the durable-fix fallback (a subtractive RBAC
/// revoke, not additive-live) is likewise uncontainable — never offered as selectable,
/// so the model can't be baited into naming a node determinism can't actually cut.
#[test]
fn entry_with_no_additive_live_mechanism_is_uncontainable() {
    use super::super::fixtures::{internal_only_rbac_chain, internal_rbac_chain};

    let (graph, chains) = internal_only_rbac_chain();
    let chain = internal_rbac_chain(&chains);
    let menu = build_menu(chain, &graph, &empty_health());

    let entry = crate::engine::graph::NodeKey("workload/edge/Pod/internal-app".into());
    assert!(
        !menu.selectable.iter().any(|l| l.node == entry),
        "an entry with only a subtractive durable-fix rung must never be selectable"
    );
    assert!(menu.uncontainable.contains(&entry));
}

/// ADR-0022 entry-exclusion: even when the entry ALSO qualifies as a `quarantine_targets`
/// member (an `ActivelyExploited` entry, JEF-284 condition 2 fires on any pod, entry
/// included), the menu must list it exactly ONCE — via the entry ladder line, never a
/// second time as a "downstream" QuarantineWorkload line.
#[test]
fn entry_exclusion_the_entry_never_gets_a_second_downstream_line() {
    use crate::engine::observe::{Attribution, RuntimeObservation};

    let live_on_web = RuntimeObservation {
        attribution: Attribution::by_namespaced_name("app", "web"),
        source: None,
        observed_at_ms: None,
        node: None,
        behavior: crate::engine::graph::Behavior::FileWrite {
            path: "/usr/bin/dropper".into(),
        },
    };
    let (graph, chains) = web_reaches_pivot_store(vec![live_on_web], true);
    let chain = web_to_store_chain(&chains);
    assert!(
        chain
            .quarantine_targets
            .iter()
            .any(|t| t.node == entry_key()),
        "the entry itself is ALSO an ActivelyExploited quarantine target on this fixture"
    );

    let menu = build_menu(chain, &graph, &empty_health());
    let entry_lines: Vec<_> = menu
        .selectable
        .iter()
        .filter(|l| l.node == entry_key())
        .collect();
    assert_eq!(
        entry_lines.len(),
        1,
        "the entry appears exactly once on the menu, never duplicated as a downstream line"
    );
}

/// Content-derived id stability (ADR-0034 D4): building the SAME menu twice from the
/// same snapshot produces byte-identical `Menu` values and rendered text — cache-safe.
#[test]
fn menu_is_byte_identical_across_two_builds_of_the_same_snapshot() {
    let (graph, chains) = web_reaches_pivot_store(vec![store_live_signal()], true);
    let chain = web_to_store_chain(&chains);

    let first = build_menu(chain, &graph, &empty_health());
    let second = build_menu(chain, &graph, &empty_health());

    assert_eq!(first, second);
    assert_eq!(first.render(), second.render());
}

/// The selectable set is sorted by node key, not by traversal/insertion order.
#[test]
fn selectable_lines_are_sorted_by_node_key() {
    let (graph, chains) = web_reaches_pivot_store(vec![store_live_signal()], true);
    let chain = web_to_store_chain(&chains);
    let menu = build_menu(chain, &graph, &empty_health());

    let keys: Vec<_> = menu.selectable.iter().map(|l| l.node.0.clone()).collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
}

/// Every selectable line's mechanism text is one of `ProposedAction::describe`'s FIXED
/// strings — never untrusted text — and the node key is fenced.
#[test]
fn render_uses_only_fixed_mechanism_strings_and_fences_the_node_key() {
    let (graph, chains) = web_reaches_pivot_store(vec![store_live_signal()], true);
    let chain = web_to_store_chain(&chains);
    let menu = build_menu(chain, &graph, &empty_health());
    let rendered = menu.render();

    for line in &menu.selectable {
        assert!(rendered.contains(line.action.describe()));
        assert!(rendered.contains(&format!("<<<{}>>>", line.node.0)));
    }
}

/// A menu line always carries a blast-radius note (advisory; the actuator's own gate
/// still runs post-decision).
#[test]
fn every_selectable_line_carries_a_blast_radius_note() {
    let (graph, chains) = web_reaches_pivot_store(vec![store_live_signal()], true);
    let chain = web_to_store_chain(&chains);
    let menu = build_menu(chain, &graph, &empty_health());

    assert!(!menu.selectable.is_empty());
    for line in &menu.selectable {
        assert!(line.blast_note.starts_with("blast radius:"));
    }
}

/// `Menu::resolve` only ever returns a cut for a node ON the menu.
#[test]
fn resolve_returns_none_for_a_node_not_on_the_menu() {
    let (graph, chains) = web_reaches_pivot_store(Vec::new(), true);
    let chain = web_to_store_chain(&chains);
    let menu = build_menu(chain, &graph, &empty_health());

    let stranger = crate::engine::graph::NodeKey("workload/app/Pod/nonexistent".into());
    assert!(menu.resolve(&stranger).is_none());
}

/// An empty menu still renders a stable, non-panicking placeholder.
#[test]
fn empty_menu_renders_a_placeholder() {
    let menu = Menu::default();
    assert_eq!(menu.render(), "  (none)");
}
