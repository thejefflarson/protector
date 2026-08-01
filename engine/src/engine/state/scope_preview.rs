//! The standing-cut snapshot the pre-arm scope-simulation preview reads (ADR-0021,
//! ADR-0016): one `(Mitigation, BlastRadius)` pair per currently-active mitigation,
//! captured verbatim from the SAME point in the pass the live actuator loop already
//! computes each cut's blast radius — so the preview classifies the exact numbers the
//! blast gate acted on, never a second, independently-derived copy. Pure data, like every
//! other handle in this module: no rendering, no decision.

use std::sync::Mutex;

use crate::engine::respond::Mitigation;
use crate::engine::respond::actuator::BlastRadius;

/// A snapshot of this pass's active mitigations paired with their predicted blast radius,
/// overwritten wholesale each pass (like [`super::Findings`]'s rows) — a snapshot, not a
/// ring: the preview only ever reasons about what is standing THIS pass, never a stale one.
#[derive(Default)]
pub struct ScopePreviewStore {
    standing: Mutex<Vec<(Mitigation, BlastRadius)>>,
}

impl ScopePreviewStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace this pass's standing snapshot.
    pub fn set(&self, standing: Vec<(Mitigation, BlastRadius)>) {
        *self
            .standing
            .lock()
            .expect("scope preview store mutex poisoned") = standing;
    }

    /// A read-only clone of the current snapshot, for the dashboard's on-demand
    /// scope-preview projection.
    pub fn snapshot(&self) -> Vec<(Mitigation, BlastRadius)> {
        self.standing
            .lock()
            .expect("scope preview store mutex poisoned")
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::graph::NodeKey;
    use crate::engine::reason::proof::Link;
    use crate::engine::respond::ProposedAction;

    fn mitigation() -> Mitigation {
        Mitigation {
            cut: Link {
                from: NodeKey("workload/app/Pod/web".to_string()),
                to: NodeKey("workload/app/Pod/db".to_string()),
                relation: "reaches/Tcp/5432".to_string(),
                technique: None,
                from_labels: Default::default(),
                to_labels: Default::default(),
            },
            action: ProposedAction::DenyNetworkPath,
            justifications: vec![],
        }
    }

    #[test]
    fn starts_empty_and_reflects_the_latest_set_call() {
        let store = ScopePreviewStore::new();
        assert!(store.snapshot().is_empty());

        store.set(vec![(mitigation(), BlastRadius::default())]);
        assert_eq!(store.snapshot().len(), 1);

        // A later pass with nothing standing replaces the snapshot, it doesn't append.
        store.set(vec![]);
        assert!(store.snapshot().is_empty());
    }
}
