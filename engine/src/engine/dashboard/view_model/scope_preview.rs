//! Map the engine's standing-cut snapshot ([`ScopePreviewStore`](crate::engine::state::ScopePreviewStore))
//! plus a CALLER-supplied candidate `enforceScope` into the [`ScopePreviewViewProps`] the
//! scope-preview panel renders (ADR-0021, ADR-0016): "what fires, and what it severs, if I
//! armed `mode: enforce` on this scope right now". Pure given its inputs — this file never
//! applies, arms, or mutates anything; it classifies data the engine already produced this
//! pass ([`preview_scope`]) and shapes the result into presentation props. Data layer:
//! touches `respond::`/`state::`; the components never do.

use crate::engine::respond::Mitigation;
use crate::engine::respond::actuator::scope_preview::{FiringCut, HeldCut, preview_scope};
use crate::engine::respond::actuator::{ActuationScope, BlastRadius};

use super::props::{FiringCutProps, HeldCutProps, ScopePreviewViewProps, StatusStripProps};

fn firing_cut_props(f: &FiringCut) -> FiringCutProps {
    FiringCutProps {
        cut: f.cut.clone(),
        action: f.action.describe().to_string(),
        alive_collateral: f.alive_collateral.clone(),
        collateral_unknown: f.collateral_unknown,
    }
}

fn held_cut_props(h: &HeldCut) -> HeldCutProps {
    HeldCutProps {
        cut: h.cut.clone(),
        action: h.action.describe().to_string(),
    }
}

/// Build the whole scope-preview panel's props: the persistent strip + the candidate scope
/// classification. `standing` is this pass's `(Mitigation, BlastRadius)` snapshot; `namespaces`
/// / `labels` are the caller's candidate `enforceScope`, already parsed. Pure given its inputs.
pub(super) fn build(
    strip: StatusStripProps,
    standing: &[(Mitigation, BlastRadius)],
    namespaces: &[String],
    labels: &[(String, String)],
) -> ScopePreviewViewProps {
    let candidate_is_empty = namespaces.is_empty() && labels.is_empty();
    let candidate = ActuationScope::new(namespaces.iter().cloned().collect(), labels.to_vec());
    let preview = preview_scope(standing, &candidate);
    ScopePreviewViewProps {
        strip,
        candidate_namespaces: namespaces.to_vec(),
        candidate_labels: labels.iter().map(|(k, v)| format!("{k}={v}")).collect(),
        candidate_is_empty,
        would_fire: preview.would_fire.iter().map(firing_cut_props).collect(),
        held_out_of_scope: preview
            .held_out_of_scope
            .iter()
            .map(held_cut_props)
            .collect(),
    }
}

#[cfg(test)]
mod tests;
