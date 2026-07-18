//! Map the engine's [`Readiness`] coverage snapshot into the [`ReadinessViewProps`] the
//! Readiness view renders (brief §6). This is the per-feed "how to enable" surface: one row per
//! decision input, its honest Present/Absent/Degraded state, the live detail, why it matters, and
//! the env var to enable it. Rows that WEAKEN decisions when absent float to the top so the gaps
//! that demote the model's call are seen first. Data layer: touches `state::`; components never do.

use crate::engine::state::{InputState, NodeCoverageState, Readiness, ReadinessRow};

use super::props::{
    InputStateProps, NodeCoverageStateProps, NodeRowProps, ReadinessRowProps, ReadinessViewProps,
};

/// Map the engine's [`InputState`] into the presentation enum (the honesty stays: Absent and
/// Degraded never read as covered).
fn input_state(state: InputState) -> InputStateProps {
    match state {
        InputState::Present => InputStateProps::Present,
        InputState::Absent => InputStateProps::Absent,
        InputState::Degraded => InputStateProps::Degraded,
        InputState::Blind => InputStateProps::Blind,
        InputState::Stalled => InputStateProps::Stalled,
    }
}

/// Map an engine node-coverage state into its presentation enum (JEF-308).
fn node_state(state: NodeCoverageState) -> NodeCoverageStateProps {
    match state {
        NodeCoverageState::Healthy => NodeCoverageStateProps::Healthy,
        NodeCoverageState::Degraded => NodeCoverageStateProps::Degraded,
        NodeCoverageState::Blind => NodeCoverageStateProps::Blind,
        NodeCoverageState::OutOfScope => NodeCoverageStateProps::OutOfScope,
    }
}

/// Project one engine readiness row into its props, carrying any per-node breakdown (JEF-308).
fn row_props(row: &ReadinessRow) -> ReadinessRowProps {
    ReadinessRowProps {
        id: row.id.to_string(),
        label: row.label.to_string(),
        state: input_state(row.state),
        why: row.why.to_string(),
        enable: row.enable.to_string(),
        detail: row.detail.clone(),
        weakens_decisions: row.weakens_decisions,
        nodes: row
            .nodes
            .iter()
            .map(|n| NodeRowProps {
                node: n.node.clone(),
                state: node_state(n.state),
                detail: n.detail.clone(),
            })
            .collect(),
    }
}

/// Build the Readiness view's props from the live readiness snapshot. The strip is built by the
/// caller (the same persistent strip every view carries). Rows are ordered so the ones that
/// WEAKEN decisions when absent AND are not currently present float to the top (the gaps that
/// matter), then everything else keeps the engine's stable, decision-ordered sequence (brief §6).
/// Pure given its inputs — driveable in tests with no engine.
pub(super) fn map_readiness(readiness: &Readiness) -> Vec<ReadinessRowProps> {
    let mut rows: Vec<ReadinessRowProps> = readiness.inputs.iter().map(row_props).collect();
    // Stable partition: an unmet weakening input (weakens AND not present) sorts before the rest.
    // `sort_by_key` is stable, so within each group the engine's decision order is preserved.
    // The key is `false` for the attention rows so they sort first (false < true).
    rows.sort_by_key(|r| !is_attention_gap(r));
    rows
}

/// Whether a row is the attention case: an input that WEAKENS decisions when absent AND is not
/// currently present (absent or degraded) — the gap to surface first.
fn is_attention_gap(r: &ReadinessRowProps) -> bool {
    r.weakens_decisions && !r.state.is_present()
}

/// Build the whole Readiness view's props (rows + the persistent strip the caller supplies).
pub(super) fn build(
    strip: super::props::StatusStripProps,
    readiness: &Readiness,
) -> ReadinessViewProps {
    ReadinessViewProps {
        strip,
        rows: map_readiness(readiness),
    }
}

#[cfg(test)]
mod tests;
