//! The Readiness-view presentation props (brief §6) — one row per decision input, with the honest
//! Present/Absent/Degraded state, the live detail, why it matters, and the env var to enable it.
//! Rows that weaken decisions when absent float to the top. Split out of the parent `props`
//! module to keep every file under the repo's 1,000-line cap (CLAUDE.md); re-exported flat so
//! `props::ReadinessRowProps` etc. resolve unchanged.
//!
//! The wire format (ADR-0025): these props `serde`-serialize as the read-only Readiness JSON. The
//! state enums serialize to STABLE lowercase string tags (`"present"`, `"blind"`, …) so the
//! client's switch is exhaustive over a fixed vocabulary, and [`ReadinessRowProps::id`] serializes
//! as the keyed reconcile anchor. Every string is UNTRUSTED and ships RAW (the render layer
//! escapes; double-escaping is a bug).

use super::status::StatusStripProps;

/// The LIVE state of one decision input — the presentation mirror of the engine's
/// `InputState`, carried as colour + glyph + word (never colour alone). Serialized as a STABLE
/// lowercase string tag (`"present"` / `"absent"` / `"degraded"`) — ADR-0025.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InputStateProps {
    /// Wired and live — contributing to decisions this pass.
    Present,
    /// Not configured (or loaded empty) — a coverage gap.
    Absent,
    /// Configured but not currently answering — a real, ambiguity-introducing gap.
    Degraded,
    /// A WAS-COVERING input has STALLED (JEF-421) — was reporting, now fully dark past the debounce.
    /// The loud edge, DISTINCT from `Absent` (never enabled). Serialized as `"stalled"`.
    Stalled,
}

impl InputStateProps {
    /// The CSS token suffix (`--cov-{kind}`) for this state.
    pub fn token(self) -> &'static str {
        match self {
            InputStateProps::Present => "present",
            InputStateProps::Absent => "absent",
            InputStateProps::Degraded => "degraded",
            InputStateProps::Stalled => "stalled",
        }
    }

    /// The glyph carrying the state without colour.
    pub fn glyph(self) -> &'static str {
        match self {
            InputStateProps::Present => "\u{2713}",  // ✓
            InputStateProps::Absent => "\u{2014}",   // —
            InputStateProps::Degraded => "\u{25D0}", // ◐
            InputStateProps::Stalled => "\u{26A0}",  // ⚠
        }
    }

    /// The word — always present alongside colour + glyph.
    pub fn word(self) -> &'static str {
        match self {
            InputStateProps::Present => "present",
            InputStateProps::Absent => "absent",
            InputStateProps::Degraded => "degraded",
            InputStateProps::Stalled => "stalled",
        }
    }

    /// Whether the input is contributing (Present). The honesty side: Absent/Degraded never
    /// read as covered.
    pub fn is_present(self) -> bool {
        matches!(self, InputStateProps::Present)
    }
}

/// One readiness row — a decision input's live coverage (brief §6). Carries only owned strings
/// and the small presentation enum; no engine type. A row that `weakens_decisions` when absent
/// is the kind that demotes the model's call (the enrichment inputs of ADR-0016).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ReadinessRowProps {
    /// The input's machine id (`model`/`kev`/…) — used as a stable anchor (the client reconcile
    /// key, ADR-0025).
    pub id: String,
    /// The human label for the input.
    pub label: String,
    pub state: InputStateProps,
    /// One-line "why it matters" — what protector loses without this input.
    pub why: String,
    /// The single env var / mount to enable it. Empty for arm-state (a posture toggle).
    pub enable: String,
    /// A short live detail (a count, "last call ok", "shadow mode").
    pub detail: String,
    /// Whether this input being absent WEAKENS the model's decision.
    pub weakens_decisions: bool,
    /// The per-node runtime-corroboration breakdown (JEF-308) — populated ONLY for the
    /// `runtime-corroboration` row, empty otherwise. Rendered as a server-side `<table>` inside
    /// `<details>` (no JS) so an operator can see exactly which node is blind.
    pub nodes: Vec<NodeRowProps>,
}

/// One node's line in the runtime-corroboration per-node breakdown (JEF-308). Every string is
/// UNTRUSTED at render (the node name can be attacker-influenced) — the component auto-escapes it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct NodeRowProps {
    /// The node name (untrusted).
    pub node: String,
    pub state: NodeCoverageStateProps,
    /// A short live detail (signal count, "quiet", probe fraction, or the blind reason).
    pub detail: String,
}

/// One expected node's honest liveness state (JEF-308) — colour + glyph + word, never colour alone.
/// "Quiet" and "blind" never collapse into one word: a quiet-but-healthy node is not a down sensor.
/// Serialized as a STABLE kebab-case string tag (`"healthy"` / `"blind"` / `"out-of-scope"` …) —
/// ADR-0025.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeCoverageStateProps {
    /// Reporting with probes loaded (quiet counts).
    Healthy,
    /// Reporting but only some probes attached.
    Degraded,
    /// No live sensor on this expected node — the attention case.
    Blind,
    /// A node the agent isn't scheduled on — out-of-scope, not blind.
    OutOfScope,
}

impl NodeCoverageStateProps {
    /// The CSS token suffix (`--node-{kind}`) / `data-state` value.
    pub fn token(self) -> &'static str {
        match self {
            NodeCoverageStateProps::Healthy => "healthy",
            NodeCoverageStateProps::Degraded => "degraded",
            NodeCoverageStateProps::Blind => "blind",
            NodeCoverageStateProps::OutOfScope => "out-of-scope",
        }
    }

    /// The glyph carrying the state without colour.
    pub fn glyph(self) -> &'static str {
        match self {
            NodeCoverageStateProps::Healthy => "\u{2713}",    // ✓
            NodeCoverageStateProps::Degraded => "\u{25D0}",   // ◐
            NodeCoverageStateProps::Blind => "\u{25CF}",      // ●
            NodeCoverageStateProps::OutOfScope => "\u{2014}", // —
        }
    }

    /// The word — always present alongside colour + glyph.
    pub fn word(self) -> &'static str {
        match self {
            NodeCoverageStateProps::Healthy => "healthy",
            NodeCoverageStateProps::Degraded => "degraded",
            NodeCoverageStateProps::Blind => "BLIND",
            NodeCoverageStateProps::OutOfScope => "out-of-scope",
        }
    }
}

/// The whole Readiness view's props: the persistent strip + the coverage rows, weakening-inputs
/// first.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ReadinessViewProps {
    pub strip: StatusStripProps,
    /// Coverage rows — weakening-when-absent inputs float to the top (brief §6).
    pub rows: Vec<ReadinessRowProps>,
}
