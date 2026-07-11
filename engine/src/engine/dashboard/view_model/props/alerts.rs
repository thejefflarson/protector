//! The Alerts-view presentation props (JEF-323) — the live "alarming-now" activity surface. A
//! CURRENT-WINDOW view of the runtime signals alarming THIS pass (runtime signals live one pass
//! then clear — this is NOT a persisted audit log), each attributed to its (informer-resolved)
//! workload, with recency and the proven chain it is alarming ON. An alarming signal is EVIDENCE,
//! never a verdict (ADR-0016) — the copy never implies a breach conclusion, and it never claims
//! "corroborated": the engine reserves that axis for the Alert-only subset that flips
//! `ProvenChain::corroborated` (ADR-0009), and this set is broader.
//!
//! Split out of the parent `props` module to keep every file under the repo's 1,000-line cap
//! (CLAUDE.md); re-exported flat so `props::AlertProps` etc. resolve unchanged. The wire format
//! (ADR-0025): these props `serde`-serialize as the read-only Alerts JSON; every string is
//! UNTRUSTED and ships RAW (the render layer escapes; double-escaping is a bug), and the
//! server-derived [`AlertsViewProps::blind_caveat`] is shipped as the already-decided token so the
//! client never re-derives "is a quiet view honest?".

use super::status::StatusStripProps;

/// One alarming-now activity event for the Alerts tab (JEF-323). Pure presentation data — no
/// engine domain type leaks in. Every string is UNTRUSTED at render (the signal can carry an
/// attacker-chosen path, the rule an attacker-chosen name, the workload an attacker-influenced
/// pod name): the component auto-escapes them (maud `{}`, never `PreEscaped`). No stable id by
/// design — an alarming-now event is a current-window observation, not a reconcilable row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AlertProps {
    /// The signal, human-phrased (`"drop-and-execute: /usr/bin/x"`, `"contacted cloud-metadata"`,
    /// `"notable exec: bash"`, `"sensor rule fired: <rule>"`). Untrusted.
    pub signal: String,
    /// A stable, low-cardinality kind token (`alert`/`exec`/`write`/`peer`) — the CSS/glyph seam
    /// so a signal carries its kind without colour. Never per-instance payload.
    pub kind: String,
    /// The workload the signal was attributed to (informer-resolved short label), untrusted.
    pub workload: String,
    /// How recent the signal is, human-phrased (`"this pass"`, or the entry's age `"2m ago"`).
    /// Runtime signals are transient (one pass), so recency is the alarming chain's age — the
    /// honest "how long this has been alarming" — or simply "this pass" when no age is known.
    pub recency: String,
    /// The proven breach-relevant objective/chain this signal is alarming ON, if it lands on one
    /// (`"web \u{2192} db-creds"`), else `None` — an alarming signal with no proven chain still shows
    /// (it is alarming), it just lands on no specific chain yet. Untrusted. Deliberately NOT named
    /// "corroborates": the engine reserves the corroboration axis for the Alert-only subset that
    /// flips `ProvenChain::corroborated` (ADR-0009), and this set is broader (it includes
    /// engine-defined CONTEXT signals), so the view never asserts corroboration the engine didn't
    /// conclude.
    pub on_chain: Option<String>,
}

/// The whole Alerts view's props (JEF-323): the persistent strip + the current-window alarming-now
/// events + the honest calm/blind empty framing. When `alerts` is empty the view renders a CALM
/// "no alarming activity right now" state (reassuring, not an alarm) — UNLESS a node is blind, in
/// which case the caveat replaces the reassurance ("absence of a signal is not evidence of safety",
/// JEF-308). `blind_caveat` is `Some` exactly when at least one expected node has no live sensor.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AlertsViewProps {
    pub strip: StatusStripProps,
    /// The alarming-now events this pass, most-recent-first. A CURRENT-WINDOW view, not history.
    pub alerts: Vec<AlertProps>,
    /// The blind-node caveat (JEF-308) shown on the empty/quiet state, or `None` when every expected
    /// node has a live sensor. A quiet Alerts view must NOT read "all clear" while we are blind.
    pub blind_caveat: Option<String>,
}
