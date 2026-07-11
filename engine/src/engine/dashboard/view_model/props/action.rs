//! The Action-view presentation props (brief §4/§6) — the engine's whole action story in
//! LIFECYCLE order (the merged Trust + Activity tabs): PROPOSED CUTS (would-act proposals + their
//! self-reverted continuations) → LEFT ALONE (proven paths the model cleared) → JUDGEMENT AUDIT
//! (the verbatim prompt/reply ring). Honest empties throughout: `journal_empty` distinct from
//! none-in-window; "no cuts reverted yet"; "no judgements recorded".
//!
//! Split out of the parent `props` module to keep every file under the repo's 1,000-line cap
//! (CLAUDE.md); re-exported flat so `props::ActionViewProps` etc. resolve unchanged. The wire
//! format (ADR-0025): these props `serde`-serialize as the read-only Action JSON; every string is
//! UNTRUSTED and ships RAW (the render layer escapes; double-escaping is a bug). View-never-a-gate:
//! nothing here is a decision — the payload is a read-only projection of the journal/rings.

use super::status::StatusStripProps;

/// One workload the engine WOULD have isolated in the window — a still-standing proposed cut (the
/// scrutinize side of the diff). Carries its lifecycle classification (open / short-lived /
/// coverage-gap) so the Action view's "proposed cuts" section can tag each row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct WouldActProps {
    /// The internet-facing entry that reached the exploitable verdict (untrusted).
    pub entry: String,
    /// How many would-act episodes occurred (breach-condition recurrences).
    pub episodes: usize,
    /// How many breach decisions affirmed exploitability.
    pub would_act_decisions: usize,
    /// The longest projected would-be cut lifetime, human-formatted (`"4m"`, `"2h"`).
    pub max_lifetime: String,
    /// The longest episode is still OPEN — the cut would still be standing now.
    pub open: bool,
    /// Lifted within the threshold ⇒ likely false positive.
    pub short_lived: bool,
    /// Affirmed exploitability with NO CVE/behavioral backing — scrutinize first.
    pub coverage_gap: bool,
    /// The model's verdict for the most recent would-act episode (untrusted prose).
    pub last_verdict: String,
}

/// One proven path the model deliberately CLEARED — the trust half of the diff.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct LeftAloneProps {
    /// The internet-facing entry whose latest verdict cleared it (untrusted).
    pub entry: String,
    /// The model's clearing verdict (untrusted prose).
    pub verdict: String,
}

/// One self-reverted cut for the Action view's "proposed cuts" section — a cut that was applied
/// then self-reverted when the breach condition lifted (the safety story, kept visible). It is the
/// REVERTED end of the proposed-cut lifecycle (was-cut → self-reverted).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ReversionProps {
    /// The cut signature that was lifted (untrusted node keys).
    pub cut: String,
    /// Why it was lifted (untrusted prose).
    pub reason: String,
    /// How long ago it was lifted, human-formatted (`"90s"`, `"4m"`).
    pub age: String,
}

/// One judgement for the Action view's judgement-audit section — the verbatim prompt/reply behind a
/// model call, for debugging. Mirrors `JudgementProps` but carries the entry it judged.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct JudgementEntryProps {
    /// The internet-facing entry that was judged (untrusted).
    pub entry: String,
    /// How many objectives the entry reaches (the breadth the model weighed).
    pub objectives: usize,
    /// The final verdict (Debug form), if recorded.
    pub verdict: Option<String>,
    /// The full prompt the model saw. `None` ⇒ the deterministic pre-filter decided.
    pub prompt: Option<String>,
    /// The model's raw reply. `None` ⇒ the model was unavailable (timeout).
    pub reply: Option<String>,
}

/// The whole **Action** view's props (brief §4/§6) — the merged Trust + Activity story, laid out in
/// LIFECYCLE order:
///
/// 1. **Proposed cuts** — the would-act proposals ([`would_act`](Self::would_act), still standing,
///    each classified open / short-lived / coverage-gap) PLUS the cuts that were applied then
///    self-reverted ([`reversions`](Self::reversions) — the reverted tail of the lifecycle).
/// 2. **Left alone (cleared)** — proven paths the model cleared ([`left_alone`](Self::left_alone)),
///    the trust half.
/// 3. **Judgement audit** — the verbatim prompt/reply ring ([`judgements`](Self::judgements)).
///
/// Honest empties are preserved: [`journal_empty`](Self::journal_empty) (no journal history) is
/// distinct from "none in this window"; an empty reversion/judgement set renders its own explicit
/// "none yet" line, never a blank.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ActionViewProps {
    pub strip: StatusStripProps,
    /// The rolling window the would-act report aggregates over, human-formatted (`"7d"`).
    pub window_human: String,
    /// The journal held NO breach decisions at all (durable history empty) — distinct from
    /// "decisions, but none in this window".
    pub journal_empty: bool,
    /// How many breach decisions fell within the window (the raw material).
    pub decisions_in_window: usize,
    /// Still-standing proposed cuts the engine would have made, most-sustained first.
    pub would_act: Vec<WouldActProps>,
    /// Cuts that were applied then self-reverted, newest-first (the reverted tail of the lifecycle).
    pub reversions: Vec<ReversionProps>,
    /// Proven paths the model cleared and left alone.
    pub left_alone: Vec<LeftAloneProps>,
    /// The judgement ring, newest-first (the model-debug audit).
    pub judgements: Vec<JudgementEntryProps>,
    /// Headline: distinct workloads that would have been cut.
    pub would_act_count: usize,
    /// Headline: would-acts flagged short-lived (the likely-FP subset).
    pub short_lived_count: usize,
    /// Headline: would-acts that fired during a coverage gap (scrutinize first).
    pub coverage_gap_count: usize,
    /// Headline: distinct proven-but-cleared paths.
    pub left_alone_count: usize,
    /// Headline: cuts that were applied then self-reverted (the reverted count).
    pub reverted_count: usize,
}
