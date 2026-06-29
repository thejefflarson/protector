//! The plain presentation **Props** the components render (ADR-0019). These types are the
//! contract between the `view_model` (which maps engine/`state::` domain types into them) and
//! the `components` (pure `Props -> Markup` renderers). They carry NO engine/`state::` domain
//! type — only owned strings, numbers, and small presentation enums — so the component layer
//! can be compiled and guard-tested in isolation from the engine (invariant #4 of the brief).
//!
//! Every string here is treated as UNTRUSTED at render: the components escape it (maud
//! auto-escape). The view_model never makes a decision — these props are a view, never a gate
//! (ADR-0016).

/// The model's posture for a finding — the LOUD channel. Mirrors the four states the style
/// guide names (Breach / Cleared / Uncertain / Awaiting), each with a distinct colour token,
/// glyph, and word so meaning never rides on colour alone. `Awaiting` and `Uncertain` are
/// NEVER the cleared/green token — the honesty invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    /// The model affirmed a real, exploitable breach (`Confirmed` / `Exploitable`).
    Breach,
    /// The model judged the path NOT exploitable (`Refuted`).
    Cleared,
    /// The model could not tell (`Uncertain`) — not safe, never green.
    Uncertain,
    /// No verdict yet — the model hasn't judged this entry. Never green.
    Awaiting,
}

impl Posture {
    /// The CSS token suffix (`--posture-{kind}`) for this posture.
    pub fn token(self) -> &'static str {
        match self {
            Posture::Breach => "breach",
            Posture::Cleared => "cleared",
            Posture::Uncertain => "uncertain",
            Posture::Awaiting => "awaiting",
        }
    }

    /// The glyph that carries the posture without colour (style guide §posture).
    pub fn glyph(self) -> &'static str {
        match self {
            Posture::Breach => "\u{25CF}",    // ● filled
            Posture::Cleared => "\u{25CB}",   // ○ open
            Posture::Uncertain => "\u{25D0}", // ◐ half
            Posture::Awaiting => "\u{25CC}",  // ◌ dotted
        }
    }

    /// The word — always present alongside colour + glyph.
    pub fn word(self) -> &'static str {
        match self {
            Posture::Breach => "BREACH",
            Posture::Cleared => "no exploit evidence",
            Posture::Uncertain => "uncertain",
            Posture::Awaiting => "awaiting judgement",
        }
    }

    /// Whether this posture is the cleared/green path. The honesty guard asserts only
    /// `Cleared` is ever true here — `Uncertain`/`Awaiting`/`Breach` are not green.
    pub fn is_cleared(self) -> bool {
        matches!(self, Posture::Cleared)
    }
}

/// A finding's live-vs-judged sub-tag (style guide / brief §10): a live runtime signal backed
/// the chain (`Confirmed` ⇒ **live**) vs a model-only promotion (`Exploitable` ⇒ **judged**).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveTag {
    /// Live-corroborated by a runtime signal.
    Live,
    /// Model-promoted only (no live corroboration).
    Judged,
    /// No sub-tag (not a breach posture).
    None,
}

/// The recency Δ for a finding's entry — the calmer channel. A steady entry shows its AGE,
/// not an alarm glyph (brief §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaProps {
    /// First seen this pass.
    New,
    /// Posture worsened since last pass.
    Escalated,
    /// Posture de-escalated since last pass.
    DeEscalated,
    /// Steady — shows the human age (`"12s"`, `"4m"`), never an arrow. `None` when no age
    /// is known yet.
    Unchanged { age: Option<String> },
    /// Restored from the durable journal on boot.
    Restored,
}

impl DeltaProps {
    /// The CSS token suffix (`--delta-{kind}`), or `None` for the muted steady-age case.
    pub fn token(&self) -> Option<&'static str> {
        match self {
            DeltaProps::New => Some("new"),
            DeltaProps::Escalated => Some("up"),
            DeltaProps::DeEscalated => Some("down"),
            DeltaProps::Restored => Some("restored"),
            DeltaProps::Unchanged { .. } => None,
        }
    }

    /// The glyph + word for the Δ cell (steady age has no glyph).
    pub fn glyph(&self) -> &'static str {
        match self {
            DeltaProps::New => "\u{2605}", // ★ (not "+", which is the row expander)
            DeltaProps::Escalated => "\u{25B2}", // ▲
            DeltaProps::DeEscalated => "\u{25BC}", // ▼
            DeltaProps::Restored => "\u{21BA}", // ↺
            DeltaProps::Unchanged { .. } => "",
        }
    }

    /// A short label for the Δ (for the `title`/screen-reader text).
    pub fn label(&self) -> String {
        match self {
            DeltaProps::New => "new this pass".to_string(),
            DeltaProps::Escalated => "escalated".to_string(),
            DeltaProps::DeEscalated => "de-escalated".to_string(),
            DeltaProps::Restored => "restored".to_string(),
            DeltaProps::Unchanged { age: Some(a) } => format!("steady · {a}"),
            DeltaProps::Unchanged { age: None } => "steady".to_string(),
        }
    }
}

/// One CVE row for the evidence table (subordinate severity channel).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveProps {
    pub id: String,
    /// The severity token suffix (`critical`/`high`/`medium`/`low`).
    pub severity: String,
    /// CVSS score string (`"9.8"`), or `None`.
    pub score: Option<String>,
    pub kev: bool,
    /// EPSS percent string (`"90%"`), or `None`.
    pub epss: Option<String>,
    pub reachability: String,
    pub fix: String,
    /// Untrusted advisory title.
    pub title: Option<String>,
}

/// One scanner finding row (exposed secret / misconfig / RBAC) for the evidence tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanProps {
    pub id: String,
    pub severity: String,
    pub category: Option<String>,
    /// Untrusted title (a redacted secret match, a check description).
    pub title: Option<String>,
}

/// One runtime behavior line for the evidence panel, split corroborating vs context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BehaviorProps {
    /// The behavior's variant token (`alert`/`connection`/…).
    pub variant: String,
    /// The human summary (untrusted — carries peers/paths/secret names).
    pub summary: String,
    /// Whether this behavior corroborates the chain (an alert).
    pub corroborating: bool,
}

/// One hop of the proven path, rendered as a vertical chain diagram (brief §3). Each hop is a
/// `from ─[relation]→ to` edge; the diagram threads the hops top-to-bottom (entry → objective)
/// down a connector spine. Structural hops are muted; the cut point is marked on its edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopProps {
    pub from: String,
    /// The node-kind glyph for `from` (workload ▢ / secret 🔑 / host 🖥 / …; 🌐 for an internet
    /// entry). Carries the node kind without colour (style guide principle 3).
    pub from_glyph: String,
    pub relation: String,
    pub to: String,
    /// The node-kind glyph for `to`.
    pub to_glyph: String,
    /// Whether this is a structural (substrate) hop — rendered muted.
    pub structural: bool,
    /// Whether the proposed cut severs at this hop.
    pub is_cut: bool,
}

/// The verbatim model judgement behind a finding, for the "show model prompt" disclosure.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JudgementProps {
    /// The full prompt the model saw, if captured. `None` ⇒ the deterministic pre-filter
    /// decided without asking the model.
    pub prompt: Option<String>,
    /// The model's raw reply, if any. `None` ⇒ the model was unavailable (timeout).
    pub reply: Option<String>,
    /// The final verdict line (Debug form).
    pub verdict: Option<String>,
}

/// The full evidence cluster for a finding's expanded panel.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EvidenceProps {
    pub cves: Vec<CveProps>,
    /// Runtime behaviors that corroborate (alerts).
    pub corroborating: Vec<BehaviorProps>,
    /// Runtime behaviors carried as context.
    pub context: Vec<BehaviorProps>,
    pub exposed_secrets: Vec<ScanProps>,
    pub misconfigs: Vec<ScanProps>,
    pub rbac_findings: Vec<ScanProps>,
}

impl EvidenceProps {
    /// Whether there is no evidence at all — drives the honest "no evidence" state (never a
    /// blank). Invariant #3.
    pub fn is_empty(&self) -> bool {
        self.cves.is_empty()
            && self.corroborating.is_empty()
            && self.context.is_empty()
            && self.exposed_secrets.is_empty()
            && self.misconfigs.is_empty()
            && self.rbac_findings.is_empty()
    }
}

/// The compact evidence-cluster glyph summary shown in the row (CVE count + KEV + runtime +
/// secrets), or the honest "no evidence" marker.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EvidenceSummary {
    pub cve_count: usize,
    pub kev: bool,
    pub runtime_alerts: usize,
    pub exposed_secrets: usize,
}

impl EvidenceSummary {
    /// Whether the entry has no surfaced evidence — the row shows "no evidence", not a blank.
    pub fn is_empty(&self) -> bool {
        self.cve_count == 0 && !self.kev && self.runtime_alerts == 0 && self.exposed_secrets == 0
    }
}

/// One finding row + its expand-in-place "why" — the unit of the Findings view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingProps {
    /// A stable id for the row toggle (the paired detail row is `detail-{id}`) + deep-link
    /// fragment (derived from the entry key).
    pub id: String,
    pub posture: Posture,
    pub live_tag: LiveTag,
    pub delta: DeltaProps,
    /// The entry node-kind glyph (🌐 for an internet foothold).
    pub entry_glyph: String,
    /// The short entry label (untrusted node key remainder).
    pub entry: String,
    /// Whether the entry is an internet-facing front door.
    pub foothold: bool,
    /// The objective label (untrusted).
    pub objective: String,
    /// The fan-out count when the entry reaches many secrets/objectives (`→ ×N`), else `None`.
    pub fanout: Option<usize>,
    pub evidence_summary: EvidenceSummary,
    /// The mechanical disposition (auto-eligible / propose / durable-fix PR / …).
    pub disposition: String,
    /// The verbatim verdict summary (`Verdict::summary()`), or `None` while awaiting.
    pub verdict_summary: Option<String>,
    pub path: Vec<HopProps>,
    /// The proposed/applied cut signature, if one exists.
    pub cut: Option<String>,
    pub evidence: EvidenceProps,
    pub judgement: JudgementProps,
}

/// The three honesty axes the status strip carries (brief §3): decided/judging/covered. Never
/// collapse into one signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusStripProps {
    /// The cluster label (`prod-east`), untrusted.
    pub cluster: String,
    /// `true` ⇒ enforcing; `false` ⇒ shadow.
    pub armed: bool,
    /// The model is answering RIGHT NOW (attached AND last call decisive). The ONLY condition
    /// under which a calm/green all-clear is honest (invariant #1).
    pub model_judging: bool,
    /// No pass has completed — verdicts are still loading.
    pub warming_up: bool,
    /// Whether a model is configured at all (vs down).
    pub model_attached: bool,
    /// Coverage chips for the enrichment feeds (KEV/EPSS/Falco/eBPF).
    pub coverage: Vec<CoverageChip>,
    /// Human "last pass NNs ago", or `None` before the first pass.
    pub last_pass: Option<String>,
    /// The headline counts (breach / awaiting / uncertain / cleared) for the findings summary
    /// line.
    pub breach_count: usize,
    pub awaiting_count: usize,
    /// Entries the model could not decide (`Verdict::Uncertain`) — not safe, never green.
    pub uncertain_count: usize,
    pub cleared_count: usize,
    /// Newly-escalated since last pass (the Δ headline).
    pub escalated_count: usize,
}

impl StatusStripProps {
    /// Whether the model is up and answering (not warming/blind). This is the floor for a
    /// non-blind render — but it is NOT enough for a green all-clear (see [`Self::all_clear`]).
    pub fn model_is_up(&self) -> bool {
        self.model_judging && !self.warming_up
    }

    /// Whether the engine is **covered** enough to call an all-clear: the model is up and no feed
    /// is *degraded* (configured but not answering — a real, ambiguity-introducing coverage gap).
    /// A feed that is simply absent (never deployed, e.g. the optional eBPF agent) is an honest
    /// known-absence, not a degradation, so it does not by itself block the all-clear.
    pub fn fully_covered(&self) -> bool {
        self.model_is_up() && self.coverage.iter().all(|c| !c.degraded)
    }

    /// Whether the overall **green/all-clear** is HONEST: the model has affirmatively cleared
    /// EVERYTHING it is looking at — judging, not warming, fully covered, and zero breaches AND
    /// zero entries still awaiting AND zero uncertain (the tightened honesty gate, invariant #1).
    /// "Quiet because the model affirmatively cleared it" is the ONLY thing that may go green.
    pub fn all_clear(&self) -> bool {
        self.fully_covered()
            && self.breach_count == 0
            && self.awaiting_count == 0
            && self.uncertain_count == 0
    }

    /// Whether the strip should show the elevated **"watching"** state: the model is up but has
    /// NOT yet affirmatively cleared everything — something is still awaiting or uncertain (or a
    /// feed is missing). Calm, but **not** green — the model isn't sure yet. Distinct from a
    /// breach (which is loud) and from blind/warming (model down).
    pub fn watching(&self) -> bool {
        self.model_is_up() && self.breach_count == 0 && !self.all_clear()
    }
}

/// One coverage chip in the status strip (a feed's presence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageChip {
    pub label: String,
    pub present: bool,
    /// `true` when the feed is degraded (configured but not answering) — distinct from absent.
    pub degraded: bool,
}

/// Which top-level tab is active (the 4-tab nav shell). **Action** sits second (the old Trust
/// slot); it tells the engine's whole action story — proposed cuts, what was left alone, and the
/// judgement audit (it absorbs the former Trust + Activity tabs). Admission is the webhook floor —
/// a peer surface (brief §4), placed last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Findings,
    Action,
    Readiness,
    Admission,
}

impl Tab {
    /// The tab's route path.
    pub fn path(self) -> &'static str {
        match self {
            Tab::Findings => "/",
            Tab::Action => "/?tab=action",
            Tab::Readiness => "/?tab=readiness",
            Tab::Admission => "/?tab=admission",
        }
    }

    /// The tab label.
    pub fn label(self) -> &'static str {
        match self {
            Tab::Findings => "Findings",
            Tab::Action => "Action",
            Tab::Readiness => "Readiness",
            Tab::Admission => "Admission",
        }
    }
}

/// The whole Findings view's props: the status strip + the sorted finding rows + the honest
/// empty/awaiting/blind framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingsViewProps {
    pub strip: StatusStripProps,
    /// Findings, already sorted by URGENCY (not severity) — brief §5.
    pub findings: Vec<FindingProps>,
}

// ---------------------------------------------------------------------------
// Readiness view (brief §6) — one row per decision input, with the honest
// Present/Absent/Degraded state, the live detail, why it matters, and the env
// var to enable it. Rows that weaken decisions when absent float to the top.
// ---------------------------------------------------------------------------

/// The LIVE state of one decision input — the presentation mirror of the engine's
/// `InputState`, carried as colour + glyph + word (never colour alone).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputStateProps {
    /// Wired and live — contributing to decisions this pass.
    Present,
    /// Not configured (or loaded empty) — a coverage gap.
    Absent,
    /// Configured but not currently answering — a real, ambiguity-introducing gap.
    Degraded,
}

impl InputStateProps {
    /// The CSS token suffix (`--cov-{kind}`) for this state.
    pub fn token(self) -> &'static str {
        match self {
            InputStateProps::Present => "present",
            InputStateProps::Absent => "absent",
            InputStateProps::Degraded => "degraded",
        }
    }

    /// The glyph carrying the state without colour.
    pub fn glyph(self) -> &'static str {
        match self {
            InputStateProps::Present => "\u{2713}",  // ✓
            InputStateProps::Absent => "\u{2014}",   // —
            InputStateProps::Degraded => "\u{25D0}", // ◐
        }
    }

    /// The word — always present alongside colour + glyph.
    pub fn word(self) -> &'static str {
        match self {
            InputStateProps::Present => "present",
            InputStateProps::Absent => "absent",
            InputStateProps::Degraded => "degraded",
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessRowProps {
    /// The input's machine id (`model`/`kev`/…) — used as a stable anchor.
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
}

/// The whole Readiness view's props: the persistent strip + the coverage rows, weakening-inputs
/// first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessViewProps {
    pub strip: StatusStripProps,
    /// Coverage rows — weakening-when-absent inputs float to the top (brief §6).
    pub rows: Vec<ReadinessRowProps>,
}

// ---------------------------------------------------------------------------
// Action view (brief §4/§6) — the engine's whole action story in LIFECYCLE order
// (the merged Trust + Activity tabs): PROPOSED CUTS (would-act proposals + their
// self-reverted continuations) → LEFT ALONE (proven paths the model cleared) →
// JUDGEMENT AUDIT (the verbatim prompt/reply ring). Honest empties throughout:
// `journal_empty` distinct from none-in-window; "no cuts reverted yet"; "no
// judgements recorded".
// ---------------------------------------------------------------------------

/// One workload the engine WOULD have isolated in the window — a still-standing proposed cut (the
/// scrutinize side of the diff). Carries its lifecycle classification (open / short-lived /
/// coverage-gap) so the Action view's "proposed cuts" section can tag each row.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftAloneProps {
    /// The internet-facing entry whose latest verdict cleared it (untrusted).
    pub entry: String,
    /// The model's clearing verdict (untrusted prose).
    pub verdict: String,
}

/// One self-reverted cut for the Action view's "proposed cuts" section — a cut that was applied
/// then self-reverted when the breach condition lifted (the safety story, kept visible). It is the
/// REVERTED end of the proposed-cut lifecycle (was-cut → self-reverted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReversionProps {
    /// The cut signature that was lifted (untrusted node keys).
    pub cut: String,
    /// Why it was lifted (untrusted prose).
    pub reason: String,
    /// How long ago it was lifted, human-formatted (`"90s"`, `"4m"`).
    pub age: String,
}

/// One judgement for the Action view's judgement-audit section — the verbatim prompt/reply behind a
/// model call, for debugging. Mirrors [`JudgementProps`] but carries the entry it judged.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

// ---------------------------------------------------------------------------
// Admission/policy view (the webhook floor, brief §6) — the `DecisionTallies`
// header (admitted/audited/denied, so a healthy view is never blank) + deduped
// decision rows (signature/mesh/decision + the "if enforced" what-if).
// ---------------------------------------------------------------------------

/// A per-gate shadow status (JEF-246) for the admission view — the "was this actually checked?"
/// three-state vocabulary from `ShadowVerdict::status()`: `verified` (in scope, checked, passed),
/// `would-pass` (out of scope, shadow-checked, would pass), `would-fail` (would deny if enforced),
/// or `None` when the gate has no opinion (the field was empty). Carried as colour + glyph + word
/// so meaning never rides on colour alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStatus {
    /// In scope, checked, passed.
    Verified,
    /// Out of scope, shadow-checked, would pass if enforced.
    WouldPass,
    /// Would deny if enforced — the attention case.
    WouldFail,
    /// The gate had no opinion (e.g. a non-Pod / out-of-scope object).
    NotApplicable,
}

impl GateStatus {
    /// Parse the engine's coarse shadow status word into the presentation enum. An empty string
    /// (or any unknown legacy word, e.g. the pre-JEF-246 `signed`/`unsigned`) reads as
    /// [`NotApplicable`](Self::NotApplicable) rather than a misleading pass/fail.
    pub fn parse(word: &str) -> GateStatus {
        match word {
            "verified" => GateStatus::Verified,
            "would-pass" => GateStatus::WouldPass,
            "would-fail" => GateStatus::WouldFail,
            _ => GateStatus::NotApplicable,
        }
    }

    /// The CSS token suffix (`--gate-{kind}`) for this status.
    pub fn token(self) -> &'static str {
        match self {
            GateStatus::Verified => "verified",
            GateStatus::WouldPass => "wouldpass",
            GateStatus::WouldFail => "wouldfail",
            GateStatus::NotApplicable => "na",
        }
    }

    /// The glyph carrying the status without colour.
    pub fn glyph(self) -> &'static str {
        match self {
            GateStatus::Verified => "\u{2713}",      // ✓
            GateStatus::WouldPass => "\u{25CB}",     // ○ — would pass (shadow)
            GateStatus::WouldFail => "\u{2715}",     // ✕ — would fail
            GateStatus::NotApplicable => "\u{2014}", // —
        }
    }

    /// The word — always present alongside colour + glyph.
    pub fn word(self) -> &'static str {
        match self {
            GateStatus::Verified => "verified",
            GateStatus::WouldPass => "would-pass",
            GateStatus::WouldFail => "would-fail",
            GateStatus::NotApplicable => "n/a",
        }
    }

    /// Whether this gate would deny if enforced — the attention case the row highlights.
    pub fn is_fail(self) -> bool {
        matches!(self, GateStatus::WouldFail)
    }
}

/// The coarse admission decision the webhook resolved — the honest API verdict (never the
/// counterfactual). `allow` = clean admit, `audit` = would-deny-but-allowed (the discovery
/// signal), `deny` = enforced rejection. An unknown legacy word maps to [`Other`](Self::Other).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// A clean admit.
    Allow,
    /// Would-deny-but-allowed (shadow discovery signal).
    Audit,
    /// An enforced rejection.
    Deny,
    /// An unrecognised legacy decision word.
    Other,
}

impl AdmissionDecision {
    /// Parse the engine's coarse decision word.
    pub fn parse(word: &str) -> AdmissionDecision {
        match word {
            "allow" => AdmissionDecision::Allow,
            "audit" => AdmissionDecision::Audit,
            "deny" => AdmissionDecision::Deny,
            _ => AdmissionDecision::Other,
        }
    }

    /// The CSS token suffix (`--decision-{kind}`).
    pub fn token(self) -> &'static str {
        match self {
            AdmissionDecision::Allow => "allow",
            AdmissionDecision::Audit => "audit",
            AdmissionDecision::Deny => "deny",
            AdmissionDecision::Other => "other",
        }
    }

    /// The glyph carrying the decision without colour.
    pub fn glyph(self) -> &'static str {
        match self {
            AdmissionDecision::Allow => "\u{2713}", // ✓
            AdmissionDecision::Audit => "\u{25D0}", // ◐
            AdmissionDecision::Deny => "\u{25CF}",  // ●
            AdmissionDecision::Other => "\u{2014}", // —
        }
    }

    /// The word — always present alongside colour + glyph.
    pub fn word(self) -> &'static str {
        match self {
            AdmissionDecision::Allow => "admitted",
            AdmissionDecision::Audit => "audited",
            AdmissionDecision::Deny => "denied",
            AdmissionDecision::Other => "other",
        }
    }
}

/// One deduped admission decision row for the Admission view. Plain presentation data only — the
/// engine `PolicyDecisionRecord` is mapped into this at the view_model boundary. Every string is
/// UNTRUSTED at render (the image ref / subject / reason can quote attacker-chosen text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionRowProps {
    /// The coarse decision word (colour + glyph + word).
    pub decision: AdmissionDecision,
    /// The workload subject (`kind/name`), untrusted.
    pub subject: String,
    /// The representative image ref, untrusted. Empty when the decision isn't image-scoped.
    pub image: String,
    /// The request's namespace, untrusted. Empty for a cluster-scoped object.
    pub namespace: String,
    /// The signature gate's shadow status.
    pub signature: GateStatus,
    /// The mesh gate's shadow status.
    pub mesh: GateStatus,
    /// The "if enforced" net counterfactual (JEF-246): would this be admitted if every gate were
    /// enforced? Display-only — the honest API verdict is [`decision`](Self::decision).
    pub would_admit: bool,
    /// The human-actionable reason, untrusted. Empty for a plain admit.
    pub reason: String,
    /// How many times this exact `(subject, image, decision)` was seen (the dedup count).
    pub count: u64,
}

/// The whole Admission/policy view's props (brief §6): the strip + the decision tallies header
/// (so a healthy view is never blank) + the deduped decision rows + the honest-empty framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionViewProps {
    pub strip: StatusStripProps,
    /// Clean admits (`allow`) summed over the deduped rows' counts.
    pub admitted: u64,
    /// Would-deny-but-allowed (`audit`).
    pub audited: u64,
    /// Enforced rejections (`deny`).
    pub denied: u64,
    /// Total decisions across all outcomes — drives the honest-empty state when zero.
    pub total: u64,
    /// The deduped decision rows, newest-first.
    pub rows: Vec<DecisionRowProps>,
}
