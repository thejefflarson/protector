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

/// Which top-level tab is active (the 4-tab nav shell).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Findings,
    Trust,
    Readiness,
    Activity,
}

impl Tab {
    /// The tab's route path.
    pub fn path(self) -> &'static str {
        match self {
            Tab::Findings => "/",
            Tab::Trust => "/?tab=trust",
            Tab::Readiness => "/?tab=readiness",
            Tab::Activity => "/?tab=activity",
        }
    }

    /// The tab label.
    pub fn label(self) -> &'static str {
        match self {
            Tab::Findings => "Findings",
            Tab::Trust => "Trust",
            Tab::Readiness => "Readiness",
            Tab::Activity => "Activity",
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
