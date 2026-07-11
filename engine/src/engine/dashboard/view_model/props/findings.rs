//! The Findings-view presentation props — the LOUD channel (per-row posture) plus the evidence
//! cluster, the proven-path staircases, and the verbatim judgement disclosure. Split out of the
//! parent `props` module to keep every file under the repo's 1,000-line cap (CLAUDE.md);
//! re-exported flat so `props::Posture` etc. resolve unchanged.
//!
//! The wire format (ADR-0025): these props `serde`-serialize as the read-only Findings JSON. The
//! per-row [`Posture`] serializes to a STABLE lowercase string tag (`"breach"`) so the client
//! switch is exhaustive and a rename can't silently break it; the honesty token
//! ([`Posture::is_cleared`]) and the row/blind-caveat state are already decided here. Every string
//! is UNTRUSTED and ships RAW (the render layer escapes; double-escaping is a bug).

use super::alerts::AlertProps;
use super::status::StatusStripProps;

/// The model's posture for a finding — the LOUD channel. Mirrors the four states the style
/// guide names (Breach / Cleared / Uncertain / Awaiting), each with a distinct colour token,
/// glyph, and word so meaning never rides on colour alone. `Awaiting` and `Uncertain` are
/// NEVER the cleared/green token — the honesty invariant.
///
/// Serialized as a STABLE lowercase string tag (`"breach"` / `"cleared"` / `"uncertain"` /
/// `"awaiting"`) so the wire format is legible and the client's posture switch is exhaustive — a
/// rename breaks the round-trip test, not the client, silently (ADR-0025).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
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
///
/// Serialized as a STABLE lowercase string tag (`"live"` / `"judged"` / `"none"`) — ADR-0025.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
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
///
/// Serialized as an internally-tagged enum with a STABLE lowercase `kind` tag (`"new"`,
/// `"escalated"`, `"de-escalated"`, `"unchanged"`, `"restored"`) so the client can switch on the
/// tag and the steady case carries its `age` alongside — a legible, exhaustive wire shape
/// (ADR-0025).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ScanProps {
    pub id: String,
    pub severity: String,
    pub category: Option<String>,
    /// Untrusted title (a redacted secret match, a check description).
    pub title: Option<String>,
}

/// One runtime behavior line for the evidence panel, split corroborating vs context.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
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
    /// Whether this edge is SHARED across every proven path to the objective — a common
    /// bottleneck (JEF-281). When several paths share an edge it is a single-edge-cut candidate;
    /// when they share none, no single edge severs the objective. Only meaningful in the
    /// multi-path view; `false` for a lone path. Marked visually so redundancy is legible.
    pub shared: bool,
}

/// The verbatim model judgement behind a finding, for the "show model prompt" disclosure.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
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
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
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
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FindingProps {
    /// A stable id for the row toggle (the paired detail row is `detail-{id}`) + deep-link
    /// fragment (derived from the entry key). Serialized so the client can use it as the keyed
    /// reconcile key (ADR-0025).
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
    /// The replica count when this row REPRESENTS a collapsed workload (N pod replicas of the
    /// same owning controller folded into one row, `×N`), else `None`. Distinct from `fanout`:
    /// fan-out is one entry reaching many objectives; replicas is many pod entries of one
    /// workload folded to one (brief item 5).
    pub replicas: Option<usize>,
    pub evidence_summary: EvidenceSummary,
    /// The mechanical disposition (auto-eligible / propose / durable-fix PR / …).
    pub disposition: String,
    /// The verbatim verdict summary (`Verdict::summary()`), or `None` while awaiting.
    pub verdict_summary: Option<String>,
    /// The REPRESENTATIVE (shortest) proven path — kept for the row's one-line summary.
    pub path: Vec<HopProps>,
    /// EVERY proven path to the objective (bounded, shortest-first), each a hop-list — the
    /// complete reachability picture the finding detail renders as stacked chains (JEF-281).
    /// Edges shared across all paths carry [`HopProps::shared`] so redundancy is visible; when
    /// several redundant paths exist and none is a single cut, that IS the no-cut explanation.
    pub paths: Vec<Vec<HopProps>>,
    /// `true` when more proven paths exist than the bounded set in [`paths`](Self::paths) — the
    /// detail shows a "+N more" note rather than an unbounded wall (JEF-281).
    pub paths_truncated: bool,
    /// The proposed/applied cut signature, if one exists.
    pub cut: Option<String>,
    pub evidence: EvidenceProps,
    pub judgement: JudgementProps,
    /// The blind-node caveat (JEF-308): set when this finding sits on a node with NO live runtime
    /// sensor and its disposition is latent / propose-only (uncorroborated). Its calm propose-only
    /// reading would be dishonest there — absence of a corroborating signal is not evidence of
    /// safety — so the detail renders this caveat. `None` when the node has a live sensor, the
    /// finding is corroborated, or the node isn't known.
    pub blind_node_caveat: Option<String>,
    /// The live "alarming-now" signals observed on this chain's entry THIS pass (JEF-323) — each a
    /// `"drop-and-execute on web (2m ago)"`-style annotation the detail panel renders under
    /// "alarming activity observed". EVIDENCE, not a verdict: an alarming signal never concludes a
    /// breach (ADR-0016), and this is deliberately NOT labelled "corroborated" (the engine reserves
    /// that axis for the Alert-only subset that flips `ProvenChain::corroborated`, ADR-0009; this set
    /// is broader). Empty when nothing is alarming on this chain right now. Every string is UNTRUSTED
    /// (it can carry an attacker-chosen path / rule name) — auto-escaped at render. Projected from the
    /// SAME per-pass runtime signals the Alerts tab reads.
    pub alerts: Vec<AlertProps>,
}

/// The whole Findings view's props: the status strip + the sorted finding rows + the honest
/// empty/awaiting/blind framing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FindingsViewProps {
    pub strip: StatusStripProps,
    /// Findings, already sorted by URGENCY (not severity) — brief §5.
    pub findings: Vec<FindingProps>,
}
