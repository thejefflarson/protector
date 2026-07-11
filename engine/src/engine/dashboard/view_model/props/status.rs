//! The persistent status strip props + the top-level tab enum — the honesty spine shown on
//! EVERY view (brief §3): the three honesty axes (decided/judging/covered) plus the headline
//! counts. Split out of the parent `props` module to keep every file under the repo's 1,000-line
//! cap (CLAUDE.md); re-exported flat so `props::StatusStripProps` etc. resolve unchanged.
//!
//! The wire format (ADR-0025): these props are `serde`-serialized as the read-only JSON the
//! client reconciles from. The server-derived honesty tokens ([`StatusStripProps::all_clear`],
//! [`StatusStripProps::watching`]) are computed HERE and shipped as decided values — the client
//! performs ZERO honesty derivation. Every string is UNTRUSTED and ships raw (the render layer
//! escapes; double-escaping is a bug).

/// The three honesty axes the status strip carries (brief §3): decided/judging/covered. Never
/// collapse into one signal.
///
/// The [`serde::Serialize`] impl is HAND-WRITTEN (not derived) so it emits, alongside the raw
/// fields, the SERVER-DERIVED honesty tokens `all-clear` and `watching` computed from
/// [`Self::all_clear`]/[`Self::watching`] — the client performs zero honesty derivation (ADR-0025).
/// Deriving them at serialize time (rather than storing them) makes drift structurally impossible:
/// the wire value IS the derivation, so no constructor can forget to keep them in sync.
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
    /// Coverage chips for the enrichment feeds (KEV/EPSS/runtime corroboration).
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
    /// Standing signing regressions against an ESTABLISHED repo baseline (JEF-264) — a strong
    /// supply-chain signal. Counts toward BREACH for the honesty gate: blocks the green all-clear
    /// AND the calm "watching" reading. Audit-only (never denies); kept SEPARATE from the
    /// reachability [`breach_count`](Self::breach_count) — a signing regression is not a
    /// reachability breach the model can isolate.
    pub signing_regression_breach: usize,
    /// Standing signing regressions against a COLD / freshly-learned baseline (JEF-264) — a weak
    /// lead (the baseline itself is weak evidence). Maps to UNCERTAIN: blocks the green all-clear
    /// but reads as the calmer "watching" register, not a breach.
    pub signing_regression_uncertain: usize,
}

impl serde::Serialize for StatusStripProps {
    /// Serialize the raw fields PLUS the server-derived honesty tokens `all-clear`/`watching`
    /// (ADR-0025). The tokens are computed here from [`Self::all_clear`]/[`Self::watching`] so the
    /// JSON the client consumes always carries the DECIDED honesty answer, never the inputs to
    /// re-derive it — and can never drift from the derivation the maud path uses.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        // 15 raw fields + 2 derived honesty tokens.
        let mut s = serializer.serialize_struct("StatusStripProps", 17)?;
        s.serialize_field("cluster", &self.cluster)?;
        s.serialize_field("armed", &self.armed)?;
        s.serialize_field("model-judging", &self.model_judging)?;
        s.serialize_field("warming-up", &self.warming_up)?;
        s.serialize_field("model-attached", &self.model_attached)?;
        s.serialize_field("coverage", &self.coverage)?;
        s.serialize_field("last-pass", &self.last_pass)?;
        s.serialize_field("breach-count", &self.breach_count)?;
        s.serialize_field("awaiting-count", &self.awaiting_count)?;
        s.serialize_field("uncertain-count", &self.uncertain_count)?;
        s.serialize_field("cleared-count", &self.cleared_count)?;
        s.serialize_field("escalated-count", &self.escalated_count)?;
        s.serialize_field("signing-regression-breach", &self.signing_regression_breach)?;
        s.serialize_field(
            "signing-regression-uncertain",
            &self.signing_regression_uncertain,
        )?;
        // The server-derived honesty tokens — the cardinal ADR-0025 contract.
        s.serialize_field("all-clear", &self.all_clear())?;
        s.serialize_field("watching", &self.watching())?;
        s.end()
    }
}

impl StatusStripProps {
    /// Attach the standing signing-regression counts (JEF-264) — an established-baseline regression
    /// (breach) and a cold-baseline one (uncertain). Builder-style so the strip builders keep their
    /// minimal signatures and the caller with the admission-decision log (`DashboardState`) wires
    /// the counts in. Both feed the honesty gate — a standing regression can never read as green.
    /// The serialized `all-clear`/`watching` tokens are re-derived at serialize time from these
    /// counts (ADR-0025), so wiring them in here is enough to keep the wire honesty honest.
    pub fn with_signing_regressions(mut self, breach: usize, uncertain: usize) -> Self {
        self.signing_regression_breach = breach;
        self.signing_regression_uncertain = uncertain;
        self
    }

    /// Whether any signing regression stands (established or cold) — the honesty side: a standing
    /// regression forbids the green all-clear (JEF-264 acceptance criterion).
    pub fn has_signing_regression(&self) -> bool {
        self.signing_regression_breach > 0 || self.signing_regression_uncertain > 0
    }

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
    /// "Quiet because the model affirmatively cleared it" is the ONLY thing that may go green. This
    /// is the SINGLE derivation the maud render, the tests, AND the serialized `all-clear` token all
    /// read (ADR-0025) — the wire carries this decided answer, never the inputs to re-derive it.
    ///
    /// A standing signing regression (JEF-264) — established OR cold — also forbids green: an
    /// un-accepted regression is an open supply-chain question the model has not cleared.
    pub fn all_clear(&self) -> bool {
        self.fully_covered()
            && self.breach_count == 0
            && self.awaiting_count == 0
            && self.uncertain_count == 0
            && !self.has_signing_regression()
    }

    /// Whether the strip should show the elevated **"watching"** state: the model is up but has
    /// NOT yet affirmatively cleared everything — something is still awaiting or uncertain (or a
    /// feed is missing). Calm, but **not** green — the model isn't sure yet. Distinct from a breach
    /// (which is loud) and from blind/warming (model down). The single derivation the maud render,
    /// the tests, and the serialized `watching` token all read (ADR-0025).
    ///
    /// An ESTABLISHED-baseline signing regression (JEF-264) is louder than watching — it counts
    /// toward breach — so it is excluded here (it falls through to the elevated/loud reading). A
    /// COLD-baseline regression is a weak lead and reads as this calm, non-green watching register.
    pub fn watching(&self) -> bool {
        self.model_is_up()
            && self.breach_count == 0
            && self.signing_regression_breach == 0
            && !self.all_clear()
    }
}

/// One coverage chip in the status strip (a feed's presence).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
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
///
/// Serialized as a STABLE lowercase string tag (`"findings"`, `"alerts"`, …) so the wire format is
/// legible and the client's tab switch is exhaustive over a fixed vocabulary (ADR-0025).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tab {
    Findings,
    /// The live "alarming-now" activity view (JEF-323) — a CURRENT-WINDOW list of the runtime
    /// signals alarming THIS pass, not a persisted audit log. Sits second, next to Findings,
    /// because it is the same live security story from the runtime-activity angle.
    Alerts,
    Action,
    Readiness,
    Admission,
}

impl Tab {
    /// The tab's route path.
    pub fn path(self) -> &'static str {
        match self {
            Tab::Findings => "/",
            Tab::Alerts => "/?tab=alerts",
            Tab::Action => "/?tab=action",
            Tab::Readiness => "/?tab=readiness",
            Tab::Admission => "/?tab=admission",
        }
    }

    /// The tab label.
    pub fn label(self) -> &'static str {
        match self {
            Tab::Findings => "Findings",
            Tab::Alerts => "Alerts",
            Tab::Action => "Action",
            Tab::Readiness => "Readiness",
            Tab::Admission => "Admission",
        }
    }
}
