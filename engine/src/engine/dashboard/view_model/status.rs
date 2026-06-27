//! The status / nav view-model (ADR-0019, the DATA layer): pure functions that map the
//! engine's per-pass snapshot (the resolved [`Finding`]s, arm-state, last-pass time, and
//! whether the model is judging) into the plain `Props` the `components::banner` /
//! `components::nav` renderers consume. No maud here, and no presentation markup — only
//! the glanceable cluster verdict and the data the components turn into HTML.

use crate::engine::dashboard::model::Finding;
use crate::engine::dashboard::view_model::findings::flagged;
use std::collections::BTreeSet;
use std::time::SystemTime;

/// The glanceable cluster verdict (JEF-159): the one-word answer the status banner leads
/// with. A pure presentation classification over the snapshot — never a decision gate
/// (ADR-0016), never a model call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterStatus {
    /// `last_pass` is `None` — no pass has completed, so there are no verdicts yet. We
    /// show progress, NOT a blank and NOT a false "OK": a warming cluster is unknown, not
    /// clear.
    WarmingUp,
    /// ≥1 breach-relevant finding the model affirmed exploitable now, AND a cut is in
    /// force for it (armed + an auto-eligible remediation, which renders as "applied").
    /// The breach is real but contained — red border on a calm fill, distinct from a
    /// live, un-cut breach.
    Isolated,
    /// ≥1 breach-relevant finding the model affirmed exploitable now, with no cut in
    /// force. The one red state: a live breach the operator must look at.
    BreachLive,
    /// Exposed breach-relevant endpoints exist and the model is NOT answering (no model
    /// configured, or its last call timed out / hasn't landed this run — JEF-174). Nothing
    /// is flagged, but that is the deterministic skeptic default, NOT a model clearance: the
    /// single most load-bearing input is absent (ADR-0016). Non-green (amber) — these paths
    /// are unjudged, not confirmed safe. Ranked worse than `Watching` (a real clearance).
    Unjudged,
    /// Exposed breach-relevant endpoints exist, the model IS answering, and it cleared them
    /// all (none exploitable). Calm green — actively watched, a live verdict, nothing live.
    Watching,
    /// No breach-relevant exposure at all. Calm green — nothing reaches an objective.
    Quiet,
}

impl ClusterStatus {
    /// The one word the banner leads with — the glanceable answer.
    pub fn word(self) -> &'static str {
        match self {
            ClusterStatus::WarmingUp => "Warming up",
            ClusterStatus::Isolated => "Isolated",
            ClusterStatus::BreachLive => "Breach — live",
            ClusterStatus::Unjudged => "Unjudged",
            ClusterStatus::Watching => "Watching",
            ClusterStatus::Quiet => "Quiet",
        }
    }

    /// A leading glyph so the state is legible without color (accessibility): the meaning
    /// is carried by word + glyph, color only reinforces it.
    pub fn glyph(self) -> &'static str {
        match self {
            ClusterStatus::WarmingUp => "◌",
            ClusterStatus::Isolated => "▣",
            ClusterStatus::BreachLive => "▲",
            ClusterStatus::Unjudged => "◍",
            ClusterStatus::Watching => "●",
            ClusterStatus::Quiet => "●",
        }
    }

    /// The CSS class for the banner's tone — maps to the tokens in `web/dist/dashboard.css`.
    /// `ok` is the new calm/green token (the first "healthy" color); `breach` is the
    /// reserved red; `isolated` is red-border-on-calm; `warming` is muted; `unjudged` is the
    /// amber/degraded token (JEF-174) — explicitly NOT green, because nothing was cleared.
    pub fn tone(self) -> &'static str {
        match self {
            ClusterStatus::WarmingUp => "warming",
            ClusterStatus::Isolated => "isolated",
            ClusterStatus::BreachLive => "breach",
            ClusterStatus::Unjudged => "unjudged",
            ClusterStatus::Watching | ClusterStatus::Quiet => "ok",
        }
    }
}

/// The glanceable cluster status (JEF-159) — a PURE function over the snapshot the
/// dashboard already has: the resolved findings, whether the engine is armed, and the
/// last-pass time. No model call. The verdict is read from each finding's RESOLVED
/// verdict (JEF-157: the snapshot resolves it from the unified per-entry store), and a
/// finding counts as a live breach exactly when [`flagged`] is true for it.
///
/// `model_judging` (JEF-174) is whether the model is actually answering right now. It gates
/// the ONE clearance claim: exposed-but-unflagged paths are `Watching` (a real, green "the
/// model cleared them") only while the model is live; otherwise they are
/// [`Unjudged`](ClusterStatus::Unjudged) — non-green, because "nothing flagged" is the
/// deterministic skeptic default, not a verdict (ADR-0016). It never relaxes a breach
/// state, only withholds a clearance.
pub fn cluster_status(
    findings: &[Finding],
    armed: bool,
    last_pass: Option<SystemTime>,
    model_judging: bool,
) -> ClusterStatus {
    // No pass yet ⇒ no verdicts ⇒ never claim OK (warming, not blank, not clear).
    if last_pass.is_none() {
        return ClusterStatus::WarmingUp;
    }

    let breach = findings.iter().filter(|f| f.breach_relevant);
    let mut exposed = 0usize;
    let mut live_breach = false;
    let mut cut_applied = false;
    for f in breach {
        exposed += 1;
        if flagged(f.verdict.as_deref()) {
            live_breach = true;
            // A cut is in force for a flagged breach only when the engine is armed AND the
            // chain is auto-eligible (it would render "applied", not "would apply").
            if armed && f.disposition == crate::engine::dashboard::model::AUTO_ELIGIBLE {
                cut_applied = true;
            }
        }
    }

    match (live_breach, cut_applied, exposed) {
        (true, true, _) => ClusterStatus::Isolated,
        (true, false, _) => ClusterStatus::BreachLive,
        // No exposure at all ⇒ nothing for the model to clear, so model health is moot:
        // `Quiet` makes no clearance claim ("no exposure reaches an objective") regardless.
        (false, _, 0) => ClusterStatus::Quiet,
        // Exposure exists and nothing is flagged: `Watching` (a green "the model cleared
        // them") is honest ONLY while the model is live. Otherwise the all-clear is just the
        // skeptic default with no model behind it ⇒ `Unjudged`, non-green (JEF-174).
        (false, _, _) if model_judging => ClusterStatus::Watching,
        (false, _, _) => ClusterStatus::Unjudged,
    }
}

/// The plain-data props for the status banner (ADR-0019 view-model). Carries the computed
/// [`ClusterStatus`], the path counts the detail line states, the freshness phrase, and the
/// arm-state — no markup, no engine domain type. The `components::banner` renderer turns
/// this into HTML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BannerProps {
    /// The glanceable verdict — drives the word, glyph, and tone class.
    pub status: ClusterStatus,
    /// Distinct exposed (breach-relevant) endpoints — the count `Watching`/`Unjudged` state.
    pub exposed: usize,
    /// Distinct flagged (model-exploitable) endpoints — the count the breach states name.
    pub flagged: usize,
    /// The "last scan …" freshness phrase (already humanized).
    pub freshness: String,
    /// Whether the engine is armed (acting) vs shadow (proposing only) — the subtitle half.
    pub armed: bool,
}

/// Build the banner props from the per-pass snapshot — the pure mapping from engine state
/// to the data the banner component renders. Mirrors the old `status_banner` inputs.
pub fn banner_props(
    findings: &[Finding],
    armed: bool,
    last_pass: Option<SystemTime>,
    freshness: &str,
    model_judging: bool,
) -> BannerProps {
    let status = cluster_status(findings, armed, last_pass, model_judging);
    let exposed = findings
        .iter()
        .filter(|f| f.breach_relevant)
        .map(|f| f.entry.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let flagged = findings
        .iter()
        .filter(|f| f.breach_relevant && flagged(f.verdict.as_deref()))
        .map(|f| f.entry.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    BannerProps {
        status,
        exposed,
        flagged,
        freshness: freshness.to_string(),
        armed,
    }
}

/// One nav item: the link target, its label, and whether it is the current page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavItem {
    pub href: &'static str,
    pub label: &'static str,
    pub current: bool,
}

/// The plain-data props for the persistent nav (ADR-0019 view-model): the ordered items
/// with the current page marked. No markup; `components::nav` renders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavProps {
    pub items: Vec<NavItem>,
}

/// Build the nav props for the page at `current`. Trimmed to answer-first (JEF-175):
/// dashboard · why · shadow log. `/readiness`, `/bake`, and `/reversions` are de-listed
/// from the nav (their routes stay reachable elsewhere).
pub fn nav_props(current: &str) -> NavProps {
    const LINKS: [(&str, &str); 3] = [
        ("/", "dashboard"),
        ("/judgements", "why"),
        ("/report", "shadow log"),
    ];
    NavProps {
        items: LINKS
            .iter()
            .map(|(href, label)| NavItem {
                href,
                label,
                current: *href == current,
            })
            .collect(),
    }
}
