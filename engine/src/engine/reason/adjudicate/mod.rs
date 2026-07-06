//! The adjudicator (ADR-0013, refined by JEF-134): proof PROVES + ENRICHES, the
//! model DECIDES breach. Deterministic proof establishes the *facts* — reachability
//! (the proven chain), how each objective is reached (the JEF-79 authorization tags),
//! and the enrichment (CVEs, runtime behavior). The model makes the *breach* call a
//! human analyst would over that whole picture — but it never *runs* an exploit (the
//! named bound: it reasons about exploitability, it does not exercise it).
//!
//! The breach model (the three principles): the deterministic layer proves + enriches
//! only; the model decides breach holistically from the **conjunction** of
//! reachability and evidence. Authorized access (`[RBAC-GRANTED]`/`[MOUNTED]`), however
//! broad or high-severity, is NOT a breach without exploitation evidence; a CVE or
//! behavioral signal on a reachable path is. JEF-134 deliberately removed the
//! deterministic pre-decision (the old "promotion grounds" pre-call filter and the
//! high-severity-tactic / cross-ns backstop) that mis-gated ArgoCD: the engine no
//! longer pre-decides, it hands EVERY breach-relevant entry's proven chain + enrichment
//! to the model.
//!
//! The model judges every breach-relevant chain and the verdict moves in **both**
//! directions:
//! - *veto* — on a live-corroborated chain, `Refuted`/`Uncertain` downgrades an
//!   otherwise auto-eligible cut to a human proposal;
//! - *promote* — on an internet-exposed but uncorroborated chain, an affirmative
//!   `Exploitable` is what makes a cut auto-eligible at all (behind the `judgement`
//!   opt-in); CVE *presence* alone never is.
//!
//! What keeps a miscalibrated model survivable is the architecture around it, not the
//! model's restraint: the only live action is additive, reversible, and self-reverting.
//! So a wrong call costs at most a missed or a transient cut, never an irreversible one.
//! The sole remaining deterministic backstop is anti-fabrication
//! ([`guard_fabricated_cve`]) — it stops the model citing a CVE absent from the
//! evidence; it is NOT a breach-decision gate.
//!
//! The prompt-building and verdict-parsing are pure and tested; the model call is
//! the shared glue in [`crate::engine::model`].

use crate::engine::graph::attack::AttackRef;
use crate::engine::graph::{NodeKey, SecurityGraph};

/// The model's judgement on a proven chain.
///
/// `Serialize`/`Deserialize` (JEF-301) let a DECISIVE verdict be persisted in the durable
/// decision journal and replayed on boot as the EXACT prior decision — an `Exploitable`
/// replays as `Exploitable`, never downgraded — so an unchanged entry is served from the
/// verdict cache without a fresh (slow, OOM-prone) model call after a restart.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Verdict {
    /// A real, contextually-exploitable attack — let the deterministic decision stand.
    Confirmed,
    /// An affirmative positive judgement (ADR-0011): remote exploitation of the
    /// exposed entry plausibly chains to the objective — game over. This is the only
    /// verdict that can *promote* a proven-but-uncorroborated chain to auto-eligible,
    /// so only a real model ever emits it (`NullAdjudicator` never does).
    Exploitable(String),
    /// Not a real/exploitable attack (benign exec, non-exploitable version, mitigated).
    Refuted(String),
    /// The model couldn't tell — treated as a downgrade (skeptic default).
    Uncertain(String),
}

impl Verdict {
    /// Whether the verdict lets an otherwise-eligible auto-action proceed (no veto).
    /// `Refuted`/`Uncertain` demote to a human proposal — the veto direction.
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Verdict::Confirmed | Verdict::Exploitable(_))
    }

    /// Whether the verdict *promotes* a proven-but-uncorroborated chain to
    /// auto-eligible (ADR-0011) — the model's positive judgement. Only `Exploitable`.
    pub fn promotes(&self) -> bool {
        matches!(self, Verdict::Exploitable(_))
    }

    /// A stable, low-cardinality label for metrics (the verdict kind, no free text).
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Confirmed => "confirmed",
            Verdict::Exploitable(_) => "exploitable",
            Verdict::Refuted(_) => "refuted",
            Verdict::Uncertain(_) => "uncertain",
        }
    }

    /// A one-line, human summary of the model's call — kept on the finding so a consumer
    /// can show *both* positive (cut) and negative (don't-cut) decisions
    /// with the model's own reasoning, not just the outcome.
    pub fn summary(&self) -> String {
        match self {
            Verdict::Confirmed => "confirmed (live attack stands)".to_string(),
            Verdict::Exploitable(why) => format!("exploitable — {why}"),
            Verdict::Refuted(why) => format!("not exploitable — {why}"),
            Verdict::Uncertain(why) => format!("uncertain — {why}"),
        }
    }
}

/// Judges a proven chain. Implementations are a model (the real one) or a fixed
/// verdict (the default / tests).
#[async_trait::async_trait]
pub trait Adjudicator: Send + Sync {
    /// Judge ONE internet-facing entry holistically: given everything it can reach
    /// (`objectives`, each with the technique it realizes), is anything a real breach
    /// risk? One call per entry, not per path — the model sees the whole subgraph
    /// anchored at that internet front door at once.
    ///
    /// `prompt` is the ALREADY-BUILT deterministic prompt (JEF-350): the engine builds it
    /// once (before the cache lookup, to derive the cache key from its hash) and hands it in,
    /// so the model call reuses the exact same bytes the cache keyed on rather than rebuilding
    /// it — the cached-on input and the sent input can never drift. `entry`/`objectives`/
    /// `graph` are still supplied for the deterministic backstops and the judgement record.
    async fn judge(
        &self,
        entry: &NodeKey,
        objectives: &[(NodeKey, AttackRef)],
        graph: &SecurityGraph,
        prompt: &str,
    ) -> Verdict;
}

/// The default: confirm everything. Absent a model the deterministic action bar
/// alone governs — behaviour is unchanged, no veto is applied.
pub struct NullAdjudicator;

#[async_trait::async_trait]
impl Adjudicator for NullAdjudicator {
    async fn judge(
        &self,
        _entry: &NodeKey,
        _objectives: &[(NodeKey, AttackRef)],
        _graph: &SecurityGraph,
        _prompt: &str,
    ) -> Verdict {
        Verdict::Confirmed
    }
}

// Cohesive submodules, split out of this file to keep each under the 1,000-line cap
// (repo CLAUDE.md). The public surface (the verdict types, the adjudicators, the
// prompt builder, and the cache/journal helpers the engine + output state import) is
// re-exported here so external paths (`reason::adjudicate::...`) resolve unchanged.
mod evidence;
mod guards;
mod model_call;
mod prompt;

pub use evidence::{EntryCoverage, entry_coverage};
pub use model_call::ModelAdjudicator;
pub use prompt::{build_judgment_prompt, parse_verdict, prompt_cache_key};
// The cross-module helpers the rest of the crate imports by the stable
// `reason::adjudicate::` path (the notify/hypothesis prompt sanitizer). The verdict cache
// keys on `prompt_cache_key` (a hash of the deterministic prompt, JEF-350). The remaining
// submodule helpers are internal to this module and are imported directly from their
// submodule (including by the tests).
pub(crate) use guards::sanitize;

#[cfg(test)]
mod tests;
