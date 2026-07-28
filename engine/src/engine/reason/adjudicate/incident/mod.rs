//! The cut-choice contract (ADR-0034): the model NAMES the compromised on-path nodes;
//! determinism resolves each to its narrowest legal cut. This module is the PURE decision
//! machinery only — types, the deterministic menu render + resolver, the tolerant parser,
//! and the grounding guards. No engine wiring: `adj_pass.rs`, `respond::reconcile`, the
//! journal, and the live prompt are untouched here (JEF-570's scope). Every helper this
//! module needs already exists elsewhere in the crate — `respond::containment_for`,
//! `respond::{quarantine_link, quarantine_workload_link}`, `respond::actuator::
//! predict_blast_radius`, and `adjudicate::guards::{guard_fabricated_cve,
//! guard_fabricated_reachability_tag}` — this module resolves + guards, it never
//! reinvents.
//!
//! Split into four cohesive submodules, each under the repo's 1,000-line cap
//! (`CLAUDE.md`), tests in their own `*_tests.rs` files alongside the code they cover:
//! - [`menu`] — the deterministic per-incident containment menu (ADR-0034 D4): one
//!   selectable line per containable on-path workload, plus an aggregate non-selectable
//!   line for evidence-bearing-but-uncontainable nodes.
//! - [`parse`] — the tolerant, skeptic-default parser (ADR-0034 D3): any JSON/shape
//!   failure, or any `contain` element outside the menu's selectable set, degrades the
//!   WHOLE decision to `Uncertain` with no cuts.
//! - [`guards`] — the ADR-0034 D5 grounding guards: per-node containment grounding,
//!   anti-fabrication (CVE id / reachability-tag), and assessment↔cuts consistency. All
//!   admissible under ADR-0029 (grounding/integrity, never a breach-decision override);
//!   all downgrade to `Uncertain`, never `Refuted`, never hide evidence.

use crate::engine::graph::NodeKey;
use crate::engine::respond::ProposedAction;

/// The model's 3-value call on a proven incident (ADR-0034 D1/D2). Collapses the old
/// 4-value [`super::Verdict`]: `Confirmed` vs `Exploitable` encoded a *deterministic* fact
/// (`ProvenChain::corroborated`) into the model's vocabulary — that fact never needed the
/// model to restate it, so fewer output values means fewer temp>0 boundary flips.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assessment {
    /// A real, contextually-exploitable attack. Valid with an EMPTY `cuts` list too
    /// (ADR-0034 D1 — "attack, but no cut warranted"; routes to the human-proposal
    /// fallback).
    Attack,
    /// Not a real/exploitable attack.
    NoAttack,
    /// The model couldn't tell, or a grounding guard downgraded the call — the skeptic
    /// default. Never carries cuts (a fresh `Uncertain` retires nothing and cuts nothing,
    /// ADR-0034 D7).
    Uncertain,
}

/// One cut the engine resolved from a node key the model named in `contain` — **never**
/// carried as model text (ADR-0034 D1): the resolver ([`menu::Menu::resolve`]) looks the
/// node up in the deterministic menu it already built and returns the menu's own
/// (action, signature), so a chosen cut can only ever be one determinism itself computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChosenCut {
    pub node: NodeKey,
    pub action: ProposedAction,
    /// The stable cut identity ([`crate::engine::respond::cut_signature`]) — the ledger's
    /// and journal's key for this cut (ADR-0034 D6/D8, JEF-570).
    pub cut_signature: String,
}

/// The model's decision on one incident (ADR-0034 D1): a 3-value assessment, its
/// one-sentence reason, and the engine-resolved cuts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentDecision {
    pub assessment: Assessment,
    pub reason: String,
    pub cuts: Vec<ChosenCut>,
}

impl IncidentDecision {
    /// The skeptic default: `Uncertain`, no cuts, carrying `reason`. Every degradation
    /// path — an unparseable reply, an out-of-range field, a non-member `contain`
    /// element, an inconsistent assessment↔cuts pairing, or a failed grounding guard —
    /// produces exactly this shape (ADR-0034 D3/D5): never `Refuted`, never a hidden line
    /// of evidence.
    pub fn uncertain(reason: impl Into<String>) -> Self {
        Self {
            assessment: Assessment::Uncertain,
            reason: reason.into(),
            cuts: Vec::new(),
        }
    }
}

mod guards;
mod menu;
mod parse;

pub use guards::{
    guard_assessment_cuts_consistency, guard_containment_grounding, guard_fabrication,
};
pub use menu::{Menu, MenuLine, build_menu};
pub use parse::parse_incident_decision;

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod mod_tests;
