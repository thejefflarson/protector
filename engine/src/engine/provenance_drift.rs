//! The pure, deterministic build-**provenance drift** classifier (JEF-275, ADR-0020 §5).
//!
//! This is the provenance twin of [`signing_drift`](super::signing_drift): observation (JEF-275)
//! reads a *snapshot* — "this image was built by X from Y right now"; the baseline (JEF-263,
//! extended by JEF-275) remembers a repo's learned provenance identity — the source repos + builder
//! identities seen in VERIFIED attestations under it. This module joins the two: it classifies a
//! **fresh provenance posture** against a repo's **learned provenance baseline** into one of three
//! resting classes, so the sweep can surface a **provenance-change** finding when an established
//! repo's build source or builder deviates — the "built by an unexpected workflow / from an
//! unexpected source" supply-chain signal.
//!
//! ## Purity
//!
//! [`classify`] is a total, side-effect-free function of `(baseline, posture)`: no clock, no I/O.
//! The wall-clock "established" notion is already baked into the shared
//! [`SigningBaseline::established`](crate::engine::state::SigningBaseline) flag; the classifier just
//! reads it — so the same `(baseline, posture)` always yields the same class.
//!
//! ## Rules (audit-only; never a gate)
//!
//! Against a repo's baseline (the entry BEFORE this observation is folded in):
//!   * **verified** provenance whose source repo AND builder are BOTH already known ⇒
//!     [`Continuous`] (a normal rebuild — no finding).
//!   * **verified** provenance against a baseline that has NO provenance identity yet ⇒
//!     [`NewProvenance`] (cold-start TOFU; the caller learns it) — never a finding.
//!   * **verified** provenance whose source repo OR builder is NOT in the baseline ⇒ [`Change`] —
//!     the provenance-change regression (built by an unexpected workflow / from an unexpected
//!     source). Carries `established` (from the baseline): an established-baseline change is a
//!     strong signal; a cold one is a weak lead.
//!   * **absent** / **unverifiable** / **checking** ⇒ [`Continuous`]. SECURITY-CRITICAL: absent
//!     provenance is CALM — it is the common case today and is NEVER a regression (an image simply
//!     carries no provenance yet). It is never read as trusted either; that is the posture's job,
//!     not drift's.
//!
//! With NO baseline at all (a repo with no learned signing history — provenance is augment-only, so
//! it cannot be learned here) ⇒ [`Continuous`]: there is nothing to anchor a change against. This is
//! the conservative direction (no false alarm on an un-anchored repo).
//!
//! [`Continuous`]: ProvenanceDrift::Continuous
//! [`NewProvenance`]: ProvenanceDrift::NewProvenance
//! [`Change`]: ProvenanceDrift::Change

use crate::engine::state::SigningBaseline;
use crate::policies::signature::ProvenancePosture;

/// The resting drift classification of a fresh [`ProvenancePosture`] against a repo's learned
/// provenance baseline (JEF-275). Total: every `(baseline, posture)` maps to exactly one variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceDrift {
    /// No drift: verified provenance by a known source+builder (a normal rebuild), or a calm
    /// absent/unverifiable/transient state with no established provenance to deviate from. No finding.
    Continuous,
    /// First verified provenance sight for a repo that had none — the cold-start TOFU establishing
    /// point. The caller learns the provenance identity; this is NOT a change and surfaces NO finding.
    NewProvenance,
    /// A provenance change against a repo that already had a learned provenance identity — the
    /// finding this ticket surfaces (audit-only, still admitted). Carries the deviating source +
    /// builder (UNTRUSTED — escape at render) and whether the baseline was `established`.
    Change {
        /// The new source repo the image was built from (UNTRUSTED — escape at render).
        new_source: String,
        /// The new builder identity (SLSA `builder.id`, UNTRUSTED — escape at render).
        new_builder: String,
        /// Whether the deviating baseline had matured (JEF-263). An established change is a strong
        /// supply-chain signal; a cold one is a weak lead ("weak baseline, treat as a lead").
        established: bool,
    },
}

impl ProvenanceDrift {
    /// Whether this drift is a change that should surface a provenance-change finding.
    pub fn is_change(&self) -> bool {
        matches!(self, ProvenanceDrift::Change { .. })
    }
}

/// Classify a fresh provenance `posture` against the repo's learned `baseline` (JEF-275). PURE +
/// deterministic — see the module docs for the full rule table.
///
/// `baseline` MUST be the repo's entry as it stands BEFORE this observation is folded in, so a new
/// source/builder is still visible as *not-yet-in* the learned sets; `None` ⇒ a repo with no signing
/// baseline to anchor against (provenance is augment-only), which is always [`Continuous`].
pub fn classify(
    baseline: Option<&SigningBaseline>,
    posture: &ProvenancePosture,
) -> ProvenanceDrift {
    // Only a verified provenance is a candidate for drift. Absent / unverifiable / checking are
    // calm and never a change — absent provenance in particular is the common case and must read as
    // calm, never an alarm (ADR-0020 §5).
    let Some(provenance) = posture.provenance() else {
        return ProvenanceDrift::Continuous;
    };
    // No baseline to anchor against (provenance is never learned without a signing baseline).
    let Some(baseline) = baseline else {
        return ProvenanceDrift::Continuous;
    };
    if !baseline.has_provenance() {
        // First verified provenance for this repo: cold-start TOFU (the caller learns it).
        return ProvenanceDrift::NewProvenance;
    }
    let source_known = baseline
        .provenance_sources
        .contains(&provenance.source_repo);
    let builder_known = baseline.provenance_builders.contains(&provenance.builder);
    if source_known && builder_known {
        ProvenanceDrift::Continuous
    } else {
        ProvenanceDrift::Change {
            new_source: provenance.source_repo.clone(),
            new_builder: provenance.builder.clone(),
            established: baseline.established,
        }
    }
}

#[cfg(test)]
#[path = "provenance_drift_tests.rs"]
mod tests;
