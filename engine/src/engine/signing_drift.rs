//! The pure, deterministic signing-**drift** classifier (JEF-264, ADR-0020 §3).
//!
//! Observation (JEF-261) reads a *snapshot* — "this image is signed by X right now". The
//! baseline (JEF-263) remembers a repo's signed *history* — who has signed under it, and whether
//! that history has matured (`established`). This module joins the two: it classifies a **fresh
//! posture** against a repo's **learned baseline** into one of four resting drift classes, so the
//! sweep can surface a signing-**regression** finding when a repo with signed history suddenly
//! ships unsigned/invalid, or is signed by a *new* identity — the push-access-compromise signal.
//!
//! ## Purity
//!
//! [`classify`] is a total, side-effect-free function of `(baseline, posture)`: no clock, no I/O,
//! no hidden state. The wall-clock notion of "established" is already baked into the baseline's
//! [`SigningBaseline::established`](crate::engine::state::SigningBaseline) flag (JEF-263), so the
//! classifier just *reads* it — the same `(baseline, posture)` always yields the same class,
//! which is what makes the classifier exhaustively unit-testable.
//!
//! ## Scope (JEF-264)
//!
//! Classification only. Recording the regression onto the admission-decision log, rendering it,
//! and feeding the status-strip honesty model are the sweep / view_model's job (they consume this
//! enum). Enforcement/blocking (JEF-265) and Rekor history (JEF-266) are later stages — a drift is
//! **audit-only**: it is surfaced, never acted on (the shadow invariant, ADR-0016).
//!
//! ## Rules (audit-only; never a gate)
//!
//! Against a repo's baseline (the entry BEFORE this observation is folded in):
//!   * signed by a **known** identity — even a brand-new digest — ⇒ [`Continuous`] (no finding: a
//!     normal deploy must never false-positive).
//!   * signed by an identity **not** in the baseline ⇒ [`Regression`] with
//!     [`IdentityChange`](RegressionKind::IdentityChange).
//!   * now **unsigned** / **invalid** ⇒ [`Regression`] with
//!     [`Unsigned`](RegressionKind::Unsigned) / [`Invalid`](RegressionKind::Invalid).
//!   * a transient [`Checking`](SigningPosture::Checking) ⇒ [`Continuous`] (a registry blip is
//!     never a regression; it resolves next pass).
//!
//! With NO baseline (a never-seen repo):
//!   * a first **signed** sight ⇒ [`NewRepo`] (cold-start TOFU; the caller records the baseline) —
//!     never a regression.
//!   * anything else ⇒ [`Continuous`] (there is no signed history to regress against).
//!
//! Every [`Regression`] carries `established` (from the baseline): an established-baseline
//! regression is a strong signal; a cold/freshly-learned one is a weak lead. The distinction is
//! honest — the first observation of a repo is the *weakest* evidence — and drives the reduced
//! intensity ("weak baseline — treat as a lead") the view surfaces.
//!
//! [`Continuous`]: SigningDrift::Continuous
//! [`NewRepo`]: SigningDrift::NewRepo
//! [`Regression`]: SigningDrift::Regression

use crate::engine::state::SigningBaseline;
use crate::policies::signature::SigningPosture;

/// Which kind of regression a fresh posture represents against a repo's baseline (JEF-264). The
/// identity strings are UNTRUSTED Fulcio cert text — every consumer MUST escape them at render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegressionKind {
    /// A repo with signed history now serves an **unsigned** image.
    Unsigned,
    /// A repo with signed history now serves an image whose signature does **not** verify.
    Invalid,
    /// A repo is now signed by an identity **never before seen** under it — a new signer. Carries
    /// the new identity + issuer (UNTRUSTED) so the finding can state before→after in full.
    IdentityChange {
        /// The new signer identity from the Fulcio cert SAN (UNTRUSTED — escape at render).
        new_identity: String,
        /// The new signer's OIDC issuer, if the cert carried one (UNTRUSTED — escape at render).
        new_issuer: Option<String>,
    },
}

impl RegressionKind {
    /// A stable, low-cardinality word for the regression kind — for the recorded row's status
    /// column and metrics. NOT the identity (that is untrusted text carried separately).
    pub fn word(&self) -> &'static str {
        match self {
            RegressionKind::Unsigned => "unsigned",
            RegressionKind::Invalid => "invalid",
            RegressionKind::IdentityChange { .. } => "identity",
        }
    }
}

/// The resting drift classification of a fresh [`SigningPosture`] against a repo's learned
/// [`SigningBaseline`] (JEF-264). Total: every `(baseline, posture)` maps to exactly one variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningDrift {
    /// No drift: signed by a known identity (a normal redeploy, even to a new digest), or a
    /// transient/unknown state with no signed history to regress against. Surfaces NO finding.
    Continuous,
    /// First observation of a never-seen repo signed — the cold-start TOFU establishing point. The
    /// caller records the baseline; this is NOT a regression and surfaces NO finding.
    NewRepo,
    /// A regression against a repo that already had signed history — the finding this ticket
    /// surfaces (audit-only, still admitted). Carries the kind + whether the baseline was
    /// `established` (a strong signal) or cold/freshly-learned (a weak lead).
    Regression {
        /// What regressed (unsigned / invalid / new signer).
        kind: RegressionKind,
        /// Whether the regressed baseline had matured past the TOFU grace window (JEF-263). An
        /// established regression is a strong supply-chain signal (maps to breach); a cold one is
        /// a weak lead (maps to uncertain — "weak baseline, treat as a lead").
        established: bool,
    },
}

impl SigningDrift {
    /// Whether this drift is a regression that should surface a signing-regression finding.
    /// [`Continuous`](Self::Continuous)/[`NewRepo`](Self::NewRepo) never do.
    pub fn is_regression(&self) -> bool {
        matches!(self, SigningDrift::Regression { .. })
    }
}

/// Classify a fresh signing `posture` against the repo's learned `baseline` (JEF-264). PURE +
/// deterministic — see the module docs for the full rule table.
///
/// `baseline` MUST be the repo's entry as it stands BEFORE this observation is folded in, so a new
/// signer is still visible as *not-yet-in* the identity set; `None` ⇒ a never-seen repo.
pub fn classify(baseline: Option<&SigningBaseline>, posture: &SigningPosture) -> SigningDrift {
    let Some(baseline) = baseline else {
        // No prior history. A first signed sight is the TOFU cold start (the caller records the
        // baseline); any other posture has nothing to regress against.
        return match posture {
            SigningPosture::Signed(_) => SigningDrift::NewRepo,
            _ => SigningDrift::Continuous,
        };
    };

    match posture {
        // A transient blip is never a regression — it resolves into a resting posture next pass.
        SigningPosture::Checking => SigningDrift::Continuous,
        SigningPosture::Signed(signer) => {
            if baseline.identities.contains(&signer.identity) {
                // A known signer — a normal redeploy, even to a brand-new digest. No finding.
                SigningDrift::Continuous
            } else {
                SigningDrift::Regression {
                    kind: RegressionKind::IdentityChange {
                        new_identity: signer.identity.clone(),
                        new_issuer: signer.issuer.clone(),
                    },
                    established: baseline.established,
                }
            }
        }
        SigningPosture::NotSigned => SigningDrift::Regression {
            kind: RegressionKind::Unsigned,
            established: baseline.established,
        },
        SigningPosture::InvalidSignature => SigningDrift::Regression {
            kind: RegressionKind::Invalid,
            established: baseline.established,
        },
    }
}

#[cfg(test)]
#[path = "signing_drift_tests.rs"]
mod tests;
