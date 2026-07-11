//! The opt-in Rekor transparency-log reconciliation pass (JEF-266, ADR-0020 §4).
//!
//! Runs AFTER the signing sweep (JEF-261) has observed each running image's posture and learned the
//! local per-repo TOFU baseline (JEF-263). For each observed image it consults the public
//! transparency log (via the bounded, cached [`RekorLane`]) and does two things the local model
//! cannot:
//!
//!   1. **History bootstrap / strength.** A `Signed` image the log already carries an entry for
//!      means the repo has *real public provenance*, not just what we happened to observe first
//!      locally — so the repo's baseline is marked **log-corroborated** (a stronger baseline than
//!      local-only TOFU). This is the direct fix for the cold-start weakness ADR-0020 names.
//!   2. **Registry↔log divergence.** A signature the registry serves but the log has no entry for
//!      (`RegistrySignedNotInLog`) — or the reverse, the log holds a signing entry for an image the
//!      registry serves unsigned (`LogSignedRegistryUnsigned`) — is tampering neither source
//!      reveals alone. It is surfaced as a **divergence finding through JEF-264's regression
//!      channel** (a `SigningRegression/<repo>` row, distinct reason "registry↔log divergence"),
//!      audit-only (still admitted — the shadow invariant, ADR-0016).
//!
//! ## Egress + degrade posture (the critical invariant)
//!
//! The whole pass is a **no-op when the lane is `None`** (the opt-in switch is off) — zero egress,
//! nothing recorded, the inventory/baseline/local-drift all still work. When enabled it makes ONE
//! bounded outbound query per uncached image. A log that is **unreachable/malformed degrades to
//! local-only**: the [`RekorLane`] returns `Err`, this pass skips that image (no corroboration, no
//! divergence) rather than fabricating a clean or a divergence — never a false clean.
//!
//! [`divergence`] is a pure, total function of `(posture, history)` — exhaustively unit-testable.

use crate::policies::signature::{RekorLane, SigningPosture, repo_key};

use super::signing_baseline_strength::strength_record;
use super::signing_sweep::REGRESSION_SUBJECT_PREFIX;
use crate::engine::journal::DecisionJournal;
use crate::engine::policy_log::{PolicyDecisionLog, PolicyDecisionRecord};
use crate::engine::state::{SigningBaseline, SigningBaselineStore};
use crate::policies::signature::PostureMap;

/// A registry↔log disagreement about an image's signature (JEF-266). The two directions are both
/// tampering signals; each is recorded with a distinct drift token so the render can name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Divergence {
    /// The registry serves a verifying signature the public transparency log has NO entry for.
    /// (A signature that never made it to the append-only log — or a registry-injected one.)
    RegistrySignedNotInLog,
    /// The transparency log holds a signing entry for an image the registry now serves UNSIGNED.
    /// (A signature dropped/stripped at the registry while the log remembers it.)
    LogSignedRegistryUnsigned,
}

impl Divergence {
    /// The direction token embedded in the drift signature (`regression-divergence-<dir>-
    /// <strength>`), parsed back by the inventory render. Low-cardinality, never untrusted text.
    fn dir_token(self) -> &'static str {
        match self {
            Divergence::RegistrySignedNotInLog => "registry",
            Divergence::LogSignedRegistryUnsigned => "log",
        }
    }

    /// The human-facing "after" clause for the finding's reason — the distinct "registry↔log
    /// divergence" prose the ticket calls for.
    fn after_clause(self) -> &'static str {
        match self {
            Divergence::RegistrySignedNotInLog => {
                "registry\u{2194}log divergence: the registry serves a signature the public \
                 transparency log has no entry for"
            }
            Divergence::LogSignedRegistryUnsigned => {
                "registry\u{2194}log divergence: the transparency log records a signature the \
                 registry now serves unsigned"
            }
        }
    }
}

/// Classify a registry↔log disagreement from the local `posture`, the log `history`, and whether
/// the repo is already **log-corroborated** (`repo_corroborated`). PURE + total.
///
///   * `NotSigned` locally but the log HAS an entry for this artifact ⇒
///     [`LogSignedRegistryUnsigned`](Divergence::LogSignedRegistryUnsigned) — the log remembers a
///     signature the registry now serves unsigned. Unambiguous: the log entry for this exact
///     artifact is itself the evidence, so no prior corroboration is needed.
///   * `Signed` locally but NO log entry, **and** the repo is already log-corroborated (we KNOW it
///     signs into the log) ⇒ [`RegistrySignedNotInLog`](Divergence::RegistrySignedNotInLog) — a
///     signature that never reached the append-only log for a repo that always logs.
///   * A `Signed` image with no log entry for a repo we have NOT corroborated is NOT divergence — it
///     is the honest **no-history / local-only fallback** (a key-based or never-logged repo), never
///     a false-positive tampering alarm.
///   * agreement, `Invalid` (already its own signal), or the transient `Checking` ⇒ no divergence.
pub fn divergence(
    posture: &SigningPosture,
    history: &crate::policies::signature::RekorHistory,
    repo_corroborated: bool,
) -> Option<Divergence> {
    match posture {
        SigningPosture::NotSigned if history.signed_in_log => {
            Some(Divergence::LogSignedRegistryUnsigned)
        }
        SigningPosture::Signed(_) if !history.signed_in_log && repo_corroborated => {
            Some(Divergence::RegistrySignedNotInLog)
        }
        _ => None,
    }
}

/// Encode a divergence finding as a `SigningRegression/<repo>` row so it rides JEF-264's regression
/// channel (the inventory partitions it out of the decision tallies and renders the loud banner).
/// The signature token is `regression-divergence-<dir>-<strength>` (dir ∈ registry/log, strength ∈
/// established/cold) — the render parses it back. Decision stays `allow`: audit-only, still
/// admitted (ADR-0016). The baseline signers ("before") are UNTRUSTED Fulcio text, escaped at
/// render.
fn divergence_record(
    repo: &str,
    image: &str,
    div: Divergence,
    baseline: Option<&SigningBaseline>,
) -> PolicyDecisionRecord {
    let established = baseline.map(|b| b.established).unwrap_or(false);
    let strength = if established { "established" } else { "cold" };
    let signature = format!("regression-divergence-{}-{}", div.dir_token(), strength);
    let before = baseline
        .map(|b| b.identities.iter().cloned().collect::<Vec<_>>().join(", "))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let reason = format!("{} | before: {}", div.after_clause(), before);
    PolicyDecisionRecord::now(
        "signing-divergence",
        "allow",
        format!("{REGRESSION_SUBJECT_PREFIX}{repo}"),
        image,
        signature,
        "",
        "",
        reason,
    )
}

/// Reconcile this pass's observed postures against the public transparency log (JEF-266). A no-op
/// (zero egress) when `lane` is `None`. Marks corroborated baselines stronger, persists that change,
/// records the (refreshed) strength row, and surfaces divergence findings. A per-image log error
/// degrades that image to local-only (skipped) — never a false clean.
pub async fn reconcile(
    lane: Option<&RekorLane>,
    map: &PostureMap,
    log: &PolicyDecisionLog,
    store: Option<&mut SigningBaselineStore>,
    journal: &DecisionJournal,
) {
    let Some(lane) = lane else {
        return; // opt-in switch off ⇒ full zero-egress, nothing consulted.
    };
    let Some(store) = store else {
        return; // no durable baseline ⇒ nothing to corroborate; divergence still needs a baseline.
    };

    for (image, posture) in map.entries() {
        let identity = posture.signer().map(|s| s.identity.as_str());
        let history = match lane.lookup(image, identity).await {
            Ok(history) => history,
            Err(error) => {
                // Unreachable / malformed / unqueryable ⇒ degrade to local-only for this image.
                tracing::debug!(%image, %error, "rekor lookup degraded — local-only this pass");
                continue;
            }
        };
        let repo = repo_key(image);

        // History bootstrap: a signed image the log vouches for makes the repo baseline stronger.
        if matches!(posture, SigningPosture::Signed(_))
            && history.signed_in_log
            && store.mark_corroborated(&repo)
        {
            store.persist(journal, &repo);
            if let Some(baseline) = store.get(&repo) {
                log.record(strength_record(&repo, baseline));
            }
        }

        // Divergence: registry and log disagree about this image's signature. The registry-signed
        // direction is gated on the repo already being log-corroborated, so a genuinely
        // no-history (local-only) signed image is a fallback, never a false-positive alarm.
        let baseline = store.get(&repo);
        let corroborated = baseline.map(|b| b.log_corroborated).unwrap_or(false);
        if let Some(div) = divergence(posture, &history, corroborated) {
            log.record(divergence_record(&repo, image, div, baseline));
        }
    }
}

#[cfg(test)]
#[path = "signing_rekor_tests.rs"]
mod tests;
