//! The per-repo signing-baseline **strength** row (JEF-266, ADR-0020 §4 render).
//!
//! The inventory (JEF-262) renders per-image posture rows; this adds the per-repo *strength* of the
//! learned baseline behind them: **log-corroborated** (the public transparency log vouches for the
//! repo's signing history — real provenance) vs **local-only** (trust-on-first-local-sight, the
//! weaker default and the ONLY state when the Rekor lane is off). Encoded as a self-describing
//! `SigningStrength/<repo>` row on the same admission-decision log the sweep already writes, so the
//! view_model reads it with the existing partition/parse machinery and it works with the lane off.

use crate::engine::policy_log::PolicyDecisionRecord;
use crate::engine::state::SigningBaseline;

/// The subject prefix a per-repo baseline-strength row is keyed under (`SigningStrength/<repo>`),
/// one per repo. A signing row (not a webhook decision), so the Admission view_model partitions it
/// out of the admitted/audited/denied tallies exactly like the observation + regression rows.
pub const STRENGTH_SUBJECT_PREFIX: &str = "SigningStrength/";

/// The `signature` word marking a log-corroborated baseline (a stronger baseline than local-only).
pub const CORROBORATED_WORD: &str = "log-corroborated";
/// The `signature` word marking a local-only baseline (weaker TOFU — the lane-off default).
pub const LOCAL_ONLY_WORD: &str = "local-only";

/// Encode a repo's baseline strength as a `SigningStrength/<repo>` row. The `signature` word is the
/// low-cardinality strength token; `reason` carries `first_seen:<ms>` so the render can say "seen
/// signed since …". Decision stays `allow` — this is inventory metadata, never a gate (ADR-0016).
pub fn strength_record(repo: &str, baseline: &SigningBaseline) -> PolicyDecisionRecord {
    let word = if baseline.log_corroborated {
        CORROBORATED_WORD
    } else {
        LOCAL_ONLY_WORD
    };
    PolicyDecisionRecord::now(
        "signing-strength",
        "allow",
        format!("{STRENGTH_SUBJECT_PREFIX}{repo}"),
        repo,
        word,
        "",
        "",
        format!("first_seen:{}", baseline.first_seen_ms),
    )
}
