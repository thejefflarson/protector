//! Per-pass build-provenance sweep (ADR-0020 §5, JEF-275) — the provenance twin of
//! [`signing_sweep`](super::signing_sweep).
//!
//! Where the signing sweep observes *who signed* each running image, this sweep observes *how it was
//! built*: it runs every distinct container image through a bounded, cached
//! [`ProvenanceScanner`] and records the observed [`ProvenancePosture`] (verified / unverifiable /
//! no-provenance / checking) into the SAME [`PolicyDecisionLog`] the signing inventory reads — so
//! the operator sees a provenance column alongside signing posture, across both admitted and
//! pre-existing workloads.
//!
//! The posture is recorded as the low-cardinality status word on a `build-provenance` row keyed
//! `Provenance/<image>`; the source repo + builder identity ride the row's reason (UNTRUSTED
//! predicate text, escaped at render).
//!
//! ## Provenance-change findings (JEF-275, ADR-0020 §5)
//!
//! After recording each posture, the sweep classifies it against the repo's CURRENT provenance
//! baseline (JEF-263, extended by JEF-275) via the pure [`provenance_drift`](super::provenance_drift)
//! classifier and, on a **change** against an established provenance identity (an unexpected builder
//! or source), records a provenance-**change** finding onto the SAME admission-decision log — keyed
//! `ProvenanceChange/<repo>`, decision `allow`. This is **audit-only — still admitted** (the shadow
//! invariant, ADR-0016): the finding is surfaced, never acted on. NO enforcement here.
//!
//! ## Off by default (zero extra egress)
//!
//! The sweep is a no-op unless a [`ProvenanceScanner`] is wired (opt-in via the run-loop's
//! `PROTECTOR_PROVENANCE_ENABLE`, mirroring the Rekor lane), so the default posture adds ZERO
//! outbound calls beyond the existing signing sweep. When on, it reuses the SAME sanctioned
//! registry/sigstore fetch path (ADR-0015), bounded by the scanner's TTL cache + `max_images` cap.

use std::sync::Arc;
use std::time::SystemTime;

use super::journal::DecisionJournal;
use super::observe::Snapshot;
use super::policy_log::{PolicyDecisionLog, PolicyDecisionRecord};
use super::provenance_drift::{ProvenanceDrift, classify};
use super::signing_sweep::snapshot_images;
use super::state::{SigningBaseline, SigningBaselineStore};
use crate::policies::signature::{ProvenanceMap, ProvenancePosture, ProvenanceScanner, repo_key};

/// The subject prefix a per-image provenance observation row is keyed under (`Provenance/<image>`),
/// so it folds one-per-image and is partitioned OUT of the webhook decision tallies by the Admission
/// view_model — a provenance observation is inventory, not an admission decision.
pub const PROVENANCE_SUBJECT_PREFIX: &str = "Provenance/";

/// The subject prefix a provenance-**change** finding is keyed under (`ProvenanceChange/<repo>`), one
/// per repo. Also a signing-inventory row (not a webhook decision), partitioned out of the tallies.
pub const PROVENANCE_CHANGE_SUBJECT_PREFIX: &str = "ProvenanceChange/";

/// The sentinel separating the "after" clause from the baseline "before" builders in a
/// provenance-change row's reason (`<after> | before: <builders>`). Mirrors the signing-regression
/// row shape so the view_model reads it with the same discipline.
const BEFORE_SEP: &str = " | before: ";

/// The human-facing reason text for a recorded provenance posture row. The source repo + builder are
/// UNTRUSTED third-party predicate text — recorded verbatim here and escaped wherever rendered.
/// Empty for a plain `no-provenance`, which needs no prose (calm, like a not-signed image).
fn posture_reason(posture: &ProvenancePosture) -> String {
    match posture {
        ProvenancePosture::Verified(p) => {
            format!("built by {} from {}", p.builder, p.source_repo)
        }
        ProvenancePosture::Unverifiable => {
            "provenance attestation present but not verified against our trust root (or carried no \
             builder identity) \u{2014} not a trusted build"
                .to_string()
        }
        ProvenancePosture::Absent => String::new(),
        ProvenancePosture::Checking => {
            "build provenance not yet known (registry/log unreachable)".to_string()
        }
    }
}

/// Record an observed [`ProvenanceMap`] into the admission-decision log as `build-provenance` rows,
/// keyed (for dedup) by the image ref. The decision word stays `allow` — pure observation, never a
/// gate (ADR-0016); the provenance posture is the security-bearing fact, carried in the `signature`
/// status column (reused generic status field).
fn record_postures(log: &PolicyDecisionLog, map: &ProvenanceMap) {
    for (image, posture) in map.entries() {
        let record = PolicyDecisionRecord::now(
            "build-provenance",
            "allow",
            format!("{PROVENANCE_SUBJECT_PREFIX}{image}"),
            image,
            posture.status(),
            "",
            "",
            posture_reason(posture),
        );
        log.record(record);
    }
}

/// Encode a provenance-change finding as an admission-decision-log row (JEF-275, ADR-0020 §5).
///
/// Routing mirrors the signing-regression row: it rides the SAME admission-decision log, keyed
/// `ProvenanceChange/<repo>` so it folds one-per-repo and the Admission view_model partitions it out
/// of the decision tallies. The decision word stays `allow`: audit-only — still admitted.
///
/// The row is self-describing: `signature` carries `provenance-change-<strength>` (strength ∈
/// established/cold — the render `rsplit`s on the last `-`); `reason` carries `built by <builder>
/// from <source> | before: <builders>` (the deviating identity, then the baseline builders). All
/// identity/source text is UNTRUSTED — carried verbatim, escaped wherever rendered.
fn change_record(
    repo: &str,
    image: &str,
    new_source: &str,
    new_builder: &str,
    established: bool,
    baseline: Option<&SigningBaseline>,
) -> PolicyDecisionRecord {
    let strength = if established { "established" } else { "cold" };
    let signature = format!("provenance-change-{strength}");
    let after_clause = format!("built by {new_builder} from {new_source}");
    let before = baseline
        .map(|b| {
            b.provenance_builders
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let reason = format!("{after_clause}{BEFORE_SEP}{before}");
    PolicyDecisionRecord::now(
        "provenance-change",
        "allow",
        format!("{PROVENANCE_CHANGE_SUBJECT_PREFIX}{repo}"),
        image,
        signature,
        "",
        "",
        reason,
    )
}

/// Classify each observed provenance posture against the repo's CURRENT baseline (JEF-275) and record
/// a provenance-change finding for any change against an established provenance identity. Runs BEFORE
/// [`learn_provenance`] so a new source/builder is still visible as not-yet-in the learned sets. Pure
/// classification + append-only recording — never a gate; the store is read, not mutated.
fn detect_changes(store: &SigningBaselineStore, log: &PolicyDecisionLog, map: &ProvenanceMap) {
    for (image, posture) in map.entries() {
        let repo = repo_key(image);
        let baseline = store.get(&repo);
        if let ProvenanceDrift::Change {
            new_source,
            new_builder,
            established,
        } = classify(baseline, posture)
        {
            log.record(change_record(
                &repo,
                image,
                &new_source,
                &new_builder,
                established,
                baseline,
            ));
        }
    }
}

/// Fold this pass's verified provenance into the durable per-repo baseline (JEF-275), persisting each
/// changed repo's full-state line (which now carries the provenance identity). Augment-only: a repo
/// with no signing baseline learns nothing (the store enforces this), so a signature-only cluster is
/// unaffected. A no-op on a disabled journal / cold store.
fn learn_provenance(
    store: &mut SigningBaselineStore,
    journal: &DecisionJournal,
    map: &ProvenanceMap,
) {
    let now_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    for (image, posture) in map.entries() {
        if let Some(repo) = store.observe_provenance(image, posture, now_ms) {
            // Persist just the changed repo's full-state line (the signing sweep already compacted
            // the whole store this pass, before provenance learning — so append the updated line).
            store.persist(journal, &repo);
        }
    }
}

/// Run one build-provenance sweep over the snapshot's running pods and record the result. A no-op
/// (zero outbound calls, nothing recorded) when no scanner is configured — so a deploy without
/// provenance enabled behaves exactly as before. Bounded by the scanner's `max_images` cap + TTL
/// cache. Returns the [`ProvenanceMap`] observed this pass.
pub async fn sweep(
    scanner: Option<&ProvenanceScanner>,
    snapshot: &Snapshot,
    log: &Arc<PolicyDecisionLog>,
    baseline: Option<&mut SigningBaselineStore>,
    journal: &DecisionJournal,
) -> ProvenanceMap {
    let Some(scanner) = scanner else {
        return ProvenanceMap::new();
    };
    let images = snapshot_images(&snapshot.pods);
    if images.is_empty() {
        return ProvenanceMap::new();
    }
    let map = scanner.sweep(images).await;
    record_postures(log, &map);
    if let Some(store) = baseline {
        // Classify against the baseline as it stands BEFORE this pass's learning, then learn — so a
        // change / new provenance is detected before the observation folds into the baseline.
        detect_changes(store, log, &map);
        learn_provenance(store, journal, &map);
    }
    map
}

#[cfg(test)]
#[path = "provenance_sweep_tests.rs"]
mod tests;
