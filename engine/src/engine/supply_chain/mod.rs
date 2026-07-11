//! Supply-chain trust sweeps (ADR-0020): the per-pass signature / provenance / Rekor /
//! trust-root observation the engine runs over the already-running fleet, gathered behind one
//! module and one facade.
//!
//! The webhook is the admit-time floor; these sweeps cover the *other* half — the workloads
//! already running when protector started, which no admission event will ever replay. Each pass
//! [`run_watch`](crate::engine::run_watch) observes the cluster, then runs this sweep sequence, then
//! reasons. The sequence is a fixed pipeline over ONE snapshot (ADR-0020):
//!
//!   1. [`signing_sweep::sweep`] — observe each running image's signing posture, learn the per-repo
//!      TOFU baseline, and surface signing-regression drift ([`signing_drift`]).
//!   2. [`signing_rekor::reconcile`] — opt-in: corroborate baselines against the public
//!      transparency log and surface registry↔log divergence (OFF ⇒ zero egress).
//!   3. [`provenance_sweep::sweep`] — opt-in: observe each image's SLSA build provenance and fold
//!      the verified provenance identity into the SAME baseline ([`provenance_drift`]).
//!
//! After the sweeps, the freshly-updated baseline is published to the webhook (the engine is the
//! SOLE writer; ADR-0020 Stage 3) and the LIVE signing-trust readiness signals are refreshed —
//! the TUF-root cache age and a fleet-wide unverifiable spike ([`signing_trust`]).
//!
//! [`run_sweeps`] is the single entry point that sequences all of the above; the [`SweepOutcome`]
//! it returns carries the posture map the pass reasons over plus the readiness inputs the caller
//! folds into its findings handle. This is code-motion behind one seam — no sweep is added,
//! dropped, or reordered, and no argument changes.

use std::sync::Arc;

use super::state::{ReadinessConfig, SharedSigningBaseline, SigningBaselineStore};
use super::{journal, policy_log};
use crate::policies::signature::{
    ProvenanceScanner, RekorLane, SigningExceptions, SigningObserver, SigningPosture,
};

// The per-pass signing-posture sweep (ADR-0020 Stage 1, JEF-261): observes the already-running
// pods' images and records their posture into the shared admission-decision log, complementing the
// webhook's admit-time observation.
pub mod signing_sweep;

// The pure signing-drift classifier (ADR-0020 §3, JEF-264): classifies a fresh posture against the
// repo's learned baseline into continuous / regression / identity-change / new-repo, so the sweep
// can surface an audit-only signing-regression finding on drift from the baseline.
pub mod signing_drift;

// The build-provenance drift classifier + sweep (ADR-0020 §5, JEF-275): the provenance twin of
// signing_drift/signing_sweep — observes each image's SLSA provenance posture, learns the per-repo
// provenance identity (TOFU), and surfaces an audit-only provenance-change finding when an
// established repo is built by an unexpected builder/source. OFF by default — zero extra egress.
pub mod provenance_drift;
pub mod provenance_sweep;

// TUF trust-root freshness + fleet-wide unverifiable-spike signals (ADR-0020 §5, JEF-280): a stale
// or starved trust root turns genuine signatures into `UnverifiableHere` and can mass-blind signing
// detection, so its cache age + a fleet-wide unverifiable spike are surfaced (non-green) in
// readiness. Pure/deterministic signals; never a gate.
pub mod signing_trust;

// The per-repo signing-baseline strength row (ADR-0020 §4, JEF-266): surfaces whether a repo's
// baseline is log-corroborated (Rekor vouches for it) or local-only (weaker TOFU) in the inventory.
pub mod signing_baseline_strength;

// The opt-in Rekor transparency-log lane (ADR-0020 §4, JEF-266): after the sweep observes each
// image, corroborates the repo baseline against the public signing history (marking it stronger
// than local-only TOFU) and surfaces registry↔log divergence as a finding. OFF by default — zero
// egress preserved unless the operator enables it.
pub mod signing_rekor;

/// The wired-in supply-chain observers for a `run_watch` loop, built ONCE at loop start so each
/// one's TTL + image/query cache persists across passes (a steady cluster re-sweeps for free). Any
/// field may be `None`: a missing signing observer (misconfigured TUF cache) degrades to a no-op
/// sweep, and the Rekor lane / provenance scanner are opt-in and absent by default (zero egress).
pub struct SupplyChainSweeps<'a> {
    /// Signing-posture observer (ADR-0020 Stage 1). `None` ⇒ the signing sweep is a no-op.
    pub signing_observer: Option<&'a SigningObserver>,
    /// Opt-in Rekor transparency-log lane (ADR-0020 §4). `None` ⇒ reconcile is a no-op (zero egress).
    pub rekor_lane: Option<&'a RekorLane>,
    /// Opt-in build-provenance scanner (ADR-0020 §5). `None` ⇒ the provenance sweep is a no-op.
    pub provenance_scanner: Option<&'a ProvenanceScanner>,
    /// The scoped "exception accepted" config, read by the signing sweep's render.
    pub exceptions: &'a SigningExceptions,
    /// The sigstore TUF trust-root cache dir, whose freshness is a readiness signal.
    pub tuf_cache_dir: &'a std::path::Path,
}

/// Run the full supply-chain sweep sequence over one observed snapshot, in the SAME order with the
/// SAME arguments the watch loop drove inline before JEF-369 — a behavior-neutral relocation of the
/// call sequence behind one entry point.
///
/// In order: observe signing posture ([`signing_sweep::sweep`]) → opt-in Rekor reconciliation
/// ([`signing_rekor::reconcile`]) → opt-in provenance observation ([`provenance_sweep::sweep`]).
/// Then publishes the freshly-updated baseline to the webhook (the engine is the SOLE writer;
/// JEF-265) — done after ALL baseline-mutating sweeps so the webhook always sees a consistent,
/// whole-pass snapshot — and refreshes the LIVE signing-trust readiness signals ([`signing_trust`])
/// off the resulting posture map, preserving the boot-captured static coverage fields.
///
/// Returns the refreshed [`ReadinessConfig`] the caller hands straight back to
/// `findings().set_readiness_config` — its TUF cache age, unverifiable spike, and checking-image
/// count updated from this pass; the boot-captured static coverage fields carried through untouched.
/// `baselines` is mutated in place (the durable TOFU store) and `readiness` is the current config to
/// refresh the three live fields on.
#[allow(clippy::too_many_arguments)]
pub async fn run_sweeps(
    sweeps: &SupplyChainSweeps<'_>,
    snapshot: &super::observe::Snapshot,
    log: &Arc<policy_log::PolicyDecisionLog>,
    baselines: &mut SigningBaselineStore,
    journal: &Arc<journal::DecisionJournal>,
    shared_baseline: &SharedSigningBaseline,
    readiness: ReadinessConfig,
) -> ReadinessConfig {
    // Observe the signing posture of every already-running image and record it into the shared
    // admission-decision log (JEF-261). Bounded by the observer's cache + MAX_IMAGES; a no-op when
    // no observer is configured. Run before `process` so the inventory reflects the same snapshot
    // the engine just reasoned over.
    let signing_map = signing_sweep::sweep(
        sweeps.signing_observer,
        snapshot,
        log,
        Some(baselines),
        journal.as_ref(),
        sweeps.exceptions,
    )
    .await;
    // Opt-in Rekor reconciliation (JEF-266): corroborate baselines against the public log and
    // surface registry↔log divergence. A no-op (zero egress) when the lane is off.
    signing_rekor::reconcile(
        sweeps.rekor_lane,
        &signing_map,
        log,
        Some(baselines),
        journal.as_ref(),
    )
    .await;
    // Observe each running image's SLSA build provenance (JEF-275, ADR-0020 §5) and fold the
    // verified provenance identity into the SAME per-repo baseline. A no-op (zero extra egress)
    // when the scanner is off. Runs AFTER the signing sweep so the baseline it augments already
    // exists (provenance is augment-only).
    provenance_sweep::sweep(
        sweeps.provenance_scanner,
        snapshot,
        log,
        Some(baselines),
        journal.as_ref(),
    )
    .await;

    // Publish the freshly-updated baseline snapshot for the admission webhook (JEF-265). The engine
    // is the SOLE writer; this is the ONLY path baselines reach the webhook, and it is read-only
    // there — so admission can consult signature continuity without ever being able to teach
    // (poison) it. Done after ALL baseline-mutating sweeps this pass so the webhook always sees a
    // consistent, whole-pass snapshot.
    shared_baseline.publish(baselines);

    // Refresh the LIVE signing-trust readiness signals (JEF-280): the TUF-root cache age (it ages
    // between passes, and a successful verify this pass may have just refreshed it) and a fleet-wide
    // spike in `UnverifiableHere` postures (a hint the trust root drifted or is being starved). Only
    // the three live fields are updated; the boot-captured static coverage fields are preserved. A
    // no-op read on a clean fleet.
    let mut readiness = readiness;
    let mut total = 0usize;
    let mut unverifiable = 0usize;
    for (_, posture) in signing_map.entries() {
        if posture.is_resting() {
            total += 1;
            if matches!(posture, SigningPosture::UnverifiableHere) {
                unverifiable += 1;
            }
        }
    }
    readiness.tuf_cache_age_secs =
        signing_trust::tuf_cache_age_secs(sweeps.tuf_cache_dir, std::time::SystemTime::now());
    readiness.unverifiable_spike = signing_trust::is_unverifiable_spike(unverifiable, total);
    // How many images this sweep couldn't resolve (JEF-326): stuck in the transient `Checking`
    // state, so their posture is unknown — surfaced non-green in readiness.
    readiness.checking_images = signing_map.summary().checking;

    readiness
}
