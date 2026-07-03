//! The readiness aggregation (JEF-160): the [`Readiness`] snapshot and its rows, and the
//! pure [`derive_readiness`] that builds them from the engine's config summary + live state.
//!
//! This is data, not markup — it holds no rendering. It is the coverage shape derived from the
//! [`ReadinessConfig`] the engine captures each run (presence/absence of each decision input,
//! the model's last-call health, this pass's behavioral signal volume), so a consumer can report
//! LIVE coverage rather than guessing.

use std::time::SystemTime;

use serde::Serialize;

use super::verdict_store::{BakeStats, ModelHealth, ReadinessConfig};
use crate::engine::signing_trust::TUF_STALE_AFTER_SECS;

/// The LIVE state of one decision input — present, absent, or degraded. Distinct from a
/// config echo: an input is `Absent` only when it is genuinely unconfigured/empty, and
/// `Degraded` when configured but not currently answering (e.g. a model that timed out).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InputState {
    /// Wired and live — contributing to decisions this pass.
    Present,
    /// Not configured (or loaded empty). For an enrichment input this is a coverage gap
    /// that weakens the model's decision (ADR-0016).
    Absent,
    /// Configured but not currently healthy — e.g. the model is attached but its last call
    /// timed out, or signals were expected this pass but none arrived.
    Degraded,
}

/// One readiness row: a decision input, its LIVE state, a one-line "why it matters", the
/// single env var / mount that enables it, and the live detail (a count, "last call ok",
/// "shadow"). `weakens_decisions` is true when this input being absent degrades the model's
/// call (the enrichment inputs of ADR-0016). JSON-serializable so the row is self-contained.
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessRow {
    /// A stable, machine-readable id for the input (`model` / `kev` / `falco` /
    /// `ebpf-agent` / `journal` / `arm-state`).
    pub id: &'static str,
    /// The human label for the input.
    pub label: &'static str,
    /// The LIVE state of this input.
    pub state: InputState,
    /// One-line "why it matters" — what protector loses without this input.
    pub why: &'static str,
    /// The single env var or mount to enable it. Empty for arm-state, which is a posture
    /// toggle, not a missing input.
    pub enable: &'static str,
    /// A short live detail: a count, "last call ok", "shadow mode", etc. — never a value
    /// or secret name.
    pub detail: String,
    /// Whether this input being absent WEAKENS the model's decision (the enrichment /
    /// adjudication inputs — ADR-0016).
    pub weakens_decisions: bool,
}

/// The whole readiness snapshot (JEF-160): every decision input's LIVE state plus the
/// cold-start flag. JSON-serializable. `warming_up` means no pass has completed, so the first
/// verdicts are still loading (expected on a CPU model).
#[derive(Debug, Clone, Serialize)]
pub struct Readiness {
    /// One row per decision input, in a stable, decision-ordered sequence.
    pub inputs: Vec<ReadinessRow>,
    /// No pass has completed yet — the bake window (first verdicts can take minutes on a
    /// CPU model) is still open.
    pub warming_up: bool,
    /// The model is actually answering RIGHT NOW — attached AND its last call was decisive
    /// ([`ModelHealth::Ok`]). False when no model is configured, or it timed out / hasn't
    /// been exercised this run. A calm/green posture is only honest while the model is live;
    /// otherwise exposed paths are unjudged, not cleared (ADR-0016).
    pub model_judging: bool,
}

impl Readiness {
    /// How many enrichment/decision inputs are absent or degraded — the count the
    /// first-run discrimination keys on. Arm-state is posture, not an input gap, so it
    /// never counts here.
    #[allow(dead_code)]
    pub fn unmet_count(&self) -> usize {
        self.inputs
            .iter()
            .filter(|r| r.id != "arm-state" && r.state != InputState::Present)
            .count()
    }

    /// Whether ANY decision input is unmet (absent or degraded) — the first-run gate.
    #[allow(dead_code)]
    pub fn has_unmet(&self) -> bool {
        self.unmet_count() > 0
    }

    /// Whether a model adjudicator is CONFIGURED at all (JEF-255) — the model row is anything
    /// but `Absent`. Distinct from [`model_judging`](Self::model_judging) (configured AND
    /// answering): a consumer needs to tell "no model" from "model down" honestly.
    #[allow(dead_code)]
    pub fn model_attached(&self) -> bool {
        self.inputs
            .iter()
            .find(|r| r.id == "model")
            .is_some_and(|r| r.state != InputState::Absent)
    }
}

/// Derive the readiness snapshot (JEF-160) from the engine's config summary and LIVE
/// state. PURE and total — no model call, no I/O: the model row reads the piggybacked
/// last-adjudication outcome, the behavioral rows read this pass's [`BakeStats`], and the
/// cold-start flag reads `last_pass`. This is the tested core.
#[allow(dead_code)]
pub(crate) fn derive_readiness(
    config: &ReadinessConfig,
    model_health: ModelHealth,
    bake: &BakeStats,
    last_pass: Option<SystemTime>,
) -> Readiness {
    let warming_up = last_pass.is_none();

    // The behavioral split (JEF-48 variant labels): Falco arrives as the `alert` variant;
    // every other variant is an eBPF-agent signal. We report each feed's "signals last
    // pass" from the per-variant counts the bake already holds.
    let falco_signals: u64 = bake.signals_by_variant.get("alert").copied().unwrap_or(0);
    let ebpf_signals: u64 = bake
        .signals_by_variant
        .iter()
        .filter(|(variant, _)| variant.as_str() != "alert")
        .map(|(_, n)| n)
        .sum();

    // The model is "judging" — giving live verdicts a consumer can lean on — only when it
    // is attached AND its last fresh call was decisive. A timeout, a cold start, or no model
    // at all all mean "not judging right now" (JEF-174): the decision still falls through to
    // the deterministic skeptic, but that is not a clearance (ADR-0016).
    let model_judging = config.model_attached && model_health == ModelHealth::Ok;

    // The model row: attached or not, and (if attached) its last-call health. A timeout is
    // Degraded, not Absent — the model IS configured, it just isn't answering right now.
    let (model_state, model_detail) = if !config.model_attached {
        (
            InputState::Absent,
            "no model configured — no exploitability calls are made".to_string(),
        )
    } else {
        match model_health {
            ModelHealth::Ok => (InputState::Present, "attached · last call ok".to_string()),
            ModelHealth::Timeout => (
                InputState::Degraded,
                "attached · last call timed out (CPU model warming or endpoint down)".to_string(),
            ),
            ModelHealth::Unknown => (
                // Attached but not yet exercised: cold start, not a fault. Degraded so a
                // consumer sees "no verdict yet" rather than a false "present".
                InputState::Degraded,
                "attached · no call yet this run (warming up)".to_string(),
            ),
        }
    };

    // A file-backed enrichment store is Present iff it loaded >=1 entry, else Absent.
    let kev_state = present_if(config.kev_count > 0);
    let epss_state = present_if(config.epss_count > 0);

    // A behavioral feed is Present iff it delivered >=1 signal this pass, else Absent. (A
    // genuinely quiet cluster reads as Absent for the pass — the "signals last pass" detail
    // and the cold-start note keep that honest rather than alarming.)
    let falco_state = present_if(falco_signals > 0);
    let ebpf_state = present_if(ebpf_signals > 0);

    let journal_state = present_if(config.journal_durable);

    // The sigstore TUF trust-root freshness (JEF-280): a stale/starved root, or a fleet-wide spike
    // in unverifiable signatures, mass-blinds signing detection — surfaced non-green so it can't
    // read as a silent green.
    let (tuf_state, tuf_detail) = tuf_row(config.tuf_cache_age_secs, config.unverifiable_spike);

    let inputs = vec![
        ReadinessRow {
            id: "model",
            label: "Model adjudicator",
            state: model_state,
            why: "decides whether a proven chain is a real breach — without it, nothing is judged exploitable",
            enable: "PROTECTOR_ENGINE_MODEL",
            detail: model_detail,
            weakens_decisions: true,
        },
        ReadinessRow {
            id: "kev",
            label: "KEV catalogue",
            state: kev_state,
            why: "flags known-exploited CVEs so the model weighs active threats first",
            enable: "PROTECTOR_KEV_FILE",
            detail: coverage_detail(config.kev_count, "known-exploited CVE id"),
            weakens_decisions: true,
        },
        ReadinessRow {
            id: "epss",
            label: "EPSS feed",
            state: epss_state,
            why: "exploit-prediction scores rank which CVEs are most likely to be hit next",
            enable: "PROTECTOR_EPSS_FILE",
            detail: coverage_detail(config.epss_count, "EPSS score"),
            weakens_decisions: true,
        },
        ReadinessRow {
            id: "falco",
            label: "Falco feed",
            state: falco_state,
            why: "live rule-fired alerts confirm a path is being exploited right now",
            enable: "runtime ingest (falcosidekick -> /alert)",
            detail: signals_detail(falco_state, falco_signals),
            weakens_decisions: true,
        },
        ReadinessRow {
            id: "ebpf-agent",
            label: "eBPF agent",
            state: ebpf_state,
            why: "in-kernel behavioral signals (exec, secret reads, connections) show live activity",
            enable: "deploy the agent DaemonSet (-> /behavior)",
            detail: signals_detail(ebpf_state, ebpf_signals),
            weakens_decisions: true,
        },
        ReadinessRow {
            id: "journal",
            label: "Decision journal",
            state: journal_state,
            why: "durable verdicts survive a restart and back the would-have-acted aggregation — without it, history resets",
            enable: "PROTECTOR_ENGINE_JOURNAL_PATH",
            detail: if config.journal_durable {
                "durable volume mounted".to_string()
            } else {
                "in-memory only — resets on restart".to_string()
            },
            weakens_decisions: false,
        },
        ReadinessRow {
            id: "tuf-root",
            label: "Signature trust root",
            state: tuf_state,
            why: "the sigstore TUF root verifies signatures; a stale/starved root turns genuine signatures unverifiable and mass-blinds signing detection",
            enable: "PROTECTOR_TUF_CACHE",
            detail: tuf_detail,
            // Signing-detection trust, not a model-adjudication enrichment input — its absence
            // doesn't weaken the model's exploitability call (ADR-0016), so this stays false.
            weakens_decisions: false,
        },
        ReadinessRow {
            id: "arm-state",
            label: "Arm state",
            // Posture, never a gap: shadow is the safe default. Always Present (the engine
            // is always in one of the two states); the detail says which.
            state: InputState::Present,
            why: "shadow proposes cuts only; enforcing applies the reversible isolation automatically",
            enable: "",
            detail: if config.armed {
                "enforcing (acting)".to_string()
            } else {
                "shadow (proposing only)".to_string()
            },
            weakens_decisions: false,
        },
    ];

    Readiness {
        inputs,
        warming_up,
        model_judging,
    }
}

/// The TUF trust-root readiness row's `(state, detail)` (JEF-280). Honest and non-green whenever
/// the root can't be trusted to catch a downgrade:
///   * no cache fetched yet ⇒ `Absent` (signature verification hasn't populated the root),
///   * cache older than [`TUF_STALE_AFTER_SECS`] ⇒ `Degraded` (stale — refresh may be starved),
///   * a fleet-wide unverifiable spike this pass ⇒ `Degraded` (the root may have drifted), even if
///     the cache mtime still looks fresh,
///   * otherwise ⇒ `Present` (fresh, no spike).
fn tuf_row(age_secs: Option<u64>, spike: bool) -> (InputState, String) {
    match age_secs {
        None => (
            InputState::Absent,
            "no sigstore trust root fetched yet \u{2014} signature verification hasn't populated the cache".to_string(),
        ),
        Some(age) => {
            let stale = age >= TUF_STALE_AFTER_SECS;
            let age_txt = humanize_age(age);
            match (stale, spike) {
                (true, _) => (
                    InputState::Degraded,
                    format!(
                        "trust root cache is {age_txt} old (stale) \u{2014} refresh may be starved; genuine signatures may read unverifiable and blind downgrade detection"
                    ),
                ),
                (false, true) => (
                    InputState::Degraded,
                    format!(
                        "cache {age_txt} old but a fleet-wide spike in unverifiable signatures this pass \u{2014} the trust root may have drifted or is being starved"
                    ),
                ),
                (false, false) => (
                    InputState::Present,
                    format!("trust root cache {age_txt} old (fresh)"),
                ),
            }
        }
    }
}

/// A coarse, human-readable age (`Ns` / `Nm` / `Nh` / `Nd`) for the TUF-root detail line. Whole
/// units only — the row is a freshness hint, not a precise clock.
fn humanize_age(secs: u64) -> String {
    const MIN: u64 = 60;
    const HOUR: u64 = 60 * MIN;
    const DAY: u64 = 24 * HOUR;
    if secs >= DAY {
        format!("{}d", secs / DAY)
    } else if secs >= HOUR {
        format!("{}h", secs / HOUR)
    } else if secs >= MIN {
        format!("{}m", secs / MIN)
    } else {
        format!("{secs}s")
    }
}

/// Present iff the condition holds, else Absent.
fn present_if(present: bool) -> InputState {
    if present {
        InputState::Present
    } else {
        InputState::Absent
    }
}

/// The live detail for a file-backed store: "N records loaded" or the honest absent line.
fn coverage_detail(count: usize, noun: &str) -> String {
    if count == 0 {
        format!("not loaded — no {noun} evidence available")
    } else {
        format!("{count} {noun}{} loaded", if count == 1 { "" } else { "s" })
    }
}

/// The live detail for a behavioral feed: "N signals last pass", or an honest "none this
/// pass" when absent (no sensor reporting, or a quiet cluster).
fn signals_detail(state: InputState, signals: u64) -> String {
    match state {
        InputState::Present => format!(
            "{signals} signal{} last pass",
            if signals == 1 { "" } else { "s" }
        ),
        _ => "no signals last pass (no sensor reporting, or a quiet cluster)".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn covered_config() -> ReadinessConfig {
        ReadinessConfig {
            model_attached: true,
            kev_count: 5,
            epss_count: 5,
            journal_durable: true,
            armed: false,
            // A fresh trust root, no fleet-wide unverifiable spike ⇒ the TUF row is Present.
            tuf_cache_age_secs: Some(60),
            unverifiable_spike: false,
        }
    }

    #[test]
    fn fully_covered_model_judging_has_no_unmet_inputs() {
        let mut bake = BakeStats::default();
        bake.signals_by_variant.insert("alert".into(), 1);
        bake.signals_by_variant.insert("connection".into(), 1);
        let readiness = derive_readiness(
            &covered_config(),
            ModelHealth::Ok,
            &bake,
            Some(SystemTime::now()),
        );
        assert!(readiness.model_judging);
        assert!(readiness.model_attached());
        assert!(!readiness.has_unmet());
        assert_eq!(readiness.unmet_count(), 0);
        assert!(!readiness.warming_up);
    }

    #[test]
    fn a_timed_out_model_is_degraded_not_judging() {
        let readiness = derive_readiness(
            &covered_config(),
            ModelHealth::Timeout,
            &BakeStats::default(),
            Some(SystemTime::now()),
        );
        assert!(!readiness.model_judging);
        // The model is still CONFIGURED — attached, just not answering.
        assert!(readiness.model_attached());
        // The model row is degraded and the (quiet) behavioral feeds are absent ⇒ unmet.
        assert!(readiness.has_unmet());
    }

    /// The TUF-root row from a readiness snapshot.
    fn tuf(readiness: &Readiness) -> &ReadinessRow {
        readiness
            .inputs
            .iter()
            .find(|r| r.id == "tuf-root")
            .expect("a TUF-root row is present")
    }

    #[test]
    fn a_fresh_trust_root_reads_present() {
        let readiness = derive_readiness(
            &covered_config(),
            ModelHealth::Ok,
            &BakeStats::default(),
            Some(SystemTime::now()),
        );
        assert_eq!(tuf(&readiness).state, InputState::Present);
        assert!(tuf(&readiness).detail.contains("fresh"));
    }

    #[test]
    fn a_stale_trust_root_is_degraded_and_surfaced_non_green() {
        let mut config = covered_config();
        config.tuf_cache_age_secs = Some(TUF_STALE_AFTER_SECS + 1);
        let readiness = derive_readiness(
            &config,
            ModelHealth::Ok,
            &BakeStats::default(),
            Some(SystemTime::now()),
        );
        assert_eq!(tuf(&readiness).state, InputState::Degraded);
        assert!(tuf(&readiness).detail.contains("stale"));
        // Non-green: a stale trust root counts as an unmet input.
        assert!(readiness.has_unmet());
    }

    #[test]
    fn a_never_fetched_trust_root_reads_absent() {
        let mut config = covered_config();
        config.tuf_cache_age_secs = None;
        let readiness = derive_readiness(
            &config,
            ModelHealth::Ok,
            &BakeStats::default(),
            Some(SystemTime::now()),
        );
        assert_eq!(tuf(&readiness).state, InputState::Absent);
    }

    #[test]
    fn a_fleet_wide_unverifiable_spike_is_surfaced_even_on_a_fresh_root() {
        let mut config = covered_config();
        config.tuf_cache_age_secs = Some(60); // fresh mtime …
        config.unverifiable_spike = true; // … but a mass unverifiable spike this pass
        let readiness = derive_readiness(
            &config,
            ModelHealth::Ok,
            &BakeStats::default(),
            Some(SystemTime::now()),
        );
        assert_eq!(tuf(&readiness).state, InputState::Degraded);
        assert!(tuf(&readiness).detail.contains("spike"));
        assert!(readiness.has_unmet());
    }

    #[test]
    fn an_unconfigured_model_reads_absent_and_warming_before_first_pass() {
        let readiness = derive_readiness(
            &ReadinessConfig::default(),
            ModelHealth::Unknown,
            &BakeStats::default(),
            None,
        );
        assert!(!readiness.model_attached());
        assert!(!readiness.model_judging);
        assert!(readiness.warming_up);
    }
}
