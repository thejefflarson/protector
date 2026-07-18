//! The readiness aggregation (JEF-160): the [`Readiness`] snapshot and its rows, and the
//! pure [`derive_readiness`] that builds them from the engine's config summary + live state.
//!
//! This is data, not markup — it holds no rendering. It is the coverage shape derived from the
//! [`ReadinessConfig`] the engine captures each run (presence/absence of each decision input,
//! the model's last-call health, this pass's behavioral signal volume), so a consumer can report
//! LIVE coverage rather than guessing.

use std::time::SystemTime;

use serde::Serialize;

use super::agent_liveness::{
    BlindReason, CoverageAlert, CoverageState, NodeState, RuntimeCoverage,
};
use super::verdict_store::{ModelHealth, ReadinessConfig};
use crate::engine::supply_chain::signing_trust::TUF_STALE_AFTER_SECS;

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
    /// EXPECTED but wholly dark — the input IS configured (nodes are expected) and EVERY expected
    /// node is blind this pass. DISTINCT from `Absent` (never enabled — an honest known-absence that
    /// may stay green) and from `Stalled` (the cross-pass was-covering→dark edge): a per-pass "the
    /// sensor fleet exists but has no live signal right now", which must FORBID the green all-clear.
    /// This is the cold-start / crash-loop case the stall edge can't catch (never `was_covering`).
    Blind,
    /// A WAS-COVERING input has STALLED (JEF-421) — it was reporting and has now gone fully dark
    /// (held past the debounce). The loud, cross-pass edge: DISTINCT from `Absent` (never enabled)
    /// and `Degraded` (partial). Applied only to the runtime-corroboration row, and only by the
    /// server-side stall overlay ([`Readiness::with_coverage_stall`]); [`derive_readiness`] never
    /// produces it (per-pass derivation can't see the cross-pass edge).
    Stalled,
}

/// One readiness row: a decision input, its LIVE state, a one-line "why it matters", the
/// single env var / mount that enables it, and the live detail (a count, "last call ok",
/// "shadow"). `weakens_decisions` is true when this input being absent degrades the model's
/// call (the enrichment inputs of ADR-0016). JSON-serializable so the row is self-contained.
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessRow {
    /// A stable, machine-readable id for the input (`model` / `kev` / `epss` /
    /// `runtime-corroboration` / `journal` / `arm-state`).
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
    /// The per-node runtime-corroboration breakdown (JEF-308) — populated ONLY for the
    /// `runtime-corroboration` row, empty for every other input. Rendered as a server-side
    /// `<table>` inside `<details>` (no JS) so an operator can see exactly which node is blind.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<NodeCoverageRow>,
}

/// One node's line in the runtime-corroboration per-node breakdown (JEF-308) — the node name,
/// its honest state, and a short live detail. Node names are UNTRUSTED-adjacent: the render
/// escapes them (maud default), never `PreEscaped`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NodeCoverageRow {
    /// The node name (untrusted-adjacent at render).
    pub node: String,
    /// The node's honest liveness state.
    pub state: NodeCoverageState,
    /// A short live detail — signal count, "quiet", probe fraction, or the blind reason.
    pub detail: String,
}

/// One expected node's honest liveness reading (JEF-308) — the per-node mirror of the coarse
/// [`InputState`], kept distinct so "quiet" and "blind" never collapse into one word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeCoverageState {
    /// Reporting with probes loaded — contributing corroboration (signals may be 0 = quiet).
    Healthy,
    /// Reporting but only some probes attached — partial coverage.
    Degraded,
    /// No live corroboration on this expected node — the agent is down or its probes failed.
    Blind,
    /// A node reporting that the agent isn't scheduled on — out-of-scope, explicitly not blind.
    OutOfScope,
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

    /// Overlay the coverage-stall register (JEF-421) onto the runtime-corroboration row. The stall is
    /// a CROSS-PASS edge (`state::CoverageState`) the per-pass [`derive_readiness`] can't see, so the
    /// caller (`DashboardState::readiness`) folds it in here: when a covering runtime feed has gone
    /// dark past the debounce, the row escalates to [`InputState::Stalled`] and its detail names the
    /// last time the sensors were observed live. Every other register leaves the row untouched — a
    /// never-enabled feed stays honestly `Absent`, a partial one `Degraded`. Builder-style.
    pub fn with_coverage_stall(mut self, state: &CoverageState) -> Self {
        if let CoverageState::Stalled(alert) = state
            && let Some(row) = self
                .inputs
                .iter_mut()
                .find(|r| r.id == "runtime-corroboration")
        {
            row.state = InputState::Stalled;
            row.detail = stalled_detail(alert);
        }
        self
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
/// last-adjudication outcome, the runtime row reads the per-node coverage, and the
/// cold-start flag reads `last_pass`. This is the tested core.
#[allow(dead_code)]
pub(crate) fn derive_readiness(
    config: &ReadinessConfig,
    model_health: ModelHealth,
    last_pass: Option<SystemTime>,
    runtime: &RuntimeCoverage,
) -> Readiness {
    let warming_up = last_pass.is_none();

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

    // Runtime corroboration (JEF-308): ONE agent-sourced, per-node row. The honesty ladder —
    // healthy / degraded (blind on N, named) / blind (no live signal) — and the per-node
    // breakdown come from the derived per-node coverage.
    let (runtime_state, runtime_detail, runtime_nodes) = runtime_corroboration_row(runtime);

    let journal_state = present_if(config.journal_durable);

    // The sigstore TUF trust-root freshness (JEF-280): a stale/starved root, or a fleet-wide spike
    // in unverifiable signatures, mass-blinds signing detection — surfaced non-green so it can't
    // read as a silent green.
    let (tuf_state, tuf_detail) = tuf_row(config.tuf_cache_age_secs, config.unverifiable_spike);

    // Signature-verification reachability (JEF-326): images left in the transient `Checking` state
    // have an UNKNOWN posture (verification couldn't complete), never a clean one. A persistent
    // backlog is surfaced non-green so perpetual "checking" is honestly visible, not silent.
    let (verify_state, verify_detail) = signature_verification_row(config.checking_images);

    let inputs = vec![
        ReadinessRow {
            id: "model",
            label: "Model adjudicator",
            state: model_state,
            why: "decides whether a proven chain is a real breach — without it, nothing is judged exploitable",
            enable: "PROTECTOR_ENGINE_MODEL",
            detail: model_detail,
            weakens_decisions: true,
            nodes: Vec::new(),
        },
        ReadinessRow {
            id: "kev",
            label: "KEV catalogue",
            state: kev_state,
            why: "flags known-exploited CVEs so the model weighs active threats first",
            enable: "PROTECTOR_KEV_FILE",
            detail: coverage_detail(config.kev_count, "known-exploited CVE id"),
            weakens_decisions: true,
            nodes: Vec::new(),
        },
        ReadinessRow {
            id: "epss",
            label: "EPSS feed",
            state: epss_state,
            why: "exploit-prediction scores rank which CVEs are most likely to be hit next",
            enable: "PROTECTOR_EPSS_FILE",
            detail: coverage_detail(config.epss_count, "EPSS score"),
            weakens_decisions: true,
            nodes: Vec::new(),
        },
        // ONE agent-sourced runtime-corroboration row (JEF-308). Its state IS the honesty
        // ladder; its `nodes` carry the per-node breakdown the view renders as a
        // `<details>`/`<table>`.
        ReadinessRow {
            id: "runtime-corroboration",
            label: "Runtime monitoring",
            state: runtime_state,
            why: "live per-node behavioral signals (exec, secret reads, connections, alerts) confirm a path is being exploited right now — a blind node cannot corroborate",
            enable: "deploy the agent DaemonSet (-> /behavior)",
            detail: runtime_detail,
            weakens_decisions: true,
            nodes: runtime_nodes,
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
            nodes: Vec::new(),
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
            nodes: Vec::new(),
        },
        ReadinessRow {
            id: "signature-verification",
            label: "Signature verification",
            state: verify_state,
            why: "reads each image's signing posture; while verification can't complete (registry/Rekor/TUF unreachable or the per-image budget too short) those images stay 'checking' — posture unknown, not clean",
            enable: "PROTECTOR_VERIFY_TIMEOUT",
            detail: verify_detail,
            // Signing-detection coverage, not a model-adjudication enrichment input — its gap
            // doesn't weaken the model's exploitability call (ADR-0016), mirroring the TUF row.
            weakens_decisions: false,
            nodes: Vec::new(),
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
            nodes: Vec::new(),
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

/// The signature-verification reachability row's `(state, detail)` (JEF-326). `Present` when no
/// image is stuck in the transient `Checking` state (verification is completing), `Degraded` when
/// one or more images could not be resolved this pass — their posture is unknown, not clean, so the
/// row goes non-green and names the count. Never `Absent`: the sweep always runs; a stuck backlog
/// is a degradation of a working input, not a missing one.
fn signature_verification_row(checking_images: usize) -> (InputState, String) {
    if checking_images == 0 {
        (
            InputState::Present,
            "verification completing — no images stuck checking".to_string(),
        )
    } else {
        (
            InputState::Degraded,
            format!(
                "verification unavailable — {checking_images} image{} stuck 'checking' (registry/Rekor/TUF unreachable or PROTECTOR_VERIFY_TIMEOUT too short); posture unknown, not clean",
                plural(checking_images as u64)
            ),
        )
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

/// The escalated detail line for a STALLED runtime-corroboration row (JEF-421): the honest "went
/// dark" message plus the last time the sensors were observed live, so an operator sees at a glance
/// how long the fleet has been silent.
fn stalled_detail(alert: &CoverageAlert) -> String {
    match &alert.last_observation {
        Some(ago) => format!("STALLED: {} (last observed {ago})", alert.message),
        None => format!("STALLED: {}", alert.message),
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

/// Build the collapsed **Runtime corroboration** row (JEF-308) — its coarse [`InputState`], the
/// honest ladder detail, and the per-node breakdown — from the derived per-node coverage. The
/// ladder, in order of increasing coverage:
///
///   * **blind** (`Absent`) — no live signal at all: the agent is deployed nowhere in scope, OR
///     every expected node is dark. Named honestly; absence of a signal is never reassuring.
///   * **degraded** (`Degraded`) — SOME expected nodes are blind (named) or only partially
///     probing, while others are healthy.
///   * **healthy** (`Present`) — every expected node is reporting with its probes loaded (quiet
///     counts).
///
/// A node the agent isn't scheduled on is out-of-scope (not in the expected set), so it never
/// pushes the row off green.
fn runtime_corroboration_row(
    runtime: &RuntimeCoverage,
) -> (InputState, String, Vec<NodeCoverageRow>) {
    let nodes = node_rows(runtime);
    let expected = runtime.expected_count();
    let blind = runtime.blind_nodes();
    let degraded = runtime.degraded_nodes();
    let healthy = runtime.healthy_count();
    let agent_signals = runtime.agent_signals();

    // No expected nodes: the agent isn't scheduled anywhere in scope this pass.
    if expected == 0 {
        return (
            InputState::Absent,
            "BLIND: no runtime sensor reporting — absence of a signal is not evidence of safety"
                .to_string(),
            nodes,
        );
    }

    // Every expected node is dark → wholly blind. DISTINCT from Absent (never enabled): the fleet
    // IS expected, it just has no live sensor right now — must forbid the green all-clear.
    if blind.len() == expected {
        return (
            InputState::Blind,
            format!(
                "BLIND: all {expected} expected node{} dark ({}) — corroboration has no live sensor",
                plural(expected as u64),
                blind.join(", ")
            ),
            nodes,
        );
    }

    // Some expected nodes blind → degraded, naming them.
    if !blind.is_empty() {
        return (
            InputState::Degraded,
            format!(
                "degraded — blind on {} of {expected} node{}: {} ({healthy} healthy)",
                blind.len(),
                plural(expected as u64),
                blind.join(", ")
            ),
            nodes,
        );
    }

    // Only partial-probe degradation remains.
    if !degraded.is_empty() {
        return (
            InputState::Degraded,
            format!(
                "degraded — probes partial on {}: {}",
                degraded.len(),
                degraded.join(", ")
            ),
            nodes,
        );
    }

    // Every expected node healthy (quiet counts).
    (
        InputState::Present,
        format!(
            "healthy — all {expected} node{} reporting, probes loaded ({agent_signals} signal{} this pass)",
            plural(expected as u64),
            plural(agent_signals)
        ),
        nodes,
    )
}

/// Project the derived coverage into the per-node display rows (JEF-308). Each line names the
/// node, its honest state, and a short live detail — quiet is spelled out as quiet, blind names
/// its reason, so the two never collapse into one word.
fn node_rows(runtime: &RuntimeCoverage) -> Vec<NodeCoverageRow> {
    runtime
        .nodes
        .iter()
        .map(|n| {
            let (state, detail) = match n.state {
                NodeState::Healthy { signals: 0 } => (
                    NodeCoverageState::Healthy,
                    "quiet — probes loaded, 0 signals this pass".to_string(),
                ),
                NodeState::Healthy { signals } => (
                    NodeCoverageState::Healthy,
                    format!(
                        "{signals} signal{} this pass, probes loaded",
                        plural(signals)
                    ),
                ),
                NodeState::DegradedProbes { loaded, total } => (
                    NodeCoverageState::Degraded,
                    format!("partial — {loaded}/{total} probes loaded"),
                ),
                NodeState::Blind {
                    reason: BlindReason::NotReporting,
                } => (
                    NodeCoverageState::Blind,
                    "not reporting — no live sensor on this node".to_string(),
                ),
                NodeState::Blind {
                    reason: BlindReason::ProbesFailed,
                } => (
                    NodeCoverageState::Blind,
                    "probes failed to load — agent up but blind".to_string(),
                ),
                NodeState::OutOfScope => (
                    NodeCoverageState::OutOfScope,
                    "agent not scheduled here".to_string(),
                ),
            };
            NodeCoverageRow {
                node: n.node.clone(),
                state,
                detail,
            }
        })
        .collect()
}

/// `"s"` unless `n == 1` — the pluralization for the honest count lines.
fn plural(n: u64) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[cfg(test)]
#[path = "readiness_tests.rs"]
mod tests;
