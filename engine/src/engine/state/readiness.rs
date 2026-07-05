//! The readiness aggregation (JEF-160): the [`Readiness`] snapshot and its rows, and the
//! pure [`derive_readiness`] that builds them from the engine's config summary + live state.
//!
//! This is data, not markup — it holds no rendering. It is the coverage shape derived from the
//! [`ReadinessConfig`] the engine captures each run (presence/absence of each decision input,
//! the model's last-call health, this pass's behavioral signal volume), so a consumer can report
//! LIVE coverage rather than guessing.

use std::time::SystemTime;

use serde::Serialize;

use super::agent_liveness::{BlindReason, NodeState, RuntimeCoverage};
use super::parity::{CorroborationParity, ParityReadiness};
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
    /// The corroboration-parity report (JEF-310, Falco-retirement F6): this pass's Falco-vs-agent
    /// corroboration split and the honest retirement reading. Read-only measurement — it drives no
    /// decision (ADR-0016); its headline "agent-uncovered" count trending to ≈0 over a bake is the
    /// signal that Falco can be retired.
    pub parity: ParityReport,
}

/// The rendered corroboration-parity report (JEF-310): the raw per-source counts plus the coarse
/// [`ParityState`] and the honest one-line summary the readiness view shows. Kept as its own shape
/// (not inlined into a `ReadinessRow`) because it is a retirement MEASUREMENT, not a decision input
/// with an enable env var. JSON-serializable so a consumer reads the same numbers the OTLP mirror does.
#[derive(Debug, Clone, Serialize)]
pub struct ParityReport {
    /// The coarse retirement reading — the honest state that must never read green off missing data.
    pub state: ParityState,
    /// The one-line human summary (counts + honesty caveat). Carries no untrusted text.
    pub summary: String,
    /// Breach chains corroborated by Falco this pass.
    pub falco_corroborated: u64,
    /// Breach chains corroborated by the first-party agent this pass.
    pub agent_corroborated: u64,
    /// Breach chains corroborated by BOTH (the parity we want).
    pub both: u64,
    /// Breach chains Falco corroborated with no agent-equivalent signal — the headline gap.
    pub agent_uncovered: u64,
    /// The distinct front-door workloads behind [`agent_uncovered`](Self::agent_uncovered) —
    /// UNTRUSTED-adjacent cluster names, escaped at render (maud default), never `PreEscaped`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uncovered_entries: Vec<String>,
}

/// The coarse corroboration-parity state (JEF-310), the presentation mirror of
/// [`ParityReadiness`]. Distinct from [`InputState`] because "nothing to compare" is a real
/// epistemic state, not an absent decision input — it must not render as a reassuring green.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParityState {
    /// Falco corroborated nothing this window — nothing to compare (NOT "safe to retire").
    NothingToCompare,
    /// Falco corroborated chains the agent did not — agent-uncovered gap remains.
    Uncovered,
    /// Every Falco-corroborated chain was also agent-corroborated — parity this window.
    Parity,
}

impl Readiness {
    /// Attach the corroboration-parity report (JEF-310) folded from this pass's proven chains.
    /// Kept separate from [`derive_readiness`] because the parity comes from the chains, not the
    /// config/health/coverage inputs the rest of the snapshot reads. Read-only (ADR-0016).
    #[allow(dead_code)]
    pub(crate) fn with_parity(mut self, parity: &CorroborationParity) -> Self {
        self.parity = parity_report(parity);
        self
    }

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
    runtime: &RuntimeCoverage,
) -> Readiness {
    let warming_up = last_pass.is_none();

    // The behavioral split (JEF-48 variant labels): Falco arrives as the `alert` variant. During
    // the Falco→agent cutover (F5..F8) it may still feed, so the collapsed row tolerates it as the
    // "both-sources" ladder rung — but the row is now agent-SOURCED (per-node, signal-flow).
    let falco_signals: u64 = bake.signals_by_variant.get("alert").copied().unwrap_or(0);

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

    // Runtime corroboration (JEF-308): ONE agent-sourced, per-node row replacing the old
    // `falco` + `ebpf-agent` split. The honesty ladder — healthy / degraded (blind on N,
    // named) / blind (no live signal) / both-sources (Falco still feeding during cutover) —
    // and the per-node breakdown come from the derived coverage + this pass's Falco volume.
    let (runtime_state, runtime_detail, runtime_nodes) =
        runtime_corroboration_row(runtime, falco_signals);

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
        // ONE agent-sourced runtime-corroboration row (JEF-308), replacing the former
        // `falco` + `ebpf-agent` split. Its state IS the honesty ladder; its `nodes` carry the
        // per-node breakdown the view renders as a `<details>`/`<table>`.
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
        // The parity report defaults to "nothing to compare" (an empty fold) and is attached from
        // the pass's chains via [`Readiness::with_parity`] — it is folded from the proven chains,
        // not the config/health inputs the rest of this snapshot reads.
        parity: parity_report(&CorroborationParity::default()),
    }
}

/// Build the corroboration-parity report (JEF-310) for the readiness view from this pass's
/// per-source counts. The summary line is honest above all: a Falco-silent window reads
/// "nothing to compare", explicitly NOT "0 uncovered = safe to retire" (ADR-0016). Carries only
/// counts and (already-bounded) cluster names — no untrusted free-text of its own.
fn parity_report(parity: &CorroborationParity) -> ParityReport {
    let (state, summary) = match parity.readiness() {
        ParityReadiness::NothingToCompare => (
            ParityState::NothingToCompare,
            "nothing to compare this pass — no Falco alert corroborated a breach chain, so agent \
             parity cannot be measured (absence of Falco activity is not evidence the agent has \
             parity)"
                .to_string(),
        ),
        ParityReadiness::Uncovered { count } => (
            ParityState::Uncovered,
            format!(
                "agent-uncovered: {count} breach chain{} corroborated by Falco with no agent signal on the same workload ({} of {} Falco corroborations matched by the agent) — NOT yet safe to retire Falco",
                plural(count),
                parity.both,
                parity.falco_corroborated,
            ),
        ),
        ParityReadiness::Parity => (
            ParityState::Parity,
            format!(
                "parity this pass — the agent corroborated all {} Falco-corroborated breach chain{} (0 agent-uncovered)",
                parity.falco_corroborated,
                plural(parity.falco_corroborated),
            ),
        ),
    };
    ParityReport {
        state,
        summary,
        falco_corroborated: parity.falco_corroborated,
        agent_corroborated: parity.agent_corroborated,
        both: parity.both,
        agent_uncovered: parity.agent_uncovered,
        uncovered_entries: parity.uncovered_entries.clone(),
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

/// Build the collapsed **Runtime corroboration** row (JEF-308) — its coarse [`InputState`], the
/// honest ladder detail, and the per-node breakdown — from the derived coverage and this pass's
/// Falco alert volume. The ladder, in order of increasing coverage:
///
///   * **blind** (`Absent`) — no live signal at all: the agent is deployed nowhere in scope and
///     Falco is silent, OR every expected node is dark. Named honestly; absence of a signal is
///     never reassuring.
///   * **degraded** (`Degraded`) — SOME expected nodes are blind (named) or only partially
///     probing, while others are healthy (and/or Falco still feeds).
///   * **healthy** (`Present`) — every expected node is reporting with its probes loaded (quiet
///     counts). Falco still feeding is noted as the cutover "both-sources" rung.
///
/// A node the agent isn't scheduled on is out-of-scope (not in the expected set), so it never
/// pushes the row off green.
fn runtime_corroboration_row(
    runtime: &RuntimeCoverage,
    falco_signals: u64,
) -> (InputState, String, Vec<NodeCoverageRow>) {
    let nodes = node_rows(runtime);
    let falco_active = falco_signals > 0;
    let expected = runtime.expected_count();
    let blind = runtime.blind_nodes();
    let degraded = runtime.degraded_nodes();
    let healthy = runtime.healthy_count();
    let agent_signals = runtime.agent_signals();

    let falco_note = if falco_active {
        format!(
            " (+ Falco corroborating: {falco_signals} alert{} this pass, cutover)",
            plural(falco_signals)
        )
    } else {
        String::new()
    };

    // No expected nodes: the agent isn't scheduled anywhere in scope this pass.
    if expected == 0 {
        return if falco_active {
            (
                InputState::Present,
                format!(
                    "Falco corroborating ({falco_signals} alert{} this pass) — eBPF agent not reporting on any node (cutover)",
                    plural(falco_signals)
                ),
                nodes,
            )
        } else {
            (
                InputState::Absent,
                "BLIND: no runtime sensor reporting — absence of a signal is not evidence of safety"
                    .to_string(),
                nodes,
            )
        };
    }

    // Every expected node is dark AND Falco is silent → wholly blind.
    if blind.len() == expected && !falco_active {
        return (
            InputState::Absent,
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
                "degraded — blind on {} of {expected} node{}: {} ({healthy} healthy){falco_note}",
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
                "degraded — probes partial on {}: {}{falco_note}",
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
            "healthy — all {expected} node{} reporting, probes loaded ({agent_signals} signal{} this pass){falco_note}",
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
