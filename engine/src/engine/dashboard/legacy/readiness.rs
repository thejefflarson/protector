//! Transitional legacy module (pre-ADR-0019 string-concat rendering).
//!
//! Migrated piecemeal in tickets 3–6; extracted here only so each file
//! stays under the 1,000-line cap (repo CLAUDE.md). New work goes in the
//! `components`/`view_model` maud layers, not here.
#![allow(dead_code)]

use super::*;

/// The LIVE state of one decision input — present, absent, or degraded. Distinct from a
/// config echo: an input is `Absent` only when it is genuinely unconfigured/empty, and
/// `Degraded` when configured but not currently answering (e.g. a model that timed out).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InputState {
    /// Wired and live — contributing to decisions this pass.
    Present,
    /// Not configured (or loaded empty). For an enrichment input this is a coverage gap
    /// that weakens the model's decision (ADR-0016); rendered visually distinct.
    Absent,
    /// Configured but not currently healthy — e.g. the model is attached but its last call
    /// timed out, or signals were expected this pass but none arrived.
    Degraded,
}

impl InputState {
    /// The status WORD shown in text (never glyph-only — accessibility). The state's
    /// meaning is carried by this word; color only reinforces it.
    pub(crate) fn word(self) -> &'static str {
        match self {
            InputState::Present => "present",
            InputState::Absent => "absent",
            InputState::Degraded => "degraded",
        }
    }

    /// The CSS tone class — maps to the readiness tokens in `web/dist/dashboard.css`:
    /// green for present (the JEF-159 `#1a7f37` token), red for an absent input that
    /// weakens decisions, amber for degraded.
    pub(crate) fn tone(self) -> &'static str {
        match self {
            InputState::Present => "ok",
            InputState::Absent => "absent",
            InputState::Degraded => "degraded",
        }
    }
}

/// One readiness row: a decision input, its LIVE state, a one-line "why it matters", the
/// single env var / mount that enables it, and the live detail (a count, "last call ok",
/// "shadow"). `weakens_decisions` is true when this input being absent degrades the model's
/// call (the enrichment inputs of ADR-0016) — those absent rows are visually distinct.
/// JSON-serializable so `/readiness` returns exactly the panel's data.
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessRow {
    /// A stable, machine-readable id for the input (`model` / `kev` / `advisory` /
    /// `falco` / `ebpf-agent` / `journal` / `arm-state`).
    pub id: &'static str,
    /// The human label shown in the panel.
    pub label: &'static str,
    /// The LIVE state of this input.
    pub state: InputState,
    /// One-line "why it matters" — what protector loses without this input.
    pub why: &'static str,
    /// The single env var or mount to enable it (the "how to fix" the checklist links to).
    /// Empty for arm-state, which is a posture toggle, not a missing input.
    pub enable: &'static str,
    /// A short live detail: a count, "last call ok", "shadow mode", etc. — never a value
    /// or secret name.
    pub detail: String,
    /// Whether this input being absent WEAKENS the model's decision (the enrichment /
    /// adjudication inputs — ADR-0016). Drives the "absent input that weakens decisions is
    /// visually distinct" acceptance criterion.
    pub weakens_decisions: bool,
}

/// The whole readiness snapshot (JEF-160): every decision input's LIVE state plus the
/// cold-start flag. JSON-serializable for `/readiness`; the HTML panel renders the same
/// data. `warming_up` mirrors the banner's [`ClusterStatus::WarmingUp`]: no pass has
/// completed, so the first verdicts are still loading (expected on a CPU model).
#[derive(Debug, Clone, Serialize)]
pub struct Readiness {
    /// One row per decision input, in a stable, decision-ordered sequence.
    pub inputs: Vec<ReadinessRow>,
    /// No pass has completed yet — the bake window (first verdicts can take minutes on a
    /// CPU model) is still open. Drives the cold-start note.
    pub warming_up: bool,
    /// The model is actually answering RIGHT NOW — attached AND its last call was decisive
    /// ([`ModelHealth::Ok`]). False when no model is configured, or it timed out / hasn't
    /// been exercised this run. The banner (JEF-174) keys its "the model cleared them"
    /// clearance claim on this: a calm/green `Watching`/`Quiet` is only honest while the
    /// model is live; otherwise exposed paths are unjudged, not cleared (ADR-0016).
    pub model_judging: bool,
}

impl Readiness {
    /// How many enrichment/decision inputs are absent or degraded — the count the
    /// first-run discrimination keys on. Arm-state is posture, not an input gap, so it
    /// never counts here.
    pub fn unmet_count(&self) -> usize {
        self.inputs
            .iter()
            .filter(|r| r.id != "arm-state" && r.state != InputState::Present)
            .count()
    }

    /// Whether ANY decision input is unmet (absent or degraded) — the first-run gate.
    pub fn has_unmet(&self) -> bool {
        self.unmet_count() > 0
    }
}

/// Derive the readiness snapshot (JEF-160) from the engine's config summary and LIVE
/// state. PURE and total — no model call, no I/O: the model row reads the piggybacked
/// last-adjudication outcome, the behavioral rows read this pass's [`BakeStats`], and the
/// cold-start flag reads `last_pass`. This is the tested core; the panel and `/readiness`
/// both render its output.
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

    // The model is "judging" — giving live verdicts the banner can lean on — only when it
    // is attached AND its last fresh call was decisive. A timeout, a cold start, or no model
    // at all all mean "not judging right now" (JEF-174): the decision still falls through to
    // the deterministic skeptic, but the banner must not call that a clearance (ADR-0016).
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
                // Attached but not yet exercised: cold start, not a fault. Degraded so the
                // operator sees "no verdict yet" rather than a false "present".
                InputState::Degraded,
                "attached · no call yet this run (warming up)".to_string(),
            ),
        }
    };

    // A file-backed enrichment store is Present iff it loaded >=1 entry, else Absent.
    let kev_state = present_if(config.kev_count > 0);
    let advisory_state = present_if(config.advisory_count > 0);

    // A behavioral feed is Present iff it delivered >=1 signal this pass, else Absent. (A
    // genuinely quiet cluster reads as Absent for the pass — the panel's "signals last
    // pass" detail and the cold-start note keep that honest rather than alarming.)
    let falco_state = present_if(falco_signals > 0);
    let ebpf_state = present_if(ebpf_signals > 0);

    let journal_state = present_if(config.journal_durable);

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
            id: "advisory",
            label: "Advisory store",
            state: advisory_state,
            why: "adds CVE summaries + fix versions — the evidence the model judges with",
            enable: "PROTECTOR_ADVISORY_FILE",
            detail: coverage_detail(config.advisory_count, "advisory record"),
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
            why: "durable verdicts survive a restart and back the would-have-acted report — without it, history resets",
            enable: "PROTECTOR_ENGINE_JOURNAL_PATH",
            detail: if config.journal_durable {
                "durable volume mounted".to_string()
            } else {
                "in-memory only — resets on restart".to_string()
            },
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

/// Present iff the condition holds, else Absent.
pub(crate) fn present_if(present: bool) -> InputState {
    if present {
        InputState::Present
    } else {
        InputState::Absent
    }
}

/// The live detail for a file-backed store: "N records loaded" or the honest absent line.
pub(crate) fn coverage_detail(count: usize, noun: &str) -> String {
    if count == 0 {
        format!("not loaded — no {noun} evidence available")
    } else {
        format!("{count} {noun}{} loaded", if count == 1 { "" } else { "s" })
    }
}

/// The live detail for a behavioral feed: "N signals last pass", or an honest "none this
/// pass" when absent (no sensor reporting, or a quiet cluster).
pub(crate) fn signals_detail(state: InputState, signals: u64) -> String {
    match state {
        InputState::Present => format!(
            "{signals} signal{} last pass",
            if signals == 1 { "" } else { "s" }
        ),
        _ => "no signals last pass (no sensor reporting, or a quiet cluster)".to_string(),
    }
}

/// The readiness / coverage panel (JEF-160): an ordered `<ol>` of every decision input
/// with its LIVE state IN TEXT (not glyph-only — accessibility), the one-line why, the
/// live detail, and (when unmet) the single env var / mount to enable it. An absent input
/// that weakens decisions is visually distinct (the red `absent` tone + a "weakens
/// decisions" tag). Pure over the derived [`Readiness`].
pub(crate) fn readiness_panel(readiness: &Readiness) -> String {
    let rows: String = readiness
        .inputs
        .iter()
        .map(|r| {
            // The enable hint shows only when the input is not Present — a met input needs
            // no instruction. Arm-state has no enable hint (it's a posture toggle).
            let enable = if r.state != InputState::Present && !r.enable.is_empty() {
                format!(
                    " <span class=\"r-enable\">enable: <code>{}</code></span>",
                    escape(r.enable)
                )
            } else {
                String::new()
            };
            // An absent input that weakens decisions is called out distinctly (text tag, not
            // color alone) so a coverage gap can't hide as a benign "off".
            let weak = if r.weakens_decisions && r.state != InputState::Present {
                " <span class=\"r-weak\">weakens decisions</span>".to_string()
            } else {
                String::new()
            };
            format!(
                "<li class=\"r-row r-{tone}\"><span class=\"r-label\">{label}</span> \
                 <span class=\"r-state r-state-{tone}\">{state}</span>{weak}<br>\
                 <span class=\"r-why\">{why}</span> \
                 <span class=\"r-detail\">— {detail}</span>{enable}</li>",
                tone = r.state.tone(),
                label = escape(r.label),
                state = r.state.word(),
                why = escape(r.why),
                detail = escape(&r.detail),
            )
        })
        .collect();

    let cold = if readiness.warming_up {
        "<p class=\"r-cold\">warming up — the first pass hasn't completed; first verdicts can \
         take a few minutes on a CPU model, so a quiet dashboard right after start is expected.</p>"
    } else {
        ""
    };

    format!("{cold}<ol class=\"readiness\">{rows}</ol>")
}

/// The instructional first-run checklist (JEF-160): when the engine has no findings AND
/// inputs are unmet, this REPLACES the empty findings body — never a bare/error-looking
/// page. Each unmet input is an actionable line linking the one env var / mount to enable
/// it (status IN TEXT, ordered list — accessibility). A met input reads as a done check.
pub(crate) fn first_run_checklist(readiness: &Readiness) -> String {
    let items: String = readiness
        .inputs
        .iter()
        // Arm-state is posture, not a setup step — skip it in the checklist.
        .filter(|r| r.id != "arm-state")
        .map(|r| {
            if r.state == InputState::Present {
                format!(
                    "<li class=\"r-done\"><b>done</b> — {label}: {detail}</li>",
                    label = escape(r.label),
                    detail = escape(&r.detail),
                )
            } else {
                let enable = if r.enable.is_empty() {
                    String::new()
                } else {
                    format!(" — set <code>{}</code>", escape(r.enable))
                };
                format!(
                    "<li class=\"r-todo\"><b>to&nbsp;do</b> — {label}: {why}{enable}</li>",
                    label = escape(r.label),
                    why = escape(r.why),
                )
            }
        })
        .collect();

    let cold = if readiness.warming_up {
        "<p class=\"r-cold\">warming up — first verdicts can take a few minutes on a CPU model.</p>"
    } else {
        ""
    };

    format!(
        "<div class=\"firstrun\"><p class=\"sum\">No findings yet, and some decision inputs \
         aren't configured. protector degrades quietly when an input is missing — this \
         checklist is the guided start, not a blank page. Wire each input below to give the \
         model the full picture.</p>{cold}<ol class=\"checklist\">{items}</ol></div>"
    )
}
