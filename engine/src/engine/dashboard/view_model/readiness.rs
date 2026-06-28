//! The readiness / first-run view-model (ADR-0019, the DATA layer): pure functions that
//! shape the engine's derived [`Readiness`] snapshot into the plain `Props` the
//! `components::panels::readiness` / `components::panels::first_run` renderers consume. No
//! maud, no markup — only the data the components turn into HTML.
//!
//! EXPERT-HONESTY (JEF-160/JEF-174) lives in this mapping, kept verbatim in meaning: the
//! "weakens decisions" call-out, the present/absent/degraded distinction IN TEXT, the
//! "enable: <var>" hint shown only for an unmet input, and the cold-start note. These are
//! honesty, not fluff — the view-model decides them so the renderer stays presentation-only.

use crate::engine::dashboard::view_model::readiness_data::{InputState, Readiness};

/// One row of the readiness panel, fully resolved for rendering: the label, the state WORD
/// (never glyph-only — accessibility), the CSS tone class, the one-line "why it matters",
/// the live detail, the enable hint (already gated to non-present inputs with a var), and
/// the "weakens decisions" flag (already gated to absent/degraded weakening inputs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessRowProps {
    /// The human label shown in the panel.
    pub label: String,
    /// The state WORD shown in text (`present` / `absent` / `degraded`).
    pub state_word: String,
    /// The CSS tone class for the row (`ok` / `absent` / `degraded`).
    pub tone: String,
    /// One-line "why it matters" — what protector loses without this input.
    pub why: String,
    /// A short live detail (a count, "last call ok", "shadow mode", …).
    pub detail: String,
    /// The single env var / mount to enable it — `Some` ONLY when the input is unmet AND
    /// it has an enable hint. A met input (or arm-state, which has no hint) carries `None`.
    pub enable: Option<String>,
    /// Whether to render the "weakens decisions" tag — true ONLY when this input is
    /// absent/degraded AND being absent weakens the model's call (a coverage gap that must
    /// not hide as a benign "off").
    pub weakens: bool,
}

/// The readiness / coverage panel props (JEF-160): the ordered rows plus the cold-start
/// flag. Plain data — `components::panels::readiness` renders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessProps {
    /// One row per decision input, in the readiness snapshot's decision order.
    pub rows: Vec<ReadinessRowProps>,
    /// No pass has completed yet — render the cold-start note (first verdicts can take a
    /// few minutes on a CPU model, so a quiet dashboard right after start is expected).
    pub warming_up: bool,
}

/// Build the readiness panel props from the derived [`Readiness`] snapshot. PURE: it
/// resolves the per-row tone, the gated enable hint, and the gated "weakens decisions"
/// flag the panel needs — the same EXPERT-HONESTY logic the legacy string-concat panel
/// applied, moved into the data layer so the renderer stays presentation-only.
pub fn readiness_props(readiness: &Readiness) -> ReadinessProps {
    let rows = readiness
        .inputs
        .iter()
        .map(|r| {
            // The enable hint shows only when the input is not Present — a met input needs
            // no instruction. Arm-state has no enable hint (it's a posture toggle).
            let enable = if r.state != InputState::Present && !r.enable.is_empty() {
                Some(r.enable.to_string())
            } else {
                None
            };
            // An absent input that weakens decisions is called out distinctly so a coverage
            // gap can't hide as a benign "off".
            let weakens = r.weakens_decisions && r.state != InputState::Present;
            ReadinessRowProps {
                label: r.label.to_string(),
                state_word: r.state.word().to_string(),
                tone: r.state.tone().to_string(),
                why: r.why.to_string(),
                detail: r.detail.clone(),
                enable,
                weakens,
            }
        })
        .collect();
    ReadinessProps {
        rows,
        warming_up: readiness.warming_up,
    }
}

/// One line of the first-run checklist: either a done check (a met input) or a to-do (an
/// unmet input, with its enable var). The `done` flag drives which line the component
/// renders; the texts are pre-resolved so the renderer only escapes + lays them out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstRunItemProps {
    /// True when this input is already met (a done check); false for a to-do line.
    pub done: bool,
    /// The input's human label.
    pub label: String,
    /// For a done line, the live detail; for a to-do line, the "why it matters".
    pub text: String,
    /// The enable var for a to-do line, when one exists (`None` for a done line, or a
    /// to-do with no env var).
    pub enable: Option<String>,
}

/// The instructional first-run checklist props (JEF-160): the per-input checklist lines
/// (arm-state excluded — it's posture, not a setup step) plus the cold-start flag. Plain
/// data — `components::panels::first_run` renders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstRunProps {
    /// One line per decision input (arm-state excluded), in snapshot order.
    pub items: Vec<FirstRunItemProps>,
    /// Render the cold-start note (first verdicts can take a few minutes on a CPU model).
    pub warming_up: bool,
}

/// Build the first-run checklist props from the derived [`Readiness`] snapshot. PURE:
/// arm-state is posture (skipped), a met input becomes a done check, an unmet one a to-do
/// linking its enable var — the same JEF-160 logic, moved into the data layer.
pub fn first_run_props(readiness: &Readiness) -> FirstRunProps {
    let items = readiness
        .inputs
        .iter()
        // Arm-state is posture, not a setup step — skip it in the checklist.
        .filter(|r| r.id != "arm-state")
        .map(|r| {
            if r.state == InputState::Present {
                FirstRunItemProps {
                    done: true,
                    label: r.label.to_string(),
                    text: r.detail.clone(),
                    enable: None,
                }
            } else {
                FirstRunItemProps {
                    done: false,
                    label: r.label.to_string(),
                    text: r.why.to_string(),
                    enable: if r.enable.is_empty() {
                        None
                    } else {
                        Some(r.enable.to_string())
                    },
                }
            }
        })
        .collect();
    FirstRunProps {
        items,
        warming_up: readiness.warming_up,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::model::{BakeStats, ModelHealth, ReadinessConfig};
    use crate::engine::dashboard::view_model::readiness_data::derive_readiness;
    use std::collections::BTreeMap;
    use std::time::SystemTime;

    fn feeds_bake(falco: u64, ebpf: u64) -> BakeStats {
        let mut signals_by_variant = BTreeMap::new();
        if falco > 0 {
            // Falco arrives as the `alert` variant; everything else is an eBPF signal.
            signals_by_variant.insert("alert".to_string(), falco);
        }
        if ebpf > 0 {
            signals_by_variant.insert("connection".to_string(), ebpf);
        }
        BakeStats {
            signals_by_variant,
            ..Default::default()
        }
    }

    fn full_config() -> ReadinessConfig {
        ReadinessConfig {
            model_attached: true,
            kev_count: 1500,
            journal_durable: true,
            armed: false,
        }
    }

    /// A met input carries no enable hint and no "weakens" tag; an absent enrichment input
    /// carries both — the EXPERT-HONESTY gating lives in the view-model.
    #[test]
    fn props_gate_enable_and_weakens_to_unmet_inputs() {
        let r = derive_readiness(
            &full_config(),
            ModelHealth::Ok,
            &feeds_bake(3, 12),
            Some(SystemTime::now()),
        );
        let props = readiness_props(&r);
        let model = props
            .rows
            .iter()
            .find(|x| x.label == "Model adjudicator")
            .unwrap();
        assert_eq!(model.state_word, "present");
        assert_eq!(model.tone, "ok");
        assert!(model.enable.is_none(), "a met input needs no enable hint");
        assert!(!model.weakens, "a met input carries no weakens tag");

        // Now absent across the board: enrichment inputs are flagged weakening + carry a hint.
        let r = derive_readiness(
            &ReadinessConfig::default(),
            ModelHealth::Unknown,
            &BakeStats::default(),
            Some(SystemTime::now()),
        );
        let props = readiness_props(&r);
        let kev = props
            .rows
            .iter()
            .find(|x| x.label == "KEV catalogue")
            .unwrap();
        assert_eq!(kev.state_word, "absent");
        assert_eq!(kev.tone, "absent");
        assert!(kev.weakens, "an absent enrichment input weakens decisions");
        assert_eq!(kev.enable.as_deref(), Some("PROTECTOR_KEV_FILE"));
    }

    /// The cold-start flag flows through; first-run excludes arm-state and splits done/to-do.
    #[test]
    fn first_run_props_split_done_and_todo_and_exclude_arm_state() {
        let r = derive_readiness(
            &ReadinessConfig::default(),
            ModelHealth::Unknown,
            &BakeStats::default(),
            None,
        );
        let props = first_run_props(&r);
        assert!(props.warming_up, "cold start flows through");
        assert!(
            props.items.iter().all(|i| !i.done),
            "nothing configured ⇒ every line is a to-do"
        );
        let model = props
            .items
            .iter()
            .find(|i| i.label == "Model adjudicator")
            .unwrap();
        assert_eq!(model.enable.as_deref(), Some("PROTECTOR_ENGINE_MODEL"));
        // Arm-state (posture) is never a checklist step.
        assert!(
            props.items.iter().all(|i| i.label != "Arm state"),
            "arm-state excluded from the checklist"
        );
    }
}
