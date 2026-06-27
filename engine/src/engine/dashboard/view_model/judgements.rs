//! The `/judgements` view-model (ADR-0019, the DATA layer): pure functions that shape the
//! recent model [`Judgement`]s (JEF-161) into the plain `Props` the `components::judgements`
//! renderer consumes. No maud, no markup — only the mapping from the engine's judgement log
//! into presentation-shaped data: the posture chip, the three honest meta-states, the short
//! workload label, and the raw prompt+reply (with the safe-fallback default text resolved
//! here) that the component tucks behind the `<details>` expander.
//!
//! The [`Judgement`] shape itself (and so the `/judgements.json` contract) stays in
//! the data layer — this layer only reshapes it for the human view, never changes it.

use crate::engine::dashboard::components::graph::short;
use crate::engine::dashboard::model::Judgement;
use crate::engine::dashboard::view_model::findings::Posture;

/// The honest meta-state a judgement card leads with (JEF-161 AC #3): the deterministic
/// pre-filter decided without the model, the model timed out (safe fallback), or the model
/// answered and we show its prose verdict verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JudgementLead {
    /// `prompt: None` — the deterministic pre-filter decided without the model (JEF-112).
    PreFilter,
    /// `reply: None` — the model timed out; the engine fell back to a safe verdict.
    Timeout,
    /// The model answered: its prose verdict, the model's own words (escaped at render).
    Verdict(String),
}

/// One `/judgements` card, pre-shaped: the posture chip, the honest lead state, the short
/// workload label, how many targets it can reach, and the raw prompt+reply (defaults
/// resolved) the component tucks behind the expander. Every text field renders through an
/// auto-escaping brace — the prompt is the injection surface (JEF-106).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JudgementCardProps {
    /// The posture chip label (`[BREACH]`/`[SAFE]`/`[awaiting judgement]`).
    pub posture_label: &'static str,
    /// The posture chip tone class.
    pub posture_tone: &'static str,
    /// The honest meta-state the card leads with.
    pub lead: JudgementLead,
    /// The short workload label (kind prefix dropped) — escaped at render.
    pub entry: String,
    /// How many targets the entry can reach (the breadth the model weighed).
    pub objectives: usize,
    /// The full prompt sent to the model, with the pre-filter default text resolved.
    pub prompt: String,
    /// The raw model reply, with the timeout default text resolved.
    pub reply: String,
}

/// The plain-data props for the `/judgements` page (ADR-0019 view-model): the ordered cards
/// (newest first, as the log snapshots them). The component renders the honest-empty state
/// when this is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JudgementsProps {
    /// The recent judgement cards, in display order.
    pub cards: Vec<JudgementCardProps>,
}

/// Shape one [`Judgement`] into its card props — the pure mapping mirroring the old
/// `judgement_card`, so the rendered HTML is byte-stable. The lead state and the raw
/// prompt/reply defaults are decided here; the component only renders.
fn card_props(j: &Judgement) -> JudgementCardProps {
    // The posture from the final verdict (Debug form, e.g. `Exploitable("…")`).
    let posture = Posture::of(Some(&j.verdict));
    // The three honest meta-states (JEF-161 AC #3).
    let lead = if j.prompt.is_none() {
        JudgementLead::PreFilter
    } else if j.reply.is_none() {
        JudgementLead::Timeout
    } else {
        JudgementLead::Verdict(j.verdict.clone())
    };
    JudgementCardProps {
        posture_label: posture.label(),
        posture_tone: posture.tone(),
        lead,
        entry: short(&j.entry),
        objectives: j.objectives,
        prompt: j
            .prompt
            .clone()
            .unwrap_or_else(|| "(none — pre-filter decided)".to_string()),
        reply: j
            .reply
            .clone()
            .unwrap_or_else(|| "(none — model timed out)".to_string()),
    }
}

/// Build the `/judgements` props from the recent judgements — the pure mapping from the
/// engine's judgement log to the data the judgements component renders.
pub fn judgements_props(judgements: &[Judgement]) -> JudgementsProps {
    JudgementsProps {
        cards: judgements.iter().map(card_props).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn judgement(verdict: &str, prompt: Option<&str>, reply: Option<&str>) -> Judgement {
        Judgement {
            entry: "workload/app/Pod/web".into(),
            objectives: 2,
            verdict: verdict.to_string(),
            prompt: prompt.map(str::to_string),
            reply: reply.map(str::to_string),
        }
    }

    #[test]
    fn lead_follows_the_three_meta_states() {
        let pre = &judgements_props(&[judgement("Refuted(..)", None, None)]).cards[0];
        assert_eq!(pre.lead, JudgementLead::PreFilter);
        let timeout = &judgements_props(&[judgement("Uncertain(..)", Some("p"), None)]).cards[0];
        assert_eq!(timeout.lead, JudgementLead::Timeout);
        let normal =
            &judgements_props(&[judgement("exploitable — RCE", Some("p"), Some("r"))]).cards[0];
        assert_eq!(
            normal.lead,
            JudgementLead::Verdict("exploitable — RCE".into())
        );
    }

    #[test]
    fn posture_maps_breach_safe_awaiting() {
        let breach =
            &judgements_props(&[judgement("exploitable — RCE", Some("p"), Some("r"))]).cards[0];
        assert_eq!(breach.posture_label, "[BREACH]");
        let safe =
            &judgements_props(&[judgement("not exploitable — denied", Some("p"), Some("r"))]).cards
                [0];
        assert_eq!(safe.posture_label, "[SAFE]");
    }

    #[test]
    fn raw_defaults_are_resolved_for_the_meta_states() {
        let card = &judgements_props(&[judgement("Refuted(..)", None, None)]).cards[0];
        assert_eq!(card.prompt, "(none — pre-filter decided)");
        assert_eq!(card.reply, "(none — model timed out)");
        assert_eq!(
            card.entry, "app/Pod/web",
            "the entry key is shortened (kind prefix dropped) for display"
        );
    }
}
