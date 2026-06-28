//! The one-line STATUS props (JEF-255) — the dashboard's headline answer:
//! `● N BREACH · M endpoints · K awaiting · model live (pass <age>) · coverage X%`.
//!
//! The line is GREEN only when it is honestly all-clear AND covered: no breach, the model is
//! live, and every decision input is met. A model that is down must NOT read calm — that is
//! the honest blind state (exposed paths are unjudged, not cleared; ADR-0016). Pure data; the
//! `components::status_line` renderer turns this into the chip + counts.

use std::time::SystemTime;

use crate::engine::dashboard::model::{Finding, relative_time};
use crate::engine::dashboard::view_model::posture::Posture;
use crate::engine::dashboard::view_model::readiness_data::Readiness;

/// The overall tone of the status line — drives the lead dot's color and the screen-reader
/// summary. Meaning is always also carried in the counts text, never the dot alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusTone {
    /// One or more entries are a confirmed breach — loud.
    Breach,
    /// No breach, but the engine is BLIND: the model is down, or coverage is incomplete, so
    /// a calm reading would be dishonest (exposed paths are unjudged).
    Blind,
    /// Honestly all-clear AND covered: no breach, model live, every input met.
    Clear,
}

impl StatusTone {
    /// The CSS tone class for the lead dot / line (`s-breach` / `s-blind` / `s-clear`).
    pub fn css(self) -> &'static str {
        match self {
            StatusTone::Breach => "s-breach",
            StatusTone::Blind => "s-blind",
            StatusTone::Clear => "s-clear",
        }
    }
}

/// The shaped status-line data the renderer consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusProps {
    pub tone: StatusTone,
    /// Confirmed-breach endpoints right now.
    pub breach: usize,
    /// Exposed endpoints with a possible attack path (the table's total rows).
    pub endpoints: usize,
    /// Exposed endpoints with no verdict yet (the model hasn't reached them).
    pub awaiting: usize,
    /// The model-health clause (`model live`, `model down — not judging`, `no model — not
    /// judging`). Honest about the blind state.
    pub model_clause: String,
    /// The last-pass age (`pass 12s ago`, `waiting for first pass`).
    pub pass_age: String,
    /// Coverage as a whole percent (met decision inputs / total inputs).
    pub coverage_pct: u8,
}

/// Build the status-line props from this pass's findings + live readiness (JEF-255). Posture
/// is derived from each entry's TYPED verdict (the SSOT) — never re-parsed prose.
pub fn status_props(
    findings: &[Finding],
    last_pass: Option<SystemTime>,
    readiness: &Readiness,
) -> StatusProps {
    // Count per unique exposed entry, not per chain: an entry is the unit. An entry is a
    // breach if ANY of its chains is a breach; awaiting if it has no verdict at all.
    let mut entries: std::collections::BTreeMap<&str, Posture> = std::collections::BTreeMap::new();
    for f in findings.iter().filter(|f| f.breach_relevant) {
        let p = Posture::of_verdict(f.verdict.as_ref());
        let slot = entries.entry(f.entry.as_str()).or_insert(Posture::Awaiting);
        // Escalate the entry's posture toward Breach: Breach > Safe > Awaiting.
        *slot = max_posture(*slot, p);
    }
    let endpoints = entries.len();
    let breach = entries.values().filter(|p| p.is_breach()).count();
    let awaiting = entries
        .values()
        .filter(|p| **p == Posture::Awaiting)
        .count();

    let coverage_pct = coverage_pct(readiness);
    let tone = if breach > 0 {
        StatusTone::Breach
    } else if !readiness.model_judging || coverage_pct < 100 {
        // No breach, but blind: the model isn't judging, or an input is missing. Honest — a
        // green/clear reading here would imply "cleared" when paths are merely unjudged.
        StatusTone::Blind
    } else {
        StatusTone::Clear
    };

    StatusProps {
        tone,
        breach,
        endpoints,
        awaiting,
        model_clause: model_clause(readiness),
        pass_age: relative_time(last_pass),
        coverage_pct,
    }
}

/// The honest model-health clause. "down → not judging" / "no model → not judging" must read
/// as a gap, never calm (ADR-0016).
fn model_clause(readiness: &Readiness) -> String {
    if readiness.model_judging {
        "model live".to_string()
    } else if readiness.model_attached() {
        "model down — not judging".to_string()
    } else {
        "no model — not judging".to_string()
    }
}

/// Coverage as a whole percent: met decision inputs over total inputs. Arm-state is posture,
/// not an input gap, so it neither counts as met nor as a denominator.
fn coverage_pct(readiness: &Readiness) -> u8 {
    let total = readiness
        .inputs
        .iter()
        .filter(|r| r.id != "arm-state")
        .count();
    if total == 0 {
        return 0;
    }
    let met = total - readiness.unmet_count();
    ((met * 100) / total) as u8
}

/// The higher (louder) of two postures: Breach > Safe > Awaiting.
fn max_posture(a: Posture, b: Posture) -> Posture {
    fn rank(p: Posture) -> u8 {
        match p {
            Posture::Awaiting => 0,
            Posture::Safe => 1,
            Posture::Breach => 2,
        }
    }
    if rank(b) > rank(a) { b } else { a }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::model::{BakeStats, EntryEvidence, ReadinessConfig};
    use crate::engine::dashboard::view_model::readiness_data::derive_readiness;
    use crate::engine::reason::adjudicate::Verdict;

    fn entry_finding(entry: &str, verdict: Option<Verdict>) -> Finding {
        Finding {
            entry: entry.into(),
            objective: "secret/app/s".into(),
            foothold: true,
            corroborated: false,
            disposition: "no-cut".into(),
            cut: None,
            breach_relevant: true,
            verdict,
            path: vec![],
            evidence: EntryEvidence::default(),
            recency: None,
        }
    }

    fn covered_judging() -> Readiness {
        let mut bake = BakeStats::default();
        bake.signals_by_variant.insert("alert".into(), 1);
        bake.signals_by_variant.insert("connection".into(), 1);
        derive_readiness(
            &ReadinessConfig {
                model_attached: true,
                kev_count: 1,
                epss_count: 1,
                journal_durable: true,
                armed: false,
            },
            crate::engine::dashboard::model::ModelHealth::Ok,
            &bake,
            Some(SystemTime::now()),
        )
    }

    #[test]
    fn breach_entry_makes_the_line_loud() {
        let fs = vec![entry_finding(
            "web",
            Some(Verdict::Exploitable("CVE-x".into())),
        )];
        let p = status_props(&fs, Some(SystemTime::now()), &covered_judging());
        assert_eq!(p.tone, StatusTone::Breach);
        assert_eq!(p.breach, 1);
        assert_eq!(p.endpoints, 1);
        assert_eq!(p.awaiting, 0);
    }

    #[test]
    fn all_clear_and_covered_reads_green() {
        let fs = vec![entry_finding(
            "web",
            Some(Verdict::Refuted("internal".into())),
        )];
        let p = status_props(&fs, Some(SystemTime::now()), &covered_judging());
        assert_eq!(p.tone, StatusTone::Clear);
        assert_eq!(p.breach, 0);
        assert_eq!(p.coverage_pct, 100);
        assert_eq!(p.model_clause, "model live");
    }

    #[test]
    fn model_down_is_blind_not_calm() {
        // Model attached but last call timed out → not judging → blind, even with no breach.
        let r = derive_readiness(
            &ReadinessConfig {
                model_attached: true,
                kev_count: 1,
                epss_count: 1,
                journal_durable: true,
                armed: false,
            },
            crate::engine::dashboard::model::ModelHealth::Timeout,
            &{
                let mut b = BakeStats::default();
                b.signals_by_variant.insert("alert".into(), 1);
                b.signals_by_variant.insert("connection".into(), 1);
                b
            },
            Some(SystemTime::now()),
        );
        let fs = vec![entry_finding("web", None)];
        let p = status_props(&fs, Some(SystemTime::now()), &r);
        assert_eq!(p.tone, StatusTone::Blind);
        assert_eq!(p.model_clause, "model down — not judging");
        assert_eq!(p.awaiting, 1);
    }

    #[test]
    fn missing_input_is_blind_even_with_model_live() {
        // Model live but no KEV loaded → coverage < 100 → blind.
        let r = derive_readiness(
            &ReadinessConfig {
                model_attached: true,
                kev_count: 0,
                epss_count: 1,
                journal_durable: true,
                armed: false,
            },
            crate::engine::dashboard::model::ModelHealth::Ok,
            &{
                let mut b = BakeStats::default();
                b.signals_by_variant.insert("alert".into(), 1);
                b.signals_by_variant.insert("connection".into(), 1);
                b
            },
            Some(SystemTime::now()),
        );
        let fs: Vec<Finding> = vec![];
        let p = status_props(&fs, Some(SystemTime::now()), &r);
        assert_eq!(p.tone, StatusTone::Blind);
        assert!(p.coverage_pct < 100);
    }
}
