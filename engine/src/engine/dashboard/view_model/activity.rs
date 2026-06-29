//! Map the engine's audit handles into the [`ActivityViewProps`] the Activity view renders
//! (brief §6): the self-reverted-cuts log ([`ReversionRecord`] — a lifted cut + why + age, the
//! safety story kept visible) and the judgement ring ([`Judgement`] — prompt/reply per call, for
//! debugging the model). Both snapshots are already newest-first. Data layer: touches `state::`;
//! the components never do.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::engine::state::{Judgement, ReversionRecord};

use super::posture::human_age;
use super::props::{ActivityViewProps, JudgementEntryProps, ReversionProps, StatusStripProps};

/// Human "NNs ago" age for a reversion timestamp (Unix epoch ms), clamped at 0 so a clock skew
/// never renders a negative age. `now_ms` is injected for testability.
fn age_since(at_ms: u64, now_ms: u64) -> String {
    let secs = now_ms.saturating_sub(at_ms) / 1000;
    human_age(secs)
}

/// Project one reversion record into its props, formatting its age relative to `now_ms`.
fn reversion_props(r: &ReversionRecord, now_ms: u64) -> ReversionProps {
    ReversionProps {
        cut: r.cut.clone(),
        reason: r.reason.clone(),
        age: age_since(r.at_ms, now_ms),
    }
}

/// Project one judgement into its props (the verbatim prompt/reply behind a model call).
fn judgement_props(j: &Judgement) -> JudgementEntryProps {
    JudgementEntryProps {
        entry: j.entry.clone(),
        objectives: j.objectives,
        verdict: Some(j.verdict.clone()),
        prompt: j.prompt.clone(),
        reply: j.reply.clone(),
    }
}

/// Build the Activity view's props from the reversion + judgement snapshots (newest-first) and
/// the persistent strip the caller supplies. `now_ms` is the wall clock the ages are measured
/// against (injected for testability). Pure given its inputs.
pub(super) fn build_at(
    strip: StatusStripProps,
    reversions: &[ReversionRecord],
    judgements: &[Judgement],
    now_ms: u64,
) -> ActivityViewProps {
    ActivityViewProps {
        strip,
        reversions: reversions
            .iter()
            .map(|r| reversion_props(r, now_ms))
            .collect(),
        judgements: judgements.iter().map(judgement_props).collect(),
    }
}

/// Build the Activity view's props against the current wall clock.
pub(super) fn build(
    strip: StatusStripProps,
    reversions: &[ReversionRecord],
    judgements: &[Judgement],
) -> ActivityViewProps {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    build_at(strip, reversions, judgements, now_ms)
}

#[cfg(test)]
mod tests;
