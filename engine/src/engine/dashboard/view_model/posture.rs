//! Map the engine's typed [`Verdict`] and recency [`Delta`] into the presentation
//! [`Posture`] / [`LiveTag`] / [`DeltaProps`] props (ADR-0019). This is the **only** place the
//! posture mapping lives, so the honesty invariants (Uncertain/Awaiting never cleared) are
//! enforced in one tested spot, and the components never see a `Verdict`.

use crate::engine::reason::adjudicate::Verdict;
use crate::engine::state::{Delta, RecencyInfo};

use super::props::{DeltaProps, LiveTag, Posture};

/// The posture a finding carries, from its typed verdict. `None` (no verdict yet) is
/// [`Posture::Awaiting`] — never cleared. `Uncertain` is its own amber state — never cleared.
/// `Confirmed`/`Exploitable` are a breach; `Refuted` is the only cleared/green path.
pub(super) fn posture_of(verdict: Option<&Verdict>) -> Posture {
    match verdict {
        None => Posture::Awaiting,
        Some(Verdict::Confirmed | Verdict::Exploitable(_)) => Posture::Breach,
        Some(Verdict::Refuted(_)) => Posture::Cleared,
        Some(Verdict::Uncertain(_)) => Posture::Uncertain,
    }
}

/// The live-vs-judged sub-tag: a `Confirmed` (live-corroborated) breach is **live**; an
/// `Exploitable` (model-promoted only) breach is **judged**; anything else has no sub-tag.
pub(super) fn live_tag_of(verdict: Option<&Verdict>) -> LiveTag {
    match verdict {
        Some(Verdict::Confirmed) => LiveTag::Live,
        Some(Verdict::Exploitable(_)) => LiveTag::Judged,
        _ => LiveTag::None,
    }
}

/// Format a whole-second age into a compact human string (`"12s"`, `"4m"`, `"2h"`, `"3d"`).
pub(super) fn human_age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

/// Map the per-entry [`RecencyInfo`] into the Δ props. A steady entry shows its age, not an
/// alarm glyph. `None` recency (never seen / no update yet) reads as steady with no age.
pub(super) fn delta_of(recency: Option<&RecencyInfo>) -> DeltaProps {
    let Some(info) = recency else {
        return DeltaProps::Unchanged { age: None };
    };
    match info.delta {
        Delta::New => DeltaProps::New,
        Delta::Escalated => DeltaProps::Escalated,
        Delta::DeEscalated => DeltaProps::DeEscalated,
        Delta::Restored => DeltaProps::Restored,
        Delta::Unchanged => DeltaProps::Unchanged {
            age: info.age_secs.map(human_age),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncertain_and_awaiting_are_never_cleared() {
        // The cardinal honesty rule, enforced at the mapping boundary (invariant #2).
        assert!(!posture_of(None).is_cleared());
        assert!(!posture_of(Some(&Verdict::Uncertain("timed out".into()))).is_cleared());
        // Only Refuted clears.
        assert!(posture_of(Some(&Verdict::Refuted("internal only".into()))).is_cleared());
        // A breach is loud, not cleared.
        assert!(!posture_of(Some(&Verdict::Confirmed)).is_cleared());
        assert!(!posture_of(Some(&Verdict::Exploitable("RCE".into()))).is_cleared());
    }

    #[test]
    fn live_vs_judged_sub_tag() {
        assert_eq!(live_tag_of(Some(&Verdict::Confirmed)), LiveTag::Live);
        assert_eq!(
            live_tag_of(Some(&Verdict::Exploitable("x".into()))),
            LiveTag::Judged
        );
        assert_eq!(live_tag_of(None), LiveTag::None);
        assert_eq!(
            live_tag_of(Some(&Verdict::Refuted("x".into()))),
            LiveTag::None
        );
    }

    #[test]
    fn human_age_buckets() {
        assert_eq!(human_age(12), "12s");
        assert_eq!(human_age(240), "4m");
        assert_eq!(human_age(7200), "2h");
        assert_eq!(human_age(259_200), "3d");
    }

    #[test]
    fn steady_delta_shows_age_not_glyph() {
        let info = RecencyInfo {
            delta: Delta::Unchanged,
            age_secs: Some(90),
        };
        let d = delta_of(Some(&info));
        assert_eq!(
            d,
            DeltaProps::Unchanged {
                age: Some("1m".into())
            }
        );
        assert_eq!(d.glyph(), "");
    }
}
