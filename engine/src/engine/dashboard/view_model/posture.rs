//! The model-decided POSTURE (JEF-255) — the dashboard's single, typed answer per entry.
//!
//! v1 string-matched the verdict prose (the "exploitable" prefix) in four places and they
//! diverged. v2 derives posture ONCE from the TYPED [`Verdict`] here (the SSOT), and the
//! data-layer twin [`StoredPosture::of_verdict`] mirrors it from the same typed input, so the
//! recency diff and the rendered chip can never drift.
//!
//! This is the only `view_model` file that names a `Verdict` — it shapes the typed domain
//! call into a plain presentational enum the components consume; the renderers never see a
//! `Verdict`, only the [`Posture`] and the already-shaped prose (ADR-0019).

use crate::engine::reason::adjudicate::Verdict;

/// The model's call on whether an exposed entry is actually compromised right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    /// The model affirmed a real, exploitable breach (`Confirmed` / `Exploitable`).
    Breach,
    /// The model judged this NOT a breach (a decisive `Refuted` / `Uncertain` call).
    Safe,
    /// No verdict has landed for this entry yet — the model hasn't reached it (or, after a
    /// restart, hasn't re-confirmed a journal-restored one). The honest "not judged" state.
    Awaiting,
}

impl Posture {
    /// Derive the posture from the model's TYPED verdict (JEF-255) — the SSOT. A
    /// `Confirmed`/`Exploitable` verdict ([`Verdict::is_confirmed`]) is a BREACH; any decisive
    /// negative is `Safe`; `None` is `Awaiting`. (v1 keyed on the "exploitable" prose prefix
    /// and missed `Confirmed` — this fixes that.)
    pub fn of_verdict(verdict: Option<&Verdict>) -> Self {
        match verdict {
            None => Posture::Awaiting,
            Some(v) if v.is_confirmed() => Posture::Breach,
            Some(_) => Posture::Safe,
        }
    }

    /// The status WORD the chip shows — meaning is carried by the word, never color alone
    /// (accessibility). Uppercase BREACH/SAFE so the loud state reads loud; "awaiting" quiet.
    pub fn label(self) -> &'static str {
        match self {
            Posture::Breach => "BREACH",
            Posture::Safe => "SAFE",
            Posture::Awaiting => "awaiting",
        }
    }

    /// The CSS tone class for the chip (`p-breach` / `p-safe` / `p-awaiting`).
    pub fn tone(self) -> &'static str {
        match self {
            Posture::Breach => "p-breach",
            Posture::Safe => "p-safe",
            Posture::Awaiting => "p-awaiting",
        }
    }

    pub fn is_breach(self) -> bool {
        matches!(self, Posture::Breach)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breach_keys_on_is_confirmed_not_prose() {
        assert_eq!(Posture::of_verdict(None), Posture::Awaiting);
        assert_eq!(
            Posture::of_verdict(Some(&Verdict::Exploitable("CVE-2021-44228".into()))),
            Posture::Breach
        );
        // The v1 bug: a `Confirmed` verdict read SAFE because its summary lacked the
        // "exploitable" prefix. The typed SSOT classes it BREACH.
        assert_eq!(
            Posture::of_verdict(Some(&Verdict::Confirmed)),
            Posture::Breach
        );
        assert_eq!(
            Posture::of_verdict(Some(&Verdict::Refuted("internal only".into()))),
            Posture::Safe
        );
        assert_eq!(
            Posture::of_verdict(Some(&Verdict::Uncertain("timed out".into()))),
            Posture::Safe
        );
    }

    #[test]
    fn labels_and_tones_are_distinct() {
        assert_eq!(Posture::Breach.label(), "BREACH");
        assert_eq!(Posture::Safe.label(), "SAFE");
        assert_eq!(Posture::Awaiting.label(), "awaiting");
        assert!(Posture::Breach.is_breach());
        assert!(!Posture::Safe.is_breach());
    }
}
