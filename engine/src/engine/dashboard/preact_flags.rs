//! The per-tab Preact-render flag (ADR-0025 / JEF-397). `PROTECTOR_DASHBOARD_PREACT_TABS` is a
//! comma-separated list of tab names (`findings`, `alerts`, `action`, `readiness`, `admission`)
//! that render as a Preact client MOUNT POINT instead of the server-rendered maud body. The status
//! strip stays server-rendered on EVERY tab regardless — the flag only swaps the view body under
//! the nav.
//!
//! **Default OFF.** With the var unset (or empty) every tab renders maud exactly as before, so this
//! ships DARK: the operator sees no change until an explicit flip. The flag is fully reversible
//! (flip the var, no data migration) — it gates rendering only, never a decision (ADR-0016).
//!
//! Only Findings is ported in JEF-397; naming another tab here has no effect yet (its maud body
//! still renders) until its own fast-follow port lands. Unknown tokens are ignored (a typo can
//! never accidentally blank a view).

use super::view_model::props::Tab;

/// The set of tabs opted into the Preact client render. Cheaply cloneable (a 5-bit flag set), so it
/// rides in [`super::DashboardState`] and is consulted at page-render time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PreactTabs {
    findings: bool,
    alerts: bool,
    action: bool,
    readiness: bool,
    admission: bool,
}

impl PreactTabs {
    /// Read the flag from the process environment (`PROTECTOR_DASHBOARD_PREACT_TABS`). Absent or
    /// empty ⇒ every tab OFF (maud) — the default-dark posture.
    pub fn from_env() -> Self {
        match std::env::var("PROTECTOR_DASHBOARD_PREACT_TABS") {
            Ok(raw) => Self::parse(&raw),
            Err(_) => Self::default(),
        }
    }

    /// Parse a comma-separated tab list into the flag set. Case-insensitive; whitespace-trimmed;
    /// unknown tokens ignored (a typo never blanks a view). Pure — the unit tests hit this directly.
    pub fn parse(raw: &str) -> Self {
        let mut tabs = Self::default();
        for token in raw.split(',') {
            match token.trim().to_ascii_lowercase().as_str() {
                "findings" => tabs.findings = true,
                "alerts" => tabs.alerts = true,
                "action" => tabs.action = true,
                "readiness" => tabs.readiness = true,
                "admission" => tabs.admission = true,
                _ => {} // empty or unknown token — ignored.
            }
        }
        tabs
    }

    /// Whether the given tab should render as the Preact client mount point (vs the maud body).
    pub fn is_preact(self, tab: Tab) -> bool {
        match tab {
            Tab::Findings => self.findings,
            Tab::Alerts => self.alerts,
            Tab::Action => self.action,
            Tab::Readiness => self.readiness,
            Tab::Admission => self.admission,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_all_maud() {
        // Ships dark: with nothing set, no tab is Preact.
        let tabs = PreactTabs::default();
        for tab in [
            Tab::Findings,
            Tab::Alerts,
            Tab::Action,
            Tab::Readiness,
            Tab::Admission,
        ] {
            assert!(!tabs.is_preact(tab), "{tab:?} should default to maud");
        }
    }

    #[test]
    fn parses_a_single_tab() {
        let tabs = PreactTabs::parse("findings");
        assert!(tabs.is_preact(Tab::Findings));
        assert!(!tabs.is_preact(Tab::Alerts));
    }

    #[test]
    fn parses_a_comma_list_case_and_whitespace_insensitive() {
        let tabs = PreactTabs::parse(" Findings , ALERTS ");
        assert!(tabs.is_preact(Tab::Findings));
        assert!(tabs.is_preact(Tab::Alerts));
        assert!(!tabs.is_preact(Tab::Action));
    }

    #[test]
    fn ignores_unknown_and_empty_tokens() {
        // A typo must never blank a view — it is simply ignored.
        let tabs = PreactTabs::parse("findings,,bogus, nope ");
        assert!(tabs.is_preact(Tab::Findings));
        assert_eq!(tabs, PreactTabs::parse("findings"));
    }

    #[test]
    fn empty_string_is_all_maud() {
        assert_eq!(PreactTabs::parse(""), PreactTabs::default());
    }
}
