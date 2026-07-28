//! Per-scenario sample-state builders.
//!
//! Each returns a fully-populated `DashboardState` for one honesty state, so the rendered page
//! reads exactly as the engine would render that state. All four share the same finding
//! skeletons in [`crate::fixtures`]; they differ in which verdicts/health/readiness they stamp.

mod blind;
mod breach;
mod clear;
mod watching;

use protector::engine::dashboard::DashboardState;

/// The selectable preview scenarios. `?scenario=` maps onto these; default is `Breach`.
#[derive(Clone, Copy)]
pub(crate) enum Scenario {
    Clear,
    Watching,
    Breach,
    Blind,
}

impl Scenario {
    pub(crate) fn parse(s: Option<&str>) -> Scenario {
        match s {
            Some("clear") => Scenario::Clear,
            Some("watching") => Scenario::Watching,
            Some("blind") => Scenario::Blind,
            _ => Scenario::Breach,
        }
    }

    pub(crate) fn build(self) -> DashboardState {
        match self {
            Scenario::Clear => clear::build_clear(),
            Scenario::Watching => watching::build_watching(),
            Scenario::Breach => breach::build_breach(),
            Scenario::Blind => blind::build_blind(),
        }
    }
}
