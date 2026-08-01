//! The `enforce` arming ladder (ADR-0035): an ORDERED position over the live network
//! cuts, not a menu of independent per-cut toggles. ADR-0021 collapsed enforcement to
//! `mode` + `enforceScope`, but a single `enforce` flip armed all three network cuts —
//! the surgical [`DenyNetworkPath`] edge-cut *and* both quarantines — at once, so there
//! was nothing to arm one class at a time against. This module is the fix: it maps a
//! single ordered [`ArmingRung`] to the [`EnabledActions`] it implies.
//!
//! The ladder is deliberately **one position, not N flags** — escalating a rung always
//! implies its narrower predecessors, so there is still exactly one thing for an
//! operator to reason about (ADR-0021's anti-drift intent, preserved). It answers only
//! "how far up the cut-severity ladder is `enforce` armed" — `enforceScope` (the *where*
//! dial) and `mode` (the shadow-vs-act gate) are untouched and orthogonal to it.

use super::EnabledActions;
use crate::engine::respond::ProposedAction;

/// How far up the network-cut severity ladder `mode: enforce` is armed. Ordered:
/// each rung implies its narrower predecessor(s) — [`Quarantine`](Self::Quarantine)
/// still arms the edge-cut, it never replaces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ArmingRung {
    /// Rung 1 — the narrowest, most-reversible cut, and the `enforce` default: only the
    /// surgical [`DenyNetworkPath`] edge-cut is armed. The broader quarantines stay
    /// propose-only until [`Quarantine`](Self::Quarantine) is explicitly opted into.
    #[default]
    EdgeCut,
    /// Rung 2 — an explicit second opt-in beyond the edge-cut rung: also arms the
    /// default-deny entry quarantine ([`QuarantineEntry`](ProposedAction::QuarantineEntry),
    /// ADR-0010) and the compromised-workload quarantine
    /// ([`QuarantineWorkload`](ProposedAction::QuarantineWorkload)).
    Quarantine,
}

impl ArmingRung {
    /// Parse the operator-facing rung name (`PROTECTOR_ENFORCE_RUNG` / the chart's
    /// `enforceRung`). Unknown or empty values fall back to the narrowest rung
    /// (`edge-cut`) — the safe direction when a rung isn't recognized.
    pub fn from_name(name: &str) -> Self {
        match name.trim() {
            "quarantine" => Self::Quarantine,
            _ => Self::EdgeCut,
        }
    }

    /// The [`EnabledActions`] this rung arms — the ordered ladder, so higher rungs
    /// always include every action their narrower predecessors arm.
    pub fn enabled_actions(self) -> EnabledActions {
        let armed = EnabledActions::none().enable(ProposedAction::DenyNetworkPath);
        match self {
            Self::EdgeCut => armed,
            Self::Quarantine => armed
                .enable(ProposedAction::QuarantineEntry)
                .enable(ProposedAction::QuarantineWorkload),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edge_cut_is_the_default_and_arms_only_the_surgical_cut() {
        assert_eq!(ArmingRung::default(), ArmingRung::EdgeCut);
        let armed = ArmingRung::EdgeCut.enabled_actions();
        assert!(armed.is_enabled(ProposedAction::DenyNetworkPath));
        assert!(!armed.is_enabled(ProposedAction::QuarantineEntry));
        assert!(!armed.is_enabled(ProposedAction::QuarantineWorkload));
    }

    #[test]
    fn quarantine_rung_implies_the_edge_cut_and_adds_both_quarantines() {
        let armed = ArmingRung::Quarantine.enabled_actions();
        assert!(armed.is_enabled(ProposedAction::DenyNetworkPath));
        assert!(armed.is_enabled(ProposedAction::QuarantineEntry));
        assert!(armed.is_enabled(ProposedAction::QuarantineWorkload));
    }

    #[test]
    fn unknown_or_empty_names_fall_back_to_the_narrowest_rung() {
        assert_eq!(ArmingRung::from_name(""), ArmingRung::EdgeCut);
        assert_eq!(ArmingRung::from_name("bogus"), ArmingRung::EdgeCut);
        assert_eq!(
            ArmingRung::from_name("  quarantine  "),
            ArmingRung::Quarantine
        );
    }

    #[test]
    fn neither_rung_arms_a_non_network_action_class() {
        // The ladder only ever governs the two live-actuatable network classes — no
        // rung enables a subtractive/irreversible class regardless of position.
        for rung in [ArmingRung::EdgeCut, ArmingRung::Quarantine] {
            let armed = rung.enabled_actions();
            assert!(!armed.is_enabled(ProposedAction::RevokeRbacGrant));
            assert!(!armed.is_enabled(ProposedAction::RemoveSecretMount));
            assert!(!armed.is_enabled(ProposedAction::RebindIdentity));
            assert!(!armed.is_enabled(ProposedAction::RemoveEscapePrimitive));
        }
    }
}
