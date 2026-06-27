//! The behavioral-bake view-model (ADR-0019, the DATA layer): a pure function mapping the
//! per-pass [`BakeStats`] into the plain `Props` the `components::panels::bake` renderer
//! consumes. No maud, no markup — the renderer turns this into the JEF-48 bake panel
//! (signal volume by variant, attribution resolved/unresolved, the live store, and
//! corroborations fired).

use crate::engine::dashboard::legacy::BakeStats;

/// One per-variant volume row: the signal variant name and its count this pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BakeVariantRow {
    /// The signal variant label (connection / secret-read / library-load / … / alert).
    pub variant: String,
    /// The count of that variant this pass.
    pub count: u64,
}

/// The behavioral-bake panel props (JEF-48). When `quiet` is true the panel renders the
/// honest "no behavioral signals observed yet" state and the rest of the fields are unused;
/// otherwise it renders the summary line + the per-variant volume table.
#[derive(Debug, Clone, PartialEq)]
pub struct BakeProps {
    /// Nothing observed this pass AND an empty live store — render the quiet state.
    pub quiet: bool,
    /// Total signals ingested this pass (the volume figure).
    pub total: u64,
    /// Signals attributed to a live workload this pass.
    pub resolved: u64,
    /// Signals whose attribution did not resolve this pass.
    pub unresolved: u64,
    /// The unresolved share as a percentage, `[0, 100]` — shown (and flagged) only when
    /// `unresolved > 0`.
    pub unresolved_pct: f64,
    /// The live (TTL'd) runtime-store cardinality as of this pass.
    pub runtime_store: u64,
    /// Corroborations that fired this pass (the would-have-promoted proxy in shadow).
    pub corroborations: u64,
    /// Per-variant volume rows, ordered by variant (stable). Empty ⇒ the "no signals this
    /// pass" placeholder row.
    pub variants: Vec<BakeVariantRow>,
}

/// Build the bake panel props from the per-pass [`BakeStats`]. PURE: mirrors the legacy
/// `bake_panel` inputs — the quiet gate, the attribution percentage, and the per-variant
/// rows — leaving only the presentation to the renderer.
pub fn bake_props(bake: &BakeStats) -> BakeProps {
    let total = bake.total_signals();
    let quiet = total == 0 && bake.runtime_store == 0;
    let variants = bake
        .signals_by_variant
        .iter()
        .map(|(variant, n)| BakeVariantRow {
            variant: variant.clone(),
            count: *n,
        })
        .collect();
    BakeProps {
        quiet,
        total,
        resolved: bake.resolved,
        unresolved: bake.unresolved,
        unresolved_pct: bake.unresolved_fraction() * 100.0,
        runtime_store: bake.runtime_store,
        corroborations: bake.corroborations,
        variants,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn bake(resolved: u64, unresolved: u64) -> BakeStats {
        let mut signals_by_variant = BTreeMap::new();
        signals_by_variant.insert("connection".to_string(), 12);
        signals_by_variant.insert("secret-read".to_string(), 3);
        signals_by_variant.insert("library-load".to_string(), 5);
        BakeStats {
            signals_by_variant,
            resolved,
            unresolved,
            runtime_store: 7,
            corroborations: 2,
        }
    }

    #[test]
    fn empty_bake_is_quiet() {
        let props = bake_props(&BakeStats::default());
        assert!(props.quiet, "nothing observed ⇒ quiet");
    }

    #[test]
    fn props_carry_volume_attribution_and_corroborations() {
        let props = bake_props(&bake(80, 20));
        assert!(!props.quiet);
        assert_eq!(props.total, 20);
        assert_eq!(props.resolved, 80);
        assert_eq!(props.unresolved, 20);
        assert!((props.unresolved_pct - 20.0).abs() < 1e-9);
        assert_eq!(props.corroborations, 2);
        assert_eq!(props.variants.len(), 3);
        // Ordered by variant (BTreeMap order): connection < library-load < secret-read.
        assert_eq!(props.variants[0].variant, "connection");
    }

    #[test]
    fn fully_resolved_pass_has_zero_unresolved() {
        let props = bake_props(&bake(15, 0));
        assert_eq!(props.unresolved, 0);
        assert_eq!(props.unresolved_pct, 0.0);
    }
}
