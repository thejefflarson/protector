//! The recent-reversions view-model (ADR-0019, the DATA layer): a pure function mapping
//! the lifted-cut records into the plain `Props` the `components::panels::reversions`
//! renderer consumes. No maud, no markup — it resolves each record's relative-time phrase
//! (the only logic) and hands the renderer plain strings to escape and lay out.

use crate::engine::dashboard::model::{ReversionRecord, relative_time};
use std::time::{Duration, SystemTime};

/// One lifted-cut row, fully resolved for rendering: the cut signature, the reason it was
/// lifted, and the humanized "when".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReversionRow {
    /// The cut signature that was lifted (`from -[relation]-> to`).
    pub cut: String,
    /// Why it was lifted.
    pub reason: String,
    /// The humanized "when" (`just now` / `NNs ago` / …).
    pub when: String,
}

/// The recent-reversions panel props (JEF-141): the lifted-cut rows, newest first. An empty
/// `rows` renders the quiet "no cuts have been lifted yet" default (a healthy state, not an
/// error). Plain data — `components::panels::reversions` renders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReversionsProps {
    /// One row per lifted cut, in the order the records arrive (newest first).
    pub rows: Vec<ReversionRow>,
}

/// Build the reversions panel props from the lifted-cut records. PURE: resolves each
/// record's relative-time phrase (the same `at_ms` → "NNs ago" mapping the legacy panel
/// used), leaving escaping + layout to the renderer.
pub fn reversions_props(reversions: &[ReversionRecord]) -> ReversionsProps {
    let rows = reversions
        .iter()
        .map(|r| {
            let when = relative_time(Some(
                SystemTime::UNIX_EPOCH + Duration::from_millis(r.at_ms),
            ));
            ReversionRow {
                cut: r.cut.clone(),
                reason: r.reason.clone(),
                when,
            }
        })
        .collect();
    ReversionsProps { rows }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unix_now_ms() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    #[test]
    fn empty_reversions_have_no_rows() {
        assert!(reversions_props(&[]).rows.is_empty());
    }

    #[test]
    fn props_resolve_cut_reason_and_when() {
        let props = reversions_props(&[ReversionRecord {
            cut: "workload/app/Pod/web -[reaches/Tcp]-> workload/app/Pod/db".into(),
            reason: "no proven chain still justifies this control".into(),
            at_ms: unix_now_ms(),
        }]);
        assert_eq!(props.rows.len(), 1);
        assert!(props.rows[0].cut.contains("workload/app/Pod/web"));
        assert!(
            props.rows[0]
                .reason
                .contains("no proven chain still justifies")
        );
        assert_eq!(props.rows[0].when, "just now");
    }
}
