//! The findings table (JEF-205, ADR-0019): the dense `<table>` of endpoint rows, the
//! summary-row + expanded-detail pair per endpoint, the per-path evidence/rail/graph blocks,
//! and the remediation card. Pure `maud` renderers (`Props -> Markup`) — every component
//! here imports only its `Props` (from `view_model::findings`), maud, the shared `chips` /
//! `graph` primitives, and its siblings; NONE imports an `engine::` domain type (ADR-0019).
//!
//! `page.rs` does the composition (partitioning endpoints into the answer-first
//! attention/watch/context sections, the context group summary row, headings, first-run
//! checklist); this module renders each endpoint pair and wraps a set of rows in the table.

pub mod detail;
pub mod evidence;
pub mod graph;
pub mod rail;
pub mod remediation;
pub mod row;

pub use detail::detail;
pub use remediation::remediation;
pub use row::row;

use crate::engine::dashboard::view_model::findings::EndpointProps;
use maud::{Markup, PreEscaped, html};

/// The number of columns in the dense findings table (JEF-202):
/// `tier · entry → reaches · verdict · evidence · next lever · age`. The detail row's
/// `<td colspan>` spans all of them.
pub const FINDINGS_COLS: usize = 6;

/// One endpoint as a pair of dense-table rows (JEF-202): the SUMMARY `<tr>` (whose tier cell
/// is the row-expand control) and a hidden DETAIL `<tr><td colspan>` carrying the full card
/// body. The detail row's `id` matches the summary's `aria-controls`, and both survive the
/// `/fragment` swap via the stable `row_id`. The detail body stays collapsed-by-default
/// (graph behind a `details.graphwrap`).
pub fn endpoint(props: &EndpointProps) -> Markup {
    html! {
        (row(&props.row))
        tr id=(props.row.detail_id) class="f-detail" hidden {
            td colspan=(FINDINGS_COLS) { (detail(&props.detail)) }
        }
    }
}

/// Wrap pre-rendered endpoint rows in the dense findings `<table>` (JEF-202): a `<thead>` of
/// `<th scope="col">` over the decisive columns, then the rows in a `<tbody>`. The columns
/// lead with the most-decisive (tier) and end with age. `rows` is already-rendered child
/// `Markup` (its braces escaped at their own components), so it is the audited `PreEscaped`
/// child-markup allowance (ADR-0019), composed here without re-escaping.
pub fn findings_table(rows: Markup) -> Markup {
    html! {
        table class="findings" {
            thead {
                tr {
                    th scope="col" { "tier" }
                    th scope="col" { "entry → reaches" }
                    th scope="col" { "verdict" }
                    th scope="col" { "evidence" }
                    th scope="col" { "next lever" }
                    th scope="col" { "age" }
                }
            }
            tbody { (PreEscaped(rows.into_string())) }
        }
    }
}
