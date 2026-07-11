//! The Alerts view body (JEF-323): the live "alarming-now" activity list — each event's signal,
//! the (informer-resolved) workload, recency, and the proven chain it is alarming ON (if any).
//! A CURRENT-WINDOW view of what is alarming THIS pass (labelled honestly as live, not a scrolling
//! audit log). An alarming signal is EVIDENCE, NEVER a verdict — the copy never implies a breach
//! conclusion or that any action was taken (default posture is shadow/propose, ADR-0016). It also
//! never claims "corroborated": the engine reserves that axis for the Alert-only subset that flips
//! `ProvenChain::corroborated` (ADR-0009), and this set is broader (it includes engine-defined
//! CONTEXT signals), so the view uses "alarming" language throughout and never asserts a
//! corroboration the engine didn't conclude. The empty state is CALM ("no alarming activity right
//! now"), unless a node is blind, in which case the reassurance is replaced by the "absence is not
//! safety" caveat (JEF-308). Pure component; no domain types; all free-text auto-escaped.

use maud::{Markup, html};

use crate::engine::dashboard::view_model::props::{AlertProps, AlertsViewProps};

/// Render the Alerts view (the live list + states). The status strip is composed by `page.rs`;
/// this is the view body under the nav.
pub fn alerts_view(v: &AlertsViewProps) -> Markup {
    html! {
        main.view.view-alerts {
            (live_note())
            @if v.alerts.is_empty() {
                (empty_state(v))
            } @else {
                (alerts_list(&v.alerts))
            }
        }
    }
}

/// The honest "this is a live window" note — the Alerts tab shows what is alarming THIS pass, not a
/// persisted history. Stated so a quiet view is not misread as "nothing has ever happened" and a
/// populated one is not misread as an audit log.
fn live_note() -> Markup {
    html! {
        p.alerts-note.muted {
            "Live view \u{2014} the runtime signals alarming right now (this observe pass). \
             Corroboration evidence, not a verdict; nothing here means an action was taken."
        }
    }
}

/// The list of alarming-now events, one card each. A real list for semantics (accessibility).
fn alerts_list(alerts: &[AlertProps]) -> Markup {
    html! {
        ul.alerts-list aria-label="alarming-now signals" {
            @for a in alerts {
                (alert_card(a))
            }
        }
    }
}

/// One alarming-now event card: the signal (with its kind token carrying the kind without colour),
/// the workload it was attributed to, its recency, and the proven breach-relevant chain it is
/// alarming ON (if any). Deliberately NOT the word "corroborates": the engine reserves the
/// corroboration axis for the Alert-only subset that flips `ProvenChain::corroborated` (ADR-0009), so
/// a context-class signal (notable exec / alarming write / foothold-peer contact) is only named as
/// "alarming on the chain", never as corroborating it. Every untrusted string (signal / workload /
/// chain) is auto-escaped by maud (`{}`, never `PreEscaped`).
fn alert_card(a: &AlertProps) -> Markup {
    html! {
        li class={ "alert-card alert-" (a.kind) } {
            div.alert-head {
                span class={ "alert-kind kind-" (a.kind) } { (a.kind) }
                span.alert-signal { (a.signal) }
            }
            div.alert-meta.muted {
                span.alert-workload {
                    span.alert-label { "workload " }
                    (a.workload)
                }
                span.alert-recency { (a.recency) }
                @match &a.on_chain {
                    Some(chain) => span.alert-on-chain {
                        span.alert-label { "alarming on the chain " }
                        (chain)
                    }
                    None => span.alert-on-chain.muted {
                        "no proven chain \u{2014} alarming on its own"
                    }
                }
            }
        }
    }
}

/// The honest empty/quiet state. CALM by default — "no alarming activity right now" is reassuring,
/// not an alarm, and NOT an error state. But when a node is blind (JEF-308) the reassurance would be
/// dishonest — absence of a signal is not evidence of safety — so the caveat replaces the all-quiet
/// copy and the state reads elevated, never green.
fn empty_state(v: &AlertsViewProps) -> Markup {
    if let Some(caveat) = &v.blind_caveat {
        return html! {
            div.empty.empty-alerts-blind {
                p.empty-head { "quiet \u{2014} but partly blind" }
                p.empty-sub.blind-node-caveat role="note" {
                    span.caveat-glyph aria-hidden="true" { "\u{26A0} " } // ⚠
                    (caveat)
                }
            }
        };
    }
    html! {
        div.empty.empty-alerts-calm {
            p.empty-head { "no alarming activity right now" }
            p.empty-sub.muted {
                "no runtime signal is alarming this pass \u{2014} nothing is showing active \
                 attack behaviour right now. This is a live window, not a history."
            }
        }
    }
}
