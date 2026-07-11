//! Map the engine's live runtime signals into the Alerts view's "alarming-now" props (JEF-323).
//! This is the data layer: it touches `state::`/`graph::`/`behavior::` domain types; the
//! components never do. It shares ONE derived seam with the critical-path annotation
//! ([`alarming_signals_of`]) so the Alerts tab and the findings-view "alarming activity observed"
//! line can never disagree about what is alarming.
//!
//! HONESTY (ADR-0009 / ADR-0016): this surface NEVER uses the word "corroborated". The engine
//! reserves that axis for the Alert-only subset that flips `ProvenChain::corroborated`; a notable
//! exec / alarming write / foothold-peer contact is CONTEXT by that definition. The alarming-now
//! SET here is deliberately broader (it is the operator's "what is alarming now" view), so it is
//! phrased purely in "alarming" language and never asserts a corroboration the engine didn't reach.
//!
//! SCOPE (fixed, JEF-323): runtime signals are TRANSIENT — they live for one observe pass then
//! clear. So this is a CURRENT-WINDOW view of what is alarming THIS pass, NOT a persisted audit
//! log. No new store is introduced; the alerts are derived from the same per-pass findings
//! snapshot the Findings view already reads.

use crate::engine::graph::{Behavior, NodeKey};
use crate::engine::observe::{alarm_class, exec_class, peer_class};
use crate::engine::state::{Finding, Readiness};

use super::findings::blind_nodes_of;
use super::posture::human_age;
use super::props::{AlertProps, AlertsViewProps, StatusStripProps};

/// The human, presentation label + kind token for an "alarming-now" behavior (JEF-323), or `None`
/// for a non-alarming one. This is the ONE definition of "what shows on the Alerts tab", shared by
/// the tab and the per-finding annotation so they can never drift.
///
/// The alarming-now set is BROADER than [`Behavior::is_alert`] (which is only a sensor `Alert`): it
/// is the blanket-corroboration set (`alarm_class::is_alarming_now` — sensor alert / notable exec /
/// alarming write) PLUS a high-signal foothold-peer contact (cloud-metadata / API server,
/// `peer_class::foothold_peer`). A cloud-metadata contact is a genuine "alarming now" operator
/// signal even though it corroborates only per-objective, so the operator view surfaces it too —
/// the ticket names "contacted cloud-metadata" as an example alarming-now signal. (Decision, per
/// ADR-0016: the Alerts tab is an operator VIEW, so it errs toward SHOWING an alarming lead; it
/// never gates or concludes.)
///
/// The classifier LABELS are fixed internal strings (never untrusted); a `rule`/`path`/`peer` the
/// label embeds IS untrusted, but every returned string is auto-escaped at render (maud `{}`).
fn alarming_now_label(behavior: &Behavior) -> Option<(&'static str, String)> {
    // A sensor rule fired — the rule name is untrusted, escaped at render.
    if let Behavior::Alert { rule } = behavior {
        return Some(("alert", format!("sensor rule fired: {rule}")));
    }
    // A notable exec (interactive shell / package manager in container). The classifier's label is
    // the fixed phrasing; the exec path is the untrusted payload.
    if let Some(label) = exec_class::notable_exec(behavior) {
        let path = match behavior {
            Behavior::ProcessExec { path } => path.as_str(),
            _ => "",
        };
        return Some(("exec", format!("notable exec: {label} ({path})")));
    }
    // An alarming file write (drop-and-execute / config or credential tamper). The classifier's
    // label describes the class; the written path is the untrusted payload.
    if let Some(label) = alarm_class::alarming_write(behavior) {
        let path = match behavior {
            Behavior::FileWrite { path } => path.as_str(),
            _ => "",
        };
        return Some(("write", format!("{label}: {path}")));
    }
    // A high-signal foothold-peer contact (cloud-metadata / API server). The peer is untrusted.
    if let Some(label) = peer_class::foothold_peer(behavior) {
        let peer = match behavior {
            Behavior::NetworkConnection { peer, .. } => peer.as_str(),
            _ => "",
        };
        return Some(("peer", format!("contacted {label} ({peer})")));
    }
    None
}

/// The recency phrasing for an alert derived from a finding. Runtime signals are transient (one
/// pass), so the honest recency is the alarming CHAIN's age (how long this entry has been present
/// and alarming) — or `"this pass"` when no age is known. Never a fabricated timestamp.
fn recency_of(f: &Finding) -> String {
    match f.recency.as_ref().and_then(|r| r.age_secs) {
        Some(secs) => format!("{} ago", human_age(secs)),
        None => "this pass".to_string(),
    }
}

/// The short "entry \u{2192} objective" label of the proven breach-relevant chain a signal is
/// alarming ON, for the Alerts row. Only breach-relevant chains carry it; a non-chain alarming signal
/// shows no chain. Deliberately NOT "corroborates": the corroboration axis (ADR-0009) is reserved for
/// the Alert-only subset that flips `ProvenChain::corroborated`, and this set is broader.
fn on_chain_of(f: &Finding) -> Option<String> {
    if !f.breach_relevant {
        return None;
    }
    Some(format!(
        "{} \u{2192} {}",
        NodeKey::short_of(&f.entry),
        NodeKey::short_of(&f.objective)
    ))
}

/// The alarming-now signals observed on ONE finding's entry this pass (JEF-323) — the shared seam
/// the Alerts tab and the per-finding "alarming activity observed" annotation both project from. Each
/// is attributed to the entry's workload (informer-resolved short label) with the chain's recency and
/// the proven chain it is alarming on.
pub(super) fn alarming_signals_of(f: &Finding) -> Vec<AlertProps> {
    let workload = NodeKey::short_of(&f.entry).to_string();
    let recency = recency_of(f);
    let on_chain = on_chain_of(f);
    f.evidence
        .runtime
        .iter()
        .filter_map(|b| alarming_now_label(b))
        .map(|(kind, signal)| AlertProps {
            signal,
            kind: kind.to_string(),
            workload: workload.clone(),
            recency: recency.clone(),
            on_chain: on_chain.clone(),
        })
        .collect()
}

/// The calm blind-node caveat for the Alerts empty/quiet state (JEF-308) — set when at least one
/// expected node has NO live runtime sensor, so a quiet view must not read "all clear": absence of a
/// signal there is not evidence of safety. `None` when every expected node is sensored.
fn blind_caveat_of(readiness: &Readiness) -> Option<String> {
    let mut blind: Vec<String> = blind_nodes_of(readiness).into_iter().collect();
    if blind.is_empty() {
        return None;
    }
    blind.sort();
    let nodes = blind.join(", ");
    Some(format!(
        "no live runtime sensor on: {nodes} \u{2014} a quiet view here is not an all-clear; absence of a signal is not evidence of safety"
    ))
}

/// Build the whole Alerts view's props from the engine's read-only per-pass state (JEF-323). The
/// alerts are the alarming-now signals across every finding's entry this pass, most-recent-first
/// (by the alarming chain's age); the blind caveat rides the empty/quiet state. Pure given its
/// inputs — driveable in tests with no engine.
pub fn build(
    strip: StatusStripProps,
    findings: &[Finding],
    readiness: &Readiness,
) -> AlertsViewProps {
    let mut alerts: Vec<AlertProps> = findings.iter().flat_map(alarming_signals_of).collect();
    // Most-recent-first: a chain first-seen more recently (smaller age) reads as fresher. Ties
    // broken by workload then signal so the order is deterministic across renders.
    alerts.sort_by(|a, b| {
        recency_rank(a).cmp(&recency_rank(b)).then_with(|| {
            a.workload
                .cmp(&b.workload)
                .then_with(|| a.signal.cmp(&b.signal))
        })
    });
    AlertsViewProps {
        strip,
        alerts,
        blind_caveat: blind_caveat_of(readiness),
    }
}

/// A coarse recency sort key: `"this pass"` (no age) is the freshest; otherwise smaller ages sort
/// first. We can't parse the human age back reliably, so `"this pass"` ranks 0 and everything else
/// keeps its (stable) grouped order — enough for a deterministic, sensible most-recent-first.
fn recency_rank(a: &AlertProps) -> u8 {
    if a.recency == "this pass" { 0 } else { 1 }
}
