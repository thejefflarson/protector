//! The tolerant cut-choice parser, skeptic default (ADR-0034 D3). Mirrors
//! [`super::super::prompt::parse_verdict`]'s `{`…`}` extraction — any JSON/shape failure
//! degrades to [`IncidentDecision::uncertain`], never a panic, never a partial decision.
//!
//! The membership check is the real teeth ADR-0034 chose Option B for (over the rejected
//! mechanism-menu, whose "select the whole list" passed every check): ANY `contain`
//! element that doesn't exact-match the menu's selectable set degrades the WHOLE decision,
//! not just that one element — a partially hallucinated list is ungrounded reasoning, and
//! grounding is all-or-nothing here.

use serde_json::Value;

use crate::engine::graph::NodeKey;

use super::{Assessment, IncidentDecision, Menu};

/// Parse a model reply into an [`IncidentDecision`] against `menu` — the deterministic
/// menu this exact incident's prompt would have shown (ADR-0034 D3):
///
/// 1. Extract the first `{`…last `}`; any JSON parse failure → `Uncertain`, no cuts.
/// 2. `assessment` out of the closed `{attack, no_attack, uncertain}` vocabulary →
///    `Uncertain`, no cuts (carrying the model's own `reason` when present).
/// 3. `contain` absent → `[]` (not a degrade). Present but not an array, or containing a
///    non-string element → `Uncertain`, no cuts.
/// 4. Each element is normalized (trimmed, `<<< >>>` fencing stripped) and exact-matched
///    against the menu's selectable node keys; ANY non-member → `Uncertain`, no cuts for
///    the WHOLE decision.
/// 5. The surviving node keys are deduped + sorted, then resolved through `menu` — never
///    carried as model text (ADR-0034 D1).
/// 6. `assessment ∈ {no_attack, uncertain}` with a non-empty (post-membership) `contain` →
///    `Uncertain`, no cuts + re-judge (an assessment that says "not an attack" naming a
///    cut is internally contradictory).
/// 7. Otherwise the parsed `(assessment, reason, cuts)` stands — `Attack` with an EMPTY
///    `contain` is VALID (D1 — "attack, but no cut warranted").
pub fn parse_incident_decision(reply: &str, menu: &Menu) -> IncidentDecision {
    let Some(object) = extract_object(reply) else {
        return IncidentDecision::uncertain("unparseable model reply");
    };

    let reason = object["reason"].as_str().unwrap_or("").to_string();

    let Some(assessment) = parse_assessment(&object) else {
        return IncidentDecision::uncertain(reason);
    };

    let Some(raw_contain) = parse_contain(&object) else {
        return IncidentDecision::uncertain(reason);
    };

    let mut nodes: Vec<NodeKey> = Vec::with_capacity(raw_contain.len());
    for raw in &raw_contain {
        match menu.node_for(&normalize(raw)) {
            Some(node) => nodes.push(node),
            // Any non-member degrades the WHOLE decision — a partially hallucinated
            // list is ungrounded reasoning, not a partially-trustworthy one.
            None => return IncidentDecision::uncertain(reason),
        }
    }
    nodes.sort();
    nodes.dedup();

    if matches!(assessment, Assessment::NoAttack | Assessment::Uncertain) && !nodes.is_empty() {
        return IncidentDecision::uncertain(reason);
    }

    let cuts = nodes.iter().filter_map(|n| menu.resolve(n)).collect();
    IncidentDecision {
        assessment,
        reason,
        cuts,
    }
}

/// Extract the first `{`…last `}` substring and parse it as JSON — mirrors
/// [`super::super::prompt::parse_verdict`]'s extraction exactly, so both parsers tolerate
/// the same surrounding prose a small model tends to wrap its JSON in.
fn extract_object(reply: &str) -> Option<Value> {
    reply
        .find('{')
        .zip(reply.rfind('}'))
        .and_then(|(start, end)| serde_json::from_str::<Value>(&reply[start..=end]).ok())
}

/// The `assessment` field, restricted to the closed 3-value vocabulary (ADR-0034 D2).
/// Anything else — missing, wrong type, or an unrecognized string — is out of range.
fn parse_assessment(object: &Value) -> Option<Assessment> {
    match object["assessment"].as_str().map(str::trim) {
        Some("attack") => Some(Assessment::Attack),
        Some("no_attack") => Some(Assessment::NoAttack),
        Some("uncertain") => Some(Assessment::Uncertain),
        _ => None,
    }
}

/// The `contain` field: absent is `Some(vec![])` (not a degrade — "empty array" and "the
/// field wasn't sent" are the same "nothing to contain"); present but not an array, or
/// containing any non-string element, is `None` (a degrade).
fn parse_contain(object: &Value) -> Option<Vec<String>> {
    match object.get("contain") {
        None => Some(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_string))
            .collect(),
        Some(_) => None,
    }
}

/// Normalize one `contain` element before the membership check: trim surrounding
/// whitespace, then strip an echoed `<<< >>>` fence (the model copies the fenced node key
/// verbatim from the menu; a small model sometimes echoes the fence delimiters too).
fn normalize(raw: &str) -> String {
    let mut s = raw.trim();
    if let Some(rest) = s.strip_prefix("<<<") {
        s = rest;
    }
    if let Some(rest) = s.strip_suffix(">>>") {
        s = rest;
    }
    s.trim().to_string()
}

#[cfg(test)]
#[path = "parse_tests.rs"]
mod tests;
