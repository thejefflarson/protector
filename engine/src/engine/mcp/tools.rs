//! The four READ-ONLY tools (ADR-0031 §1, JEF-488). There is NO fifth tool and NO actuation tool —
//! not a permission withheld at runtime, but a surface that DOES NOT EXIST (§1: the view cannot
//! become an actuation surface, ADR-0016 shadow-first). Every tool is a pure read over the SAME
//! `state::` handles the dashboard serves, redacted PER ENTRY to the (already clamped) effective
//! tier.
//!
//! Tier CAPS (ADR-0031 acceptance "per-entry only — no dump-all-at-raw"): the three BULK tools cap
//! at `forensic`, so secret NAMES are never emitted in a bulk response; raw secret names are
//! reachable ONLY per-entry through [`explain_verdict`].

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::engine::redact::sanitize;
use crate::engine::state::Finding;

use super::render::{self, EntryData, Withheld};
use super::state::McpState;
use super::tiering::EffectiveTier;

/// The tool name for the findings snapshot.
pub const LIST_FINDINGS: &str = "list_findings";
/// The tool name for a single entry's verdict explanation.
pub const EXPLAIN_VERDICT: &str = "explain_verdict";
/// The tool name for the runtime-coverage / freshness read.
pub const GET_COVERAGE: &str = "get_coverage";
/// The tool name for the signing posture read.
pub const SIGNING_INVENTORY: &str = "signing_inventory";

/// The COMPLETE, exhaustive tool set — exactly four reads. A test asserts this is the whole surface
/// (no mutation/actuate method). The order is the ADR-0031 §1 order. Test-only: the live surface is
/// [`ProtectorMcp::tool_descriptors`](super::server::ProtectorMcp::tool_descriptors); this const
/// exists so a test can pin the count independently.
#[cfg(test)]
pub const TOOL_NAMES: [&str; 4] = [
    LIST_FINDINGS,
    EXPLAIN_VERDICT,
    GET_COVERAGE,
    SIGNING_INVENTORY,
];

/// The image-observation subject prefix on the admission-decision log (mirrors the signing sweep,
/// JEF-261) — the rows the signing inventory is derived from.
const IMAGE_SUBJECT_PREFIX: &str = "Image/";

/// Why a tool call could not be served — a routing/validation failure, never a redaction leak.
#[derive(Debug, PartialEq, Eq)]
pub enum ToolError {
    /// The `entry` argument didn't match any known breach-relevant entry key or opaque ref
    /// (ADR-0031 §3: validate against known entry keys; never index arbitrary state).
    UnknownEntry,
    /// A required argument was missing or the wrong JSON type.
    BadArguments(&'static str),
    /// The tool name is not one of the four reads.
    UnknownTool,
}

/// The audit scope label for the three bulk tools (no single entry — the whole current snapshot).
/// `explain_verdict`'s scope is the resolved entry instead.
pub const BULK_SCOPE: &str = "(all findings)";

/// `list_findings` — the current breach-relevant findings, grouped per entry and redacted to `tier`
/// (capped at `forensic` by the dispatcher). Never a bulk raw dump.
pub fn list_findings(state: &McpState, tier: EffectiveTier) -> Value {
    let findings = state.findings();
    let judgements = state.judgements();
    let blind = blind_nodes(state);

    let groups = group_by_entry(&findings);
    let entries: Vec<EntryData> = groups
        .iter()
        .map(|(entry, group)| {
            let judgement = judgements.iter().find(|j| &j.entry == entry);
            let is_blind = group
                .iter()
                .any(|f| f.node.as_deref().is_some_and(|n| blind.contains(n)));
            EntryData::from_group(entry, group, judgement, is_blind)
        })
        .collect();

    let rendered: Vec<Value> = entries.iter().map(|e| e.render(tier)).collect();
    let withheld = render::withheld_for(&entries, tier);
    json!({
        "cluster": sanitize(&state.cluster),
        "count": rendered.len(),
        "findings": rendered,
        "redaction": render::manifest(tier, &withheld),
    })
}

/// `explain_verdict` — one entry's verdict + why, at `tier` (may reach `raw` — the ONLY per-entry
/// raw path). `entry_arg` is validated against the known entry set (raw key OR opaque ref); an
/// unknown value is [`ToolError::UnknownEntry`], never an index into arbitrary state. Returns the
/// rendered value AND the resolved entry key (for the audit line).
pub fn explain_verdict(
    state: &McpState,
    entry_arg: &str,
    tier: EffectiveTier,
) -> Result<(Value, String), ToolError> {
    let findings = state.findings();
    let judgements = state.judgements();
    let blind = blind_nodes(state);

    let groups = group_by_entry(&findings);
    let (entry, group) = groups
        .iter()
        .find(|(entry, _)| entry.as_str() == entry_arg || render::entry_ref(entry) == entry_arg)
        .ok_or(ToolError::UnknownEntry)?;

    let judgement = judgements.iter().find(|j| &j.entry == entry);
    let is_blind = group
        .iter()
        .any(|f| f.node.as_deref().is_some_and(|n| blind.contains(n)));
    let data = EntryData::from_group(entry, group, judgement, is_blind);

    let withheld = render::withheld_for(std::slice::from_ref(&data), tier);
    let value = json!({
        "cluster": sanitize(&state.cluster),
        "finding": data.render(tier),
        "redaction": render::manifest(tier, &withheld),
    });
    Ok((value, entry.clone()))
}

/// `get_coverage` — the runtime-coverage / freshness read (is protector blind on a node, how stale
/// is what it last saw). Redacted: per-input state + counts + freshness. Forensic+: the per-node
/// breakdown (node NAMES are topology). Capped at `forensic`.
pub fn get_coverage(state: &McpState, tier: EffectiveTier) -> Value {
    let readiness = state.readiness();
    let last_pass = state
        .last_pass()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());

    let inputs: Vec<Value> = readiness
        .inputs
        .iter()
        .map(|row| {
            let node_field = if row.nodes.is_empty() {
                Value::Null
            } else if tier >= EffectiveTier::Forensic {
                let nodes: Vec<Value> = row
                    .nodes
                    .iter()
                    .map(|n| json!({ "node": sanitize(&n.node), "state": n.state, "detail": sanitize(&n.detail) }))
                    .collect();
                json!({ "count": row.nodes.len(), "nodes": nodes })
            } else {
                json!({ "count": row.nodes.len(), "nodes": "[redacted — node names; forensic tier required]" })
            };
            json!({
                "id": row.id,
                "label": row.label,
                "state": row.state,
                "detail": sanitize(&row.detail),
                "weakens_decisions": row.weakens_decisions,
                "coverage": node_field,
            })
        })
        .collect();

    let node_total: usize = readiness.inputs.iter().map(|r| r.nodes.len()).sum();
    let withheld = if tier < EffectiveTier::Forensic {
        vec![Withheld {
            kind: "node_names",
            count: node_total,
            unlock: "forensic",
        }]
    } else {
        vec![]
    };
    json!({
        "cluster": sanitize(&state.cluster),
        "last_pass_unix_secs": last_pass,
        "inputs": inputs,
        "redaction": render::manifest(tier, &withheld),
    })
}

/// `signing_inventory` — the ADR-0020 signing posture: how many images are signed / unsigned, and
/// how many repos regressed. Redacted: counts only. Forensic+: the per-image refs (image refs are
/// paths). Capped at `forensic`.
pub fn signing_inventory(state: &McpState, tier: EffectiveTier) -> Value {
    let rows = state.policy_log.snapshot();
    let (established, cold) =
        crate::engine::dashboard::view_model::signing_regression_counts(&rows);

    let mut signed = 0usize;
    let mut unsigned = 0usize;
    let mut other = 0usize;
    let mut images: Vec<Value> = Vec::new();
    for r in &rows {
        let Some(image_ref) = r.subject.strip_prefix(IMAGE_SUBJECT_PREFIX) else {
            continue;
        };
        match r.signature.as_str() {
            "signed" => signed += 1,
            "not-signed" | "invalid-signature" => unsigned += 1,
            _ => other += 1,
        }
        if tier >= EffectiveTier::Forensic {
            images.push(json!({ "ref": sanitize(image_ref), "posture": sanitize(&r.signature) }));
        }
    }

    let images_field = if tier >= EffectiveTier::Forensic {
        json!(images)
    } else {
        json!("[redacted — image references; forensic tier required]")
    };
    let withheld = if tier < EffectiveTier::Forensic {
        vec![Withheld {
            kind: "image_refs",
            count: signed + unsigned + other,
            unlock: "forensic",
        }]
    } else {
        vec![]
    };
    json!({
        "cluster": sanitize(&state.cluster),
        "images_observed": signed + unsigned + other,
        "images_signed": signed,
        "images_unsigned": unsigned,
        "images_other": other,
        "regressions": { "established": established, "cold": cold },
        "images": images_field,
        "redaction": render::manifest(tier, &withheld),
    })
}

/// The set of runtime-blind node names (JEF-308) from the readiness runtime-corroboration row.
fn blind_nodes(state: &McpState) -> std::collections::HashSet<String> {
    let readiness = state.readiness();
    readiness
        .inputs
        .iter()
        .find(|r| r.id == "runtime-corroboration")
        .map(|r| {
            r.nodes
                .iter()
                .filter(|n| matches!(n.state, crate::engine::state::NodeCoverageState::Blind))
                .map(|n| n.node.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// Group the breach-relevant findings by their entry key, preserving a deterministic (sorted) entry
/// order so responses are stable. Only breach-relevant findings are surfaced — the same filter the
/// dashboard applies.
fn group_by_entry(findings: &[Finding]) -> Vec<(String, Vec<&Finding>)> {
    let mut map: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings.iter().filter(|f| f.breach_relevant) {
        map.entry(f.entry.clone()).or_default().push(f);
    }
    map.into_iter().collect()
}
