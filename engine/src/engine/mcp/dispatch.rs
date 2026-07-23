//! The trust core (JEF-488): tier clamp → per-tool cap → tool → journaled disclosure. This is the
//! layer that keeps EVERY trust decision in OUR code (ADR-0031 §6) — rmcp is only the transport that
//! calls [`dispatch`]. It is deliberately rmcp-free (takes a `serde_json` argument map and a
//! resolved ceiling), so the whole redaction/clamp/audit surface is unit-testable without the HTTP
//! stack.

use serde_json::{Map, Value};

use crate::engine::dashboard::auth::claims::Tier;

use super::audit::{AuditRecord, AuditSink};
use super::state::McpState;
use super::tiering::{EffectiveTier, parse_requested_tier};
use super::tools::{self, ToolError};

/// Run one tool call: derive the effective tier (clamp the requested arg to the token ceiling, then
/// apply the per-tool cap), invoke the tool, and — for any disclosure above `redacted` — append the
/// audit line bound to the verified `subject` (ADR-0031 §4). Returns the tool's JSON value, or a
/// [`ToolError`] for a routing/validation failure (unknown tool/entry, bad args).
pub fn dispatch(
    state: &McpState,
    sink: &dyn AuditSink,
    subject: &str,
    tool: &str,
    args: Option<&Map<String, Value>>,
    ceiling: Tier,
) -> Result<Value, ToolError> {
    let requested = parse_requested_tier(string_arg(args, "tier"));

    match tool {
        tools::LIST_FINDINGS => {
            let tier = EffectiveTier::clamp(requested, ceiling).capped_at(EffectiveTier::Forensic);
            let value = tools::list_findings(state, tier);
            audit(sink, subject, tools::BULK_SCOPE, tools::LIST_FINDINGS, tier);
            Ok(value)
        }
        tools::EXPLAIN_VERDICT => {
            // `explain_verdict` is the ONLY path that may reach `raw` — and only for ONE validated
            // entry (never a bulk dump).
            let tier = EffectiveTier::clamp(requested, ceiling);
            let entry = string_arg(args, "entry")
                .ok_or(ToolError::BadArguments("`entry` is required (string)"))?;
            let (value, resolved) = tools::explain_verdict(state, entry, tier)?;
            audit(sink, subject, &resolved, tools::EXPLAIN_VERDICT, tier);
            Ok(value)
        }
        tools::GET_COVERAGE => {
            let tier = EffectiveTier::clamp(requested, ceiling).capped_at(EffectiveTier::Forensic);
            let value = tools::get_coverage(state, tier);
            audit(sink, subject, tools::BULK_SCOPE, tools::GET_COVERAGE, tier);
            Ok(value)
        }
        tools::SIGNING_INVENTORY => {
            let tier = EffectiveTier::clamp(requested, ceiling).capped_at(EffectiveTier::Forensic);
            let value = tools::signing_inventory(state, tier);
            audit(
                sink,
                subject,
                tools::BULK_SCOPE,
                tools::SIGNING_INVENTORY,
                tier,
            );
            Ok(value)
        }
        _ => Err(ToolError::UnknownTool),
    }
}

/// Append the audit line for a forensic/raw disclosure; a `redacted` response discloses nothing
/// cluster-specific and is NOT journaled (ADR-0031 §4).
fn audit(
    sink: &dyn AuditSink,
    subject: &str,
    entry: &str,
    tool: &'static str,
    tier: EffectiveTier,
) {
    if tier.is_disclosure() {
        sink.emit(AuditRecord::now(subject, entry, tool, tier));
    }
}

/// Read a string argument from the tool call's argument map, or `None` when absent / not a string.
fn string_arg<'a>(args: Option<&'a Map<String, Value>>, key: &str) -> Option<&'a str> {
    args?.get(key).and_then(Value::as_str)
}
