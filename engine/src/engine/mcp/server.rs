//! The rmcp [`ServerHandler`] adapter (ADR-0031 §6, JEF-488). rmcp is transport BELOW the trust
//! boundary: this shell only (1) advertises the four tool descriptors, (2) reads the VERIFIED
//! [`Identity`] the OIDC auth layer inserted into the request extensions — which rmcp propagates
//! into the tool [`RequestContext`] as `http::request::Parts` — and (3) hands the ceiling + subject
//! to [`dispatch`], which owns every trust decision (clamp, redact, journal). rmcp makes NO trust
//! decision.
//!
//! Fail-closed: if no verified `Identity` is present (it always is behind the auth layer — this is
//! defense in depth), the handler serves NOTHING; it never falls back to a permissive tier.

use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResult, JsonObject, ListToolsResult, PaginatedRequestParams,
    ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::json;

use crate::engine::dashboard::auth::Identity;
use crate::engine::dashboard::auth::claims::Tier;

use super::audit::AuditSink;
use super::dispatch::dispatch;
use super::state::McpState;
use super::tools::{self, ToolError};

/// The read-only MCP server handler: the engine state to read, and the audit sink for
/// forensic/raw disclosures.
#[derive(Clone)]
pub struct ProtectorMcp {
    state: McpState,
    audit: Arc<dyn AuditSink>,
}

impl ProtectorMcp {
    /// Build the handler over the engine state + the audit sink JEF-490 will make durable.
    pub fn new(state: McpState, audit: Arc<dyn AuditSink>) -> Self {
        Self { state, audit }
    }

    /// The four tool descriptors (ADR-0031 §1) — the COMPLETE surface. No actuation tool exists.
    pub fn tool_descriptors() -> Vec<Tool> {
        vec![
            Tool::new(
                tools::LIST_FINDINGS,
                "List the current breach-relevant findings (verdicts + the fields the active tier \
                 permits). Read-only.",
                tier_only_schema(),
            ),
            Tool::new(
                tools::EXPLAIN_VERDICT,
                "Explain one entry's verdict and the evidence behind it, at the requested tier. \
                 The only per-entry path to raw detail. Read-only.",
                explain_schema(),
            ),
            Tool::new(
                tools::GET_COVERAGE,
                "Report runtime coverage / freshness: is protector blind on a node, and how stale \
                 is what it last saw. Read-only.",
                tier_only_schema(),
            ),
            Tool::new(
                tools::SIGNING_INVENTORY,
                "Report the image-signing posture: how many images are signed / unsigned and which \
                 repos regressed. Read-only.",
                tier_only_schema(),
            ),
        ]
    }

    /// Resolve the VERIFIED identity from the request extensions rmcp propagated from the HTTP
    /// request (the `Identity` the OIDC auth layer inserted). `None` fails the call closed.
    fn identity(context: &RequestContext<RoleServer>) -> Option<&Identity> {
        context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<Identity>())
    }
}

impl ServerHandler for ProtectorMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "protector read-only security surface (ADR-0031): four read tools, no actuation. \
             Output is redacted to the tier your token grants; request a lower tier with the \
             `tier` argument.",
        )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(Self::tool_descriptors()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        // The ceiling + subject come ONLY from the verified token (never the request params).
        let Some(identity) = Self::identity(&context) else {
            // Behind the auth layer this is unreachable; treat a missing identity as fail-closed.
            return Ok(CallToolResult::structured_error(json!({
                "error": "unauthenticated",
                "detail": "no verified identity on the request",
            })));
        };
        let ceiling: Tier = identity.tier;
        let subject = identity.subject.as_str();

        match dispatch(
            &self.state,
            self.audit.as_ref(),
            subject,
            request.name.as_ref(),
            request.arguments.as_ref(),
            ceiling,
        ) {
            Ok(value) => Ok(CallToolResult::structured(value)),
            Err(ToolError::UnknownEntry) => Ok(CallToolResult::structured_error(json!({
                "error": "unknown_entry",
                "detail": "no such breach-relevant entry (validate against list_findings refs)",
            }))),
            Err(ToolError::BadArguments(detail)) => Ok(CallToolResult::structured_error(json!({
                "error": "bad_arguments",
                "detail": detail,
            }))),
            Err(ToolError::UnknownTool) => Err(ErrorData::invalid_params(
                "no such tool (the surface is exactly four read tools)",
                None,
            )),
        }
    }
}

/// The JSON-Schema for a tool taking only the optional `tier` argument.
fn tier_only_schema() -> Arc<JsonObject> {
    schema(json!({
        "type": "object",
        "properties": {
            "tier": {
                "type": "string",
                "enum": ["redacted", "forensic", "raw"],
                "description": "Requested disclosure tier; clamped to the token's granted ceiling.",
            }
        },
        "additionalProperties": false,
    }))
}

/// The JSON-Schema for `explain_verdict`: a required `entry` (raw key or opaque ref) + optional
/// `tier`.
fn explain_schema() -> Arc<JsonObject> {
    schema(json!({
        "type": "object",
        "properties": {
            "entry": {
                "type": "string",
                "description": "The entry key or the opaque `ref` from list_findings.",
            },
            "tier": {
                "type": "string",
                "enum": ["redacted", "forensic", "raw"],
                "description": "Requested disclosure tier; clamped to the token's granted ceiling.",
            }
        },
        "required": ["entry"],
        "additionalProperties": false,
    }))
}

/// Coerce a `serde_json` object value into the `Arc<JsonObject>` a [`Tool`] schema wants.
fn schema(value: serde_json::Value) -> Arc<JsonObject> {
    match value {
        serde_json::Value::Object(map) => Arc::new(map),
        _ => Arc::new(JsonObject::new()),
    }
}
