//! The read-only, token-claim-bound tiered-redaction **MCP server** (ADR-0031 / JEF-488): the
//! pull-side sibling of the ADR-0018 breach notifier, and the second sanctioned egress carve-out.
//! Served on its OWN bind (`PROTECTOR_MCP_ADDR`, opt-in like the dashboard; unset = not served),
//! riding the SAME OIDC verifier as the dashboard (ADR-0030) and the SAME shared redaction module
//! (`super::redact`, ADR-0018/0031).
//!
//! The surface is exactly **four READ-ONLY tools** — `list_findings`, `explain_verdict`,
//! `get_coverage`, `signing_inventory` — and NO actuation tool exists BY CONSTRUCTION (ADR-0031 §1:
//! the view can never become an actuation surface, ADR-0016 shadow-first).
//!
//! Every trust decision stays in OUR code, above rmcp (ADR-0031 §6):
//!
//! - **verify** — [`transport::mcp_auth`] runs the shared [`super::dashboard::auth::authenticate`]
//!   seam; an unauthenticated call is a `401` on the same path as `/api`, before rmcp is reached;
//! - **tier ceiling** — [`tiering::EffectiveTier::clamp`] derives the tier from the VERIFIED token
//!   claim and clamps `min(requested, ceiling)` — the request arg can only narrow;
//! - **redact** — [`render`] applies the shared scrubbers PER ENTRY with the withheld-not-omitted
//!   sentinel + manifest contract;
//! - **journal** — [`audit`] appends a subject-bound line for every forensic/raw disclosure (the
//!   durable sink + "Access" tab are JEF-490; this is the seam it wires into).
//!
//! rmcp ([`server`] adapter + [`transport`] mount) is transport BELOW the boundary; it frames
//! JSON-RPC and speaks the discovery/challenge handshake, and makes no trust decision.

pub mod access_audit;
pub mod audit;
mod dispatch;
mod render;
mod server;
mod state;
mod tiering;
mod tools;
mod transport;

pub use access_audit::{AccessAuditSink, AccessRecord};
pub use state::McpState;
pub use tiering::EffectiveTier;
pub use tools::BULK_SCOPE;
pub use transport::{MCP_PATH, WELL_KNOWN_PATH, serve_mcp};

/// The sentinel a `redacted`-tier viewer sees in place of a withheld workload identity — the SAME
/// string the tool emits (`render::S_ENTRY`, JEF-488), re-exported so the "Access" screen (JEF-490)
/// redacts a pull's target-class with ONE shared vocabulary across tool + screen.
pub use render::S_ENTRY as WORKLOAD_IDENTITY_WITHHELD;

#[cfg(test)]
mod tests;
