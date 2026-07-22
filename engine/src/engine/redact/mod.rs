//! Shared redaction primitives (ADR-0031) — the egress-safety scrubbers lifted out of the
//! breach notifier (ADR-0018, `super::notify`) so the notifier AND the read-only MCP server
//! share ONE implementation and cannot drift in what they consider safe to emit off-cluster.
//!
//! Redaction is layered, and the layers are independent so a caller can compose exactly the
//! ones its egress tier permits (ADR-0031 §2 expresses each tier as "which scrubbers run"):
//!
//! - [`sanitize`] — strip prompt/wire STRUCTURE (fences, braces, backtick, CR/LF). Always
//!   applied; also the adjudication-prompt defense (ADR-0011).
//! - [`scrub_decision_names`] — strip the SEMANTIC names a model can echo into prose (the
//!   decision's own secret/peer names). The MCP `raw` tier relaxes this one.
//! - [`scrub_cve_tokens`] — strip `CVE-…` tokens from prose. The MCP `forensic` tier
//!   relaxes this one.
//! - [`redacted_attack_outcome`] — reduce reached ATT&CK refs to the counts-only outcome
//!   (which techniques, never the per-objective targets).
//!
//! None of them can emit a secret VALUE: no function here reads one — values have no path.
//!
//! Submodules are kept small and single-purpose (repo CLAUDE.md file-size cap).

mod outcome;
mod sanitize;
mod scrub;

pub(crate) use outcome::redacted_attack_outcome;
pub(crate) use sanitize::sanitize;
pub(crate) use scrub::{scrub_cve_tokens, scrub_decision_names};

#[cfg(test)]
mod tests;
