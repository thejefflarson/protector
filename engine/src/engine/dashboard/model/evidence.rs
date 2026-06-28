//! The per-entry evidence view projections (JEF-133 + JEF-244): [`CveEvidence`],
//! [`FindingEvidence`], and the [`EntryEvidence`] aggregate the dashboard renders and the
//! `/findings` JSON serializes. Split out of the `model` root purely to keep every file under
//! the 1,000-line cap (CLAUDE.md). These are projections of the graph's domain types, read
//! through the SAME `SecurityGraph::entry_evidence` / `entry_findings` the adjudicator uses,
//! so the model and the operator can never see a different set of facts.

use serde::Serialize;

use crate::engine::graph::{Behavior, ScanFinding, SecurityGraph, Vulnerability};

/// A single CVE on the entry's image, the dashboard-/JSON-facing projection of a
/// [`graph::Vulnerability`] (JEF-133). The same fields `cve_evidence` surfaces to the
/// model: id, severity, the CVSS score when trivy reported it (JEF-242), reachability,
/// fix availability, and the trivy title. ADR-0016: this is a SEVERITY/reachability input
/// — "how bad IF exploited" — never on its own the breach call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CveEvidence {
    pub id: String,
    /// `low` / `medium` / `high` / `critical` (from [`graph::Severity::label`]).
    pub severity: String,
    /// The CVSS base score trivy reported (JEF-242), if any, formatted to one decimal
    /// (`"9.8"`) — the same static-severity signal the model is shown. `None` when the
    /// scanner omits it. Stored pre-formatted (a `String`, not an `f64`) so the dashboard
    /// props can keep `Eq` and the operator reads the exact token the prompt rendered.
    pub score: Option<String>,
    /// Whether the CVE is listed in a known-exploited catalogue (CISA KEV) — the
    /// stronger-than-severity exploitation signal.
    pub kev: bool,
    /// `unknown` / `loaded-at-runtime` / `not-observed` (from [`graph::Reachability`]).
    pub reachability: String,
    /// A human fix-availability phrase: `no fix available`, `fix available: <ver>`, or
    /// `fix available: <installed> to <fixed>` — the same shape the prompt uses.
    pub fix: String,
    /// The advisory title (trivy's `title`), if reported. Untrusted free-text — HTML-
    /// escaped at render time like every other model-adjacent string.
    pub title: Option<String>,
}

impl CveEvidence {
    /// Project a graph [`Vulnerability`] into the view shape. Keeps the fix-availability
    /// phrasing identical to the adjudicator's `cve_evidence` so the operator reads the
    /// same fact the model did.
    pub(crate) fn from_vuln(v: &Vulnerability) -> Self {
        let fix = match (v.fixed_version.as_deref(), v.installed_version.as_deref()) {
            (Some(fixed), Some(installed)) => format!("fix available: {installed} to {fixed}"),
            (Some(fixed), None) => format!("fix available: {fixed}"),
            (None, _) => "no fix available".to_string(),
        };
        CveEvidence {
            id: v.id.clone(),
            severity: v.severity.label().to_string(),
            // Format to one decimal so the dashboard shows the SAME `cvss` token the prompt
            // renders (JEF-242) and the projection stays `Eq`.
            score: v.score.map(|s| format!("{s:.1}")),
            kev: v.exploited_in_wild,
            reachability: v.reachability.label().to_string(),
            fix,
            title: v.title.clone(),
        }
    }
}

/// A non-CVE scanner finding on the entry, the dashboard-/JSON-facing projection of a
/// [`graph::ScanFinding`] (JEF-244): an exposed secret, a config-audit misconfiguration, or
/// an RBAC-assessment finding. The same STRUCTURED coordinates the model is shown — id,
/// severity, category, and a short untrusted title. For an exposed secret the title carries
/// trivy's already-REDACTED match only; the raw secret value is never in this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingEvidence {
    /// The scanner rule/check id (`aws-access-key-id`, `KSV017`) — surfaced verbatim.
    pub id: String,
    /// `low` / `medium` / `high` / `critical`.
    pub severity: String,
    /// The scanner's category, if any.
    pub category: Option<String>,
    /// A short title/description — untrusted free-text, HTML-escaped at render like a CVE
    /// title. For an exposed secret this is the REDACTED match, never the secret value.
    pub title: Option<String>,
}

impl FindingEvidence {
    pub(crate) fn from_finding(f: &ScanFinding) -> Self {
        FindingEvidence {
            id: f.id.clone(),
            severity: f.severity.label().to_string(),
            category: f.category.clone(),
            title: f.title.clone(),
        }
    }
}

/// The two evidence blocks ADR-0016 keeps distinct, attached to a finding's entry
/// (JEF-133):
///
/// - `cves` — the entry image's foothold-relevant CVEs (KEV or critical), the
///   SEVERITY/reachability input.
/// - `runtime` — the runtime [`Behavior`]s observed on the entry, the LIVE-corroboration
///   signal. The subset that actually *corroborates* (Falco-style `Alert`s) is what flips
///   `corroborated`; non-corroborating agent behaviors (exec/connect/secret-read/library-
///   load/privilege-change) ride along as context, exactly as the model sees them.
///
/// Both empty is the honest "no evidence" state (render shows "none" / "unknown", never
/// an implied-absent blank — JEF-161 coverage-gap idiom).
#[derive(Debug, Clone, Default, Serialize)]
pub struct EntryEvidence {
    pub cves: Vec<CveEvidence>,
    pub runtime: Vec<Behavior>,
    /// Exposed secrets baked into the entry's image (JEF-244) — the EXPLOITATION-grade
    /// exposure block. Empty when trivy-operator's `ExposedSecretReport`s are absent.
    pub exposed_secrets: Vec<FindingEvidence>,
    /// Config-audit misconfigurations on the entry's workload (JEF-244) — static posture.
    pub misconfigs: Vec<FindingEvidence>,
    /// RBAC-assessment findings on the entry's namespace (JEF-244) — structural RBAC
    /// exposure that informs (does not double-count) the JEF-79 authorization reasoning.
    pub rbac_findings: Vec<FindingEvidence>,
}

impl EntryEvidence {
    /// Pull the entry's evidence from the graph — the SAME selection the adjudicator
    /// reads ([`SecurityGraph::entry_evidence`]: KEV-or-critical CVEs + the entry's
    /// runtime behaviors, plus the JEF-244 scanner findings from
    /// [`SecurityGraph::entry_findings`]), projected into the view shape.
    pub(crate) fn for_entry(graph: &SecurityGraph, entry: &crate::engine::graph::NodeKey) -> Self {
        let (vulns, runtime) = graph.entry_evidence(entry);
        let (secrets, misconfigs, rbac) = graph.entry_findings(entry);
        let project = |fs: &[ScanFinding]| fs.iter().map(FindingEvidence::from_finding).collect();
        EntryEvidence {
            cves: vulns.iter().map(CveEvidence::from_vuln).collect(),
            runtime,
            exposed_secrets: project(&secrets),
            misconfigs: project(&misconfigs),
            rbac_findings: project(&rbac),
        }
    }

    /// The runtime behaviors that actually corroborate the chain (Falco-style alerts) —
    /// what flips `ProvenChain::corroborated` (ADR-0009). Separated from context behaviors
    /// in the live-corroboration block.
    pub(crate) fn corroborating(&self) -> impl Iterator<Item = &Behavior> {
        self.runtime.iter().filter(|b| b.is_alert())
    }

    /// The non-corroborating agent behaviors — context for the chain, not a corroboration
    /// (exec/connect/secret-read/library-load/privilege-change). Shown for context.
    pub(crate) fn context_behaviors(&self) -> impl Iterator<Item = &Behavior> {
        self.runtime.iter().filter(|b| !b.is_alert())
    }
}
