//! The dashboard's page-composition + data render tests (ADR-0019): the `render_html` /
//! `render_fragment` composition, the `/fragment`⊂page parity seam, the AA-contrast +
//! incremental-poll asset hooks, and the report / readiness / store data behavior. They sit
//! at the dashboard module root — the only layer that composes the whole page over the model
//! and view_model data. The shared fixtures live here; each test lives in a numbered group
//! submodule, split purely to keep every file under the 1,000-line cap (repo CLAUDE.md).
#![allow(unused_imports)]

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use super::page::{FINDINGS_COLS, render_fragment, render_html};
use super::{DASHBOARD_CSS, DASHBOARD_JS, default_window_report};
use crate::engine::dashboard::model::{
    AUTO_ELIGIBLE, BakeStats, CveEvidence, EntryEvidence, Finding, Findings, Judgement,
    JudgementLog, ModelHealth, PathStep, ReadinessConfig, ReversionLog, ReversionRecord,
    VerdictStore, relative_time,
};
use crate::engine::dashboard::view_model::readiness_data::{
    InputState, Readiness, ReadinessRow, derive_readiness,
};
use crate::engine::dashboard::view_model::report_data::{
    LeftAloneEntry, Report, ReportQuery, WouldActEntry, aggregate_report, human_span,
    is_coverage_gap, verdict_would_act,
};
use crate::engine::graph::attack::{CREDENTIAL_ACCESS, EXPLOIT_PUBLIC_FACING};
use crate::engine::graph::{
    Behavior, NodeKey, Reachability, SecurityGraph, Severity, Vulnerability,
};
use crate::engine::journal::{Decision, DecisionJournal, EnrichmentCoverage, JournalEntry};
use crate::engine::reason::proof::{Link, ProvenChain};

mod group_1;
mod group_2;
mod group_3;
mod group_4;
mod guards;
mod recency;

/// A default readiness snapshot for the render tests that don't exercise the panel
/// itself — every input absent, post-warmup. The readiness-specific behavior is
/// covered by the dedicated JEF-160 tests below.
pub(super) fn ready() -> Readiness {
    derive_readiness(
        &ReadinessConfig::default(),
        ModelHealth::Unknown,
        &BakeStats::default(),
        Some(SystemTime::now()),
    )
}

pub(super) fn judgement(entry: &str) -> Judgement {
    Judgement {
        entry: entry.to_string(),
        objectives: 1,
        verdict: "Refuted(..)".to_string(),
        prompt: None,
        reply: None,
    }
}

/// A breach-relevant finding for one entry with no verdict of its own — the shape the
/// engine publishes (the verdict is resolved from the shared store at snapshot time).
pub(super) fn breach_finding(entry: &str) -> Finding {
    Finding {
        entry: entry.into(),
        objective: "secret/app/session-key".into(),
        tactic: "TA0006".into(),
        tactic_name: "Credential Access".into(),
        technique: "T1552".into(),
        technique_name: "Unsecured Credentials".into(),
        foothold: false,
        corroborated: false,
        adjudicated: true,
        promoted: false,
        disposition: "no-cut".into(),
        cut: None,
        breach_relevant: true,
        killchain: "T1552 Unsecured Credentials".into(),
        verdict: None,
        path: Vec::new(),
        evidence: EntryEvidence::default(),
        recency: None,
    }
}

pub(super) fn reversion(cut: &str) -> ReversionRecord {
    ReversionRecord {
        cut: cut.to_string(),
        reason: "no proven chain still justifies this control".to_string(),
        at_ms: 1,
    }
}

/// Now as Unix-millis, for building a `ReversionRecord` with a sane stamp in tests.
pub(super) fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// A readiness snapshot with EVERY decision input met — `has_unmet()` is false. The
/// counterpart to the default `ready()` (which is degraded/absent on every input).
pub(super) fn ready_all_met() -> Readiness {
    let mut bake = BakeStats::default();
    // One Falco (`alert`) signal + one eBPF (any other variant) signal so both
    // behavioral feeds read Present this pass.
    bake.signals_by_variant.insert("alert".to_string(), 1);
    bake.signals_by_variant.insert("connection".to_string(), 1);
    let r = derive_readiness(
        &ReadinessConfig {
            model_attached: true,
            kev_count: 3,
            journal_durable: true,
            ..Default::default()
        },
        ModelHealth::Ok,
        &bake,
        Some(SystemTime::now()),
    );
    assert!(!r.has_unmet(), "fixture: every decision input is met");
    r
}

/// A chain with a single-edge cut on `cut_relation` (what the disposition now
/// keys on), plus the evidence flags.
pub(super) fn chain(
    cut_relation: &str,
    foothold: bool,
    corroborated: bool,
    adjudicated: bool,
) -> ProvenChain {
    let cut = Link {
        from: NodeKey("workload/app/Pod/web".into()),
        to: NodeKey("workload/app/Pod/store".into()),
        relation: cut_relation.to_string(),
        technique: None,
        from_labels: Default::default(),
        to_labels: Default::default(),
    };
    ProvenChain {
        entry: NodeKey("workload/app/Pod/web".into()),
        objective: NodeKey("secret/app/s".into()),
        attack: CREDENTIAL_ACCESS,
        foothold: foothold.then_some(EXPLOIT_PUBLIC_FACING),
        corroborated,
        adjudicated,
        promoted: false,
        // The disposition tests below key on the cut + evidence, not on
        // breach-relevance; treat the entry as a front door so the chain is a
        // finding (bucket gating is exercised in the render test instead).
        exposed_entry: true,
        verdict: None,
        links: vec![cut.clone()],
        single_edge_cuts: vec![cut],
    }
}

/// Build a Finding with a two-hop path entry →reaches→ store →&lt;rel&gt;→ objective.
pub(super) fn finding(
    entry: &str,
    objective: &str,
    disposition: &str,
    terminal_rel: &str,
    breach_relevant: bool,
    verdict: Option<&str>,
) -> Finding {
    Finding {
        entry: entry.into(),
        objective: objective.into(),
        tactic: "TA0006".into(),
        tactic_name: "Credential Access".into(),
        technique: "T1552".into(),
        technique_name: "Unsecured Credentials".into(),
        foothold: false,
        corroborated: true,
        adjudicated: true,
        promoted: false,
        disposition: disposition.into(),
        // The cut is the first hop (the reaches edge entry → store), matching
        // the first PathStep below so the remediation graph can mark it.
        cut: Some(format!("{entry} -[reaches/Tcp]-> workload/app/Pod/store")),
        breach_relevant,
        killchain: "T1190 Exploit Public-Facing Application → T1552 Unsecured Credentials".into(),
        verdict: verdict.map(str::to_string),
        path: vec![
            PathStep {
                from: entry.into(),
                relation: "reaches/Tcp".into(),
                to: "workload/app/Pod/store".into(),
            },
            PathStep {
                from: "workload/app/Pod/store".into(),
                relation: terminal_rel.into(),
                to: objective.into(),
            },
        ],
        // Most render tests don't exercise the evidence blocks; the dedicated
        // JEF-133 tests below build findings with populated evidence.
        evidence: EntryEvidence::default(),
        recency: None,
    }
}

/// The expandable card BODY for an endpoint (JEF-202) — the detail-row target. Most card
/// tests inspect this body (the verbatim verdict, rail, evidence, graph, what-to-do). Since
/// JEF-205 the findings core renders through the maud `components`; this wraps the migrated
/// `detail` component over the `detail_props` data so the render-level assertions hold.
pub(super) fn card_body(entry: &str, fs: &[&Finding]) -> String {
    use crate::engine::dashboard::components::findings::detail;
    use crate::engine::dashboard::view_model::findings::detail_props;
    detail(&detail_props(entry, fs).0).into_string()
}

/// The full dense-table row pair (summary `<tr>` + detail `<tr>`) for an endpoint, at the
/// tier the ranking assigns — what `findings_region` emits per endpoint (JEF-202). Renders
/// through the migrated `endpoint` component (JEF-205).
pub(super) fn row_html(entry: &str, fs: &[&Finding]) -> String {
    use crate::engine::dashboard::components::findings::endpoint;
    use crate::engine::dashboard::view_model::findings::{endpoint_attention_rank, endpoint_props};
    let tier = endpoint_attention_rank(fs).1;
    endpoint(&endpoint_props(entry, fs, tier, Some(SystemTime::now()))).into_string()
}

pub(super) fn bake(resolved: u64, unresolved: u64) -> BakeStats {
    let mut signals_by_variant = BTreeMap::new();
    signals_by_variant.insert("connection".to_string(), 12);
    signals_by_variant.insert("secret-read".to_string(), 3);
    signals_by_variant.insert("library-load".to_string(), 5);
    BakeStats {
        signals_by_variant,
        resolved,
        unresolved,
        runtime_store: 7,
        corroborations: 2,
    }
}

/// A `now` to anchor the report's relative-time math deterministically.
pub(super) fn report_now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

/// A breach journal entry for `entry` at `secs_before` seconds before [`report_now`],
/// carrying `verdict` (the model's own words) and explicit structured
/// enrichment-coverage (JEF-145) — the evidence the model was handed, independent of
/// the verdict prose.
pub(super) fn breach_cov(
    entry: &str,
    verdict: &str,
    secs_before: u64,
    coverage: Option<EnrichmentCoverage>,
) -> JournalEntry {
    let at = report_now() - Duration::from_secs(secs_before);
    JournalEntry {
        at_ms: at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        decision: Decision::Breach {
            entry: entry.to_string(),
            objectives: 1,
            verdict: verdict.to_string(),
            coverage,
        },
    }
}

/// A breach entry whose structured coverage is derived from the verdict's CVE
/// mentions — convenience for the lifetime/episode/ranking tests, which only care that
/// a "CVE-…" verdict reads as enrichment-backed and a CVE-less one as a gap. Coverage
/// classification itself is exercised independently below.
pub(super) fn breach(entry: &str, verdict: &str, secs_before: u64) -> JournalEntry {
    let cves: Vec<String> = verdict
        .match_indices("CVE-")
        .map(|(i, _)| {
            verdict[i..]
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                .next()
                .unwrap_or("")
                .to_string()
        })
        .collect();
    breach_cov(
        entry,
        verdict,
        secs_before,
        Some(EnrichmentCoverage {
            cves,
            behavioral: false,
        }),
    )
}

const WEEK: Duration = Duration::from_secs(7 * 24 * 3600);
const FIVE_MIN: Duration = Duration::from_secs(300);

/// A bake snapshot with a Falco `alert` count and one eBPF (`connection`) count, so
/// the two behavioral feeds can be split in the readiness rows.
pub(super) fn feeds_bake(falco: u64, ebpf: u64) -> BakeStats {
    let mut signals_by_variant = BTreeMap::new();
    if falco > 0 {
        signals_by_variant.insert("alert".to_string(), falco);
    }
    if ebpf > 0 {
        signals_by_variant.insert("connection".to_string(), ebpf);
    }
    BakeStats {
        signals_by_variant,
        ..Default::default()
    }
}

/// A config summary with every input wired (a fully-covered cluster).
pub(super) fn full_config() -> ReadinessConfig {
    ReadinessConfig {
        model_attached: true,
        kev_count: 1500,
        journal_durable: true,
        armed: false,
    }
}

/// Look a readiness row up by its stable id.
pub(super) fn rrow<'a>(r: &'a Readiness, id: &str) -> &'a ReadinessRow {
    r.inputs
        .iter()
        .find(|row| row.id == id)
        .unwrap_or_else(|| panic!("readiness row {id} present"))
}

/// Build a broad (>= 20 objectives) endpoint's findings, with the given verdict.
pub(super) fn broad_findings(entry: &str, verdict: Option<&str>) -> Vec<Finding> {
    (0..25)
        .map(|n| {
            finding(
                entry,
                &format!("secret/argocd/secret-{n}"),
                "durable-fix PR",
                "can-do/get/secrets",
                true,
                verdict,
            )
        })
        .collect()
}

/// A finding with explicit attention-relevant fields — the `finding` helper hardcodes
/// `corroborated: true`, so this lets a test set the four signals independently.
pub(super) fn ranked_finding(
    entry: &str,
    disposition: &str,
    corroborated: bool,
    verdict: Option<&str>,
) -> Finding {
    let mut f = finding(
        entry,
        "secret/app/session-key",
        disposition,
        "can-do/get/secrets",
        true,
        verdict,
    );
    f.corroborated = corroborated;
    f.foothold = disposition.contains("latent foothold");
    f
}

/// The graph's `<pre class="mermaid">` is collapsed when it sits inside a
/// `details.graphwrap` (the summary precedes the pre with no intervening close).
pub(super) fn graph_is_collapsed(html: &str) -> bool {
    match (html.find("graphwrap"), html.find("class=\"mermaid\"")) {
        (Some(g), Some(p)) => g < p,
        _ => false,
    }
}

/// A `Finding` whose evidence carries the given CVEs, for the verdict-gist tests.
pub(super) fn finding_with_cves(verdict: Option<&str>, cves: Vec<CveEvidence>) -> Finding {
    let mut f = finding(
        "workload/app/Pod/web",
        "secret/app/session-key",
        "durable-fix PR",
        "can-do/get/secrets",
        true,
        verdict,
    );
    f.corroborated = false;
    f.evidence = EntryEvidence {
        cves,
        runtime: vec![],
        ..Default::default()
    };
    f
}

pub(super) fn full_judgement(
    entry: &str,
    verdict: &str,
    prompt: Option<&str>,
    reply: Option<&str>,
) -> Judgement {
    Judgement {
        entry: entry.to_string(),
        objectives: 3,
        verdict: verdict.to_string(),
        prompt: prompt.map(str::to_string),
        reply: reply.map(str::to_string),
    }
}

/// A `Vulnerability` with the fields the evidence block reads.
pub(super) fn vuln(id: &str, severity: Severity, kev: bool) -> Vulnerability {
    Vulnerability {
        id: id.into(),
        severity,
        exploited_in_wild: kev,
        reachability: Reachability::NotObserved,
        ..Default::default()
    }
}

/// The view-shape `CveEvidence` for a vuln — what `EntryEvidence.cves` holds.
pub(super) fn cve(id: &str, severity: Severity, kev: bool) -> CveEvidence {
    CveEvidence::from_vuln(&vuln(id, severity, kev))
}

/// Assert a rendered surface never prints an `ADR-` or `JEF-` token. Code comments
/// keep their refs; this is the RENDERED-output invariant (JEF-176 AC #1).
pub(super) fn assert_no_internal_refs(label: &str, rendered: &str) {
    assert!(
        !rendered.contains("ADR-"),
        "{label}: leaked an ADR- ref into operator-facing output"
    );
    assert!(
        !rendered.contains("JEF-"),
        "{label}: leaked a JEF- ref into operator-facing output"
    );
}

/// A finding with full evidence (CVEs + a live alert) and an auto-eligible cut, so a
/// rendered page exercises the card, the certainty rail, both evidence blocks, the
/// attack-steps caption and the remediation card at once.
pub(super) fn rich_finding(entry: &str, verdict: Option<&str>) -> Finding {
    let mut f = finding(
        entry,
        "secret/app/session-key",
        AUTO_ELIGIBLE,
        "can-read",
        true,
        verdict,
    );
    f.foothold = true;
    f.evidence = EntryEvidence {
        cves: vec![cve("CVE-2021-44228", Severity::Critical, true)],
        runtime: vec![Behavior::Alert {
            rule: "Terminal shell in container".into(),
        }],
        ..Default::default()
    };
    f
}
