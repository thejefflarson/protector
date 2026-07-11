//! Render-level tests for the JEF-281 multi-path finding detail: the objective reachable via
//! several redundant paths shows ALL of them (the complete-graph picture the v3 rewrite lost with
//! Mermaid), makes the no-single-edge-cut reason legible, and collapses a wide fan-out behind a
//! server-rendered `<details>` (no client JS). Split into its own file to keep every test module
//! under the 1,000-line cap (CLAUDE.md). Drives the view_model + components directly (no HTTP).

use std::time::SystemTime;

use crate::engine::reason::adjudicate::Verdict;
use crate::engine::state::{Finding, PathStep};

use super::PreactTabs;
use super::page;
use super::tests::{breach_finding, judging_readiness};
use super::view_model::build_findings_view;

/// A finding whose objective is reachable via two redundant backends, with no single-edge cut.
fn multi_path_finding() -> Finding {
    let mut f = breach_finding("deployment/edge/gw", Verdict::Confirmed);
    f.objective = "secret/app/creds".into();
    f.cut = None; // no single edge severs it — the redundant paths are the reason
    let via_db = vec![
        PathStep {
            from: "deployment/edge/gw".into(),
            relation: "reaches/Tcp/5432".into(),
            to: "statefulset/app/db".into(),
        },
        PathStep {
            from: "statefulset/app/db".into(),
            relation: "mounts".into(),
            to: "secret/app/creds".into(),
        },
    ];
    let via_cache = vec![
        PathStep {
            from: "deployment/edge/gw".into(),
            relation: "reaches/Tcp/6379".into(),
            to: "deployment/app/cache".into(),
        },
        PathStep {
            from: "deployment/app/cache".into(),
            relation: "mounts".into(),
            to: "secret/app/creds".into(),
        },
    ];
    f.path = via_db.clone();
    f.paths = vec![via_db, via_cache];
    f
}

#[test]
fn finding_detail_shows_all_proven_paths_not_one() {
    let view = build_findings_view(
        "prod".into(),
        &[multi_path_finding()],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view, PreactTabs::default()).into_string();
    // The header pluralizes, and BOTH proven paths render as numbered stacked chains.
    assert!(html.contains("proven paths"), "the header pluralizes");
    assert!(html.contains("path 1"), "the first proven path is labelled");
    assert!(
        html.contains("path 2"),
        "the second proven path is shown, not hidden"
    );
    assert_eq!(
        html.matches("class=\"chain\"").count(),
        2,
        "one chain diagram per proven path — the complete picture, not one path"
    );
}

#[test]
fn no_cut_finding_makes_the_redundant_path_reason_legible() {
    let view = build_findings_view(
        "prod".into(),
        &[multi_path_finding()],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view, PreactTabs::default()).into_string();
    // The multiple paths ARE the no-cut explanation, stated in words.
    assert!(html.contains("redundant paths"));
    assert!(
        html.contains("no single edge severs the objective"),
        "the no-single-edge-cut reason is legible from the multi-path view"
    );
}

#[test]
fn wide_path_fanout_collapses_by_default_but_expands_to_the_full_set() {
    // Five proven routes to one objective — more than the open-by-default cap. The overflow
    // folds into a native <details> (server-rendered, no JS), and a truncated set says so.
    let mut f = multi_path_finding();
    let route = |port: &str, mid: &str| {
        vec![
            PathStep {
                from: "deployment/edge/gw".into(),
                relation: format!("reaches/Tcp/{port}"),
                to: format!("deployment/app/{mid}"),
            },
            PathStep {
                from: format!("deployment/app/{mid}"),
                relation: "mounts".into(),
                to: "secret/app/creds".into(),
            },
        ]
    };
    f.paths = vec![
        route("1", "a"),
        route("2", "b"),
        route("3", "c"),
        route("4", "d"),
        route("5", "e"),
    ];
    f.paths_truncated = true;
    f.path = f.paths[0].clone();
    let view = build_findings_view(
        "prod".into(),
        &[f],
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    );
    let html = page::findings_page(&view, PreactTabs::default()).into_string();
    // The overflow (5 - 3 shown) collapses into an expandable disclosure — not an unbounded wall.
    assert!(
        html.contains("class=\"more-paths\""),
        "the overflow paths collapse into a disclosure"
    );
    assert!(
        html.contains("show 2 more paths"),
        "expandable to the full set"
    );
    assert!(
        html.contains("more proven paths exist (bounded)"),
        "and the bound is stated honestly when truncated"
    );
}
