//! Tests for the layered adjudication re-judge gate (ADR-0023, over).
//! `classify_adjudication` reads only the verdict store, so these drive it directly with a real
//! [`state::VerdictStore`] and a hand-built [`PendingEntry`] — no full engine. Extracted to a
//! sibling file to keep `adj_gate.rs` under the file-size cap (CLAUDE.md).

use std::time::Instant;
use std::time::SystemTime;

use super::*;
use crate::engine::graph::attack::EXPLOIT_PUBLIC_FACING;
use crate::engine::graph::{
    Edge, Exposure, Image, Node, NodeKey, Provenance, Reachability, Relation, SecurityGraph,
    Severity, Trust, Vulnerability, Workload,
};
use crate::engine::observe::asn::AsnDb;
use crate::engine::reason::adjudicate::{
    JudgedSurface, PromptSections, Verdict, build_delta_prompt_asn,
};

/// A minimal [`PendingEntry`] for `entry`/`fingerprint` — the only fields the gate reads. The
/// prompt/sections/surface/objectives are irrelevant to the classification decision.
fn pending(entry: &str, fingerprint: &str) -> PendingEntry {
    PendingEntry {
        entry_key: entry.to_string(),
        entry: NodeKey(entry.to_string()),
        objectives: vec![(NodeKey("secret/app/x".into()), EXPLOIT_PUBLIC_FACING)],
        downstream: vec![],
        prompt: "unused".into(),
        fingerprint: fingerprint.to_string(),
        sections: PromptSections {
            runtime: "r".into(),
            cves: "c".into(),
            secrets: "s".into(),
            posture: "p".into(),
            objectives: "o".into(),
            entry: "e".into(),
        },
        chain: "ch".into(),
        surface: JudgedSurface::default(),
        idxs: vec![0],
        menu: reason::adjudicate::incident::Menu::default(),
    }
}

fn baseline(verdict: Verdict) -> state::VerdictBaseline {
    state::VerdictBaseline {
        surface: JudgedSurface::default(),
        verdict,
    }
}

/// First judgment: no baseline ⇒ the delta build reports ADDITIVE, so a fresh (empty) store
/// re-judges — there is nothing decisive to serve yet.
#[test]
fn first_judgment_no_baseline_judges() {
    let store = state::VerdictStore::new();
    let p = pending("entry", "fp1");
    assert!(matches!(
        classify_adjudication(&store, &p, true, None, Instant::now()),
        AdjGate::Judge
    ));
}

/// An ADDITIVE delta against a decisive baseline re-judges (something NEW must be evaluated) —
/// it is NOT served from the baseline, even though a baseline exists.
#[test]
fn additive_delta_rejudges() {
    let store = state::VerdictStore::new();
    let p = pending("entry", "fp-new");
    let base = baseline(Verdict::Refuted("prior".into()));
    assert!(matches!(
        classify_adjudication(&store, &p, true, Some(&base), Instant::now()),
        AdjGate::Judge
    ));
}

/// A PURELY SUBTRACTIVE delta (nothing added since the baseline) HOLDS the prior decisive
/// verdict — no fresh model call — and warms the LRU under the current fingerprint so the
/// settled state HITS next pass. Uses a NEGATIVE baseline: a positive (`Exploitable`) is always
/// re-verified (see [`subtractive_hold_does_not_replay_exploitable`]).
#[test]
fn subtractive_delta_holds_prior_verdict() {
    let store = state::VerdictStore::new();
    let p = pending("entry", "fp-shrunk");
    let base = baseline(Verdict::Refuted("held".into()));

    let out = classify_adjudication(&store, &p, false, Some(&base), Instant::now());
    match out {
        AdjGate::Resolved { verdict, held } => {
            assert!(
                held,
                "a subtractive hold is a HELD serve, not a plain LRU hit"
            );
            assert_eq!(verdict, Verdict::Refuted("held".into()));
        }
        other => panic!("expected a held serve, got {other:?}"),
    }
    // The hold warmed the LRU: the same fingerprint now HITS directly (no model call).
    assert_eq!(
        store.cached_for("entry", "fp-shrunk"),
        Some(Verdict::Refuted("held".into())),
        "the held verdict is cached under the current fingerprint"
    );
}

/// a cached `Exploitable` is NEVER replayed from the LRU — it is re-judged against the
/// live model every pass, so a one-time temp-0 tail-flip can't freeze into a permanent false
/// breach. (Contrast [`exact_fingerprint_hit_serves_unheld`], where a cached `Refuted` DOES serve.)
#[test]
fn cached_exploitable_is_rejudged_not_replayed() {
    let store = state::VerdictStore::new();
    store.cache_decisive(
        "entry",
        "fp-seen".into(),
        Verdict::Exploitable("flip".into()),
    );
    let p = pending("entry", "fp-seen");
    assert!(
        matches!(
            classify_adjudication(&store, &p, false, None, Instant::now()),
            AdjGate::Judge
        ),
        "a cached Exploitable must fall through to a fresh re-judge, not serve from cache"
    );
}

/// the subtractive-hold path also does not replay a positive — an `Exploitable` baseline
/// on a purely-subtractive delta is re-judged, not held.
#[test]
fn subtractive_hold_does_not_replay_exploitable() {
    let store = state::VerdictStore::new();
    let p = pending("entry", "fp-shrunk");
    let base = baseline(Verdict::Exploitable("frozen".into()));
    assert!(
        matches!(
            classify_adjudication(&store, &p, false, Some(&base), Instant::now()),
            AdjGate::Judge
        ),
        "an Exploitable baseline must be re-verified, not held on a subtractive delta"
    );
    // And it did NOT warm the LRU with the stale positive (no blind hit next pass).
    assert_eq!(store.cached_for("entry", "fp-shrunk"), None);
}

///  scope guard: a corroborated `Confirmed` (backed by live evidence, not the model's own
/// positive) STILL serves from the cache — only `Exploitable` is force-re-verified, so re-judging
/// can never let a model `Refuted` veto a live attack.
#[test]
fn cached_confirmed_still_serves() {
    let store = state::VerdictStore::new();
    store.cache_decisive("entry", "fp-seen".into(), Verdict::Confirmed);
    let p = pending("entry", "fp-seen");
    match classify_adjudication(&store, &p, true, None, Instant::now()) {
        AdjGate::Resolved { verdict, held } => {
            assert!(!held);
            assert_eq!(verdict, Verdict::Confirmed);
        }
        other => panic!("expected a cached Confirmed to serve, got {other:?}"),
    }
}

/// Fail-safe: `!additive` with NO baseline (should be unreachable — a missing baseline is
/// additive) RE-JUDGES rather than serving nothing. Never suppress a judgment on possibly-new
/// surface.
#[test]
fn not_additive_without_baseline_still_rejudges() {
    let store = state::VerdictStore::new();
    let p = pending("entry", "fp");
    assert!(matches!(
        classify_adjudication(&store, &p, false, None, Instant::now()),
        AdjGate::Judge
    ));
}

/// An exact-fingerprint LRU hit serves the cached verdict as a plain hit (`held =
/// false`), taking precedence over the delta gate.
#[test]
fn exact_fingerprint_hit_serves_unheld() {
    let store = state::VerdictStore::new();
    store.cache_decisive("entry", "fp-seen".into(), Verdict::Refuted("cached".into()));
    let p = pending("entry", "fp-seen");
    // Even with an additive delta, the exact-state cache hit wins (identical input ⇒ identical
    // verdict).
    match classify_adjudication(&store, &p, true, None, Instant::now()) {
        AdjGate::Resolved { verdict, held } => {
            assert!(!held, "an exact LRU hit is not a subtractive hold");
            assert_eq!(verdict, Verdict::Refuted("cached".into()));
        }
        other => panic!("expected an LRU hit, got {other:?}"),
    }
}

// ---- LOAD-BEARING regression: a downstream-only change must re-judge -------------

/// A downstream workload `workload/app/downstream-pod`, optionally carrying a critical CVE
/// (loaded-at-runtime — exploitation evidence) on its image. The SAME identity either way, so
/// swapping `with_cve` is the only difference between a "clean" and an "evidenced" downstream
/// snapshot.
fn graph_with_downstream(with_cve: bool) -> (SecurityGraph, NodeKey) {
    let mut g = SecurityGraph::new();
    let wl = Node::Workload(Workload {
        namespace: "app".into(),
        name: "downstream-pod".into(),
        kind: "Pod".into(),
        labels: Default::default(),
        meshed: false,
        exposure: Exposure::Internal,
        runtime: Vec::new(),
        persistent: false,
        misconfigs: vec![],
        rbac_findings: vec![],
    });
    let key = wl.key();
    let w = g.upsert_node(wl);
    if with_cve {
        let img = g.upsert_node(Node::Image(Image {
            digest: "sha256:downstream".into(),
            reference: Some("downstream:1".into()),
            trust: Trust::Unknown,
            vulnerabilities: vec![Vulnerability {
                id: "CVE-2024-9999".into(),
                severity: Severity::Critical,
                reachability: Reachability::LoadedAtRuntime,
                ..Default::default()
            }],
            exposed_secrets: vec![],
            static_binary: None,
        }));
        g.add_edge(
            w,
            img,
            Edge {
                relation: Relation::RunsImage,
                provenance: Provenance::new("test", SystemTime::UNIX_EPOCH),
            },
        );
    }
    (g, key)
}

/// THE trap this ticket closes: downstream evidence must land in the PROMPT *and* the
/// SURFACE, or a downstream-only change busts the exact-fingerprint LRU (layer 1, a genuine
/// prompt-text miss) but the layer-2 subtractive-delta hold silently serves the prior decisive
/// verdict forever — since a fingerprint miss alone isn't enough; the gate's second layer only
/// re-judges on an ADDITIVE surface delta. A downstream-only CVE appearing must register as an
/// addition (`build_delta_prompt_asn`'s `additive` flag) and drive the REAL gate
/// (`classify_adjudication`) to `AdjGate::Judge`, not a held serve of the stale prior verdict.
#[test]
fn downstream_only_cve_appearing_is_additive_and_forces_a_rejudge() {
    let entry = NodeKey("workload/app/entry-web".into());
    let objectives: Vec<(NodeKey, crate::engine::graph::attack::AttackRef)> = vec![];

    let (g_clean, downstream) = graph_with_downstream(false);
    let (g_evidenced, downstream_v) = graph_with_downstream(true);
    assert_eq!(
        downstream, downstream_v,
        "same downstream workload identity — only its CVE differs"
    );

    // Pass 1: the downstream workload is CLEAN — decisively judged and baselined.
    let baseline_build = build_delta_prompt_asn(
        &entry,
        &objectives,
        &g_clean,
        &AsnDb::empty(),
        None,
        std::slice::from_ref(&downstream),
    );
    assert!(
        baseline_build.prompt.contains("no evidence observed"),
        "the clean downstream node renders the one-line marker"
    );
    let store = state::VerdictStore::new();
    store.cache_decisive(
        entry.0.as_str(),
        baseline_build.cache_key.clone(),
        Verdict::Refuted("nothing observed".into()),
    );
    let base = state::VerdictBaseline {
        surface: baseline_build.surface,
        verdict: Verdict::Refuted("nothing observed".into()),
    };

    // Pass 2: the SAME downstream workload now runs a critical CVE — a genuine fingerprint MISS
    // (the prompt text differs), but the question this test locks down is whether the GATE
    // re-judges rather than silently holding the stale "nothing observed" verdict.
    let current_build = build_delta_prompt_asn(
        &entry,
        &objectives,
        &g_evidenced,
        &AsnDb::empty(),
        Some(&base.surface),
        std::slice::from_ref(&downstream),
    );
    assert!(
        current_build.prompt.contains("CVE-2024-9999"),
        "the downstream CVE is visible in the prompt"
    );
    assert_ne!(
        current_build.cache_key, baseline_build.cache_key,
        "a genuine fingerprint miss — the LRU (layer 1) cannot serve this from cache"
    );
    assert!(
        current_build.additive,
        "a downstream-only CVE appearing MUST be an additive surface delta"
    );

    let pending = PendingEntry {
        entry_key: entry.0.clone(),
        entry: entry.clone(),
        objectives,
        downstream: vec![downstream],
        prompt: current_build.prompt,
        fingerprint: current_build.cache_key,
        sections: current_build.sections,
        chain: "ch".into(),
        surface: current_build.surface,
        idxs: vec![0],
        menu: reason::adjudicate::incident::Menu::default(),
    };
    assert!(
        matches!(
            classify_adjudication(
                &store,
                &pending,
                current_build.additive,
                Some(&base),
                Instant::now(),
            ),
            AdjGate::Judge
        ),
        "THE TRAP: a downstream-only CVE must force a fresh model call — the layer-2 \
         subtractive-delta hold must NOT silently serve the prior 'nothing observed' verdict"
    );
}
