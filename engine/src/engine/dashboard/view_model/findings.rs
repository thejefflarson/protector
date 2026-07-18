//! Map the engine's [`Finding`] rows (with their evidence, path, and typed verdict) into the
//! presentation [`FindingProps`] the components render, and apply the URGENCY sort (ADR-0016 /
//! brief §5) — corroborated-live → model-promoted → escalations → awaiting → cleared. This is
//! the data layer: it touches `state::`/`graph::` domain types; the components never do.

use std::collections::HashSet;

use crate::engine::graph::{Behavior, NodeKey};
use crate::engine::state::{
    CveEvidence, EntryEvidence, Finding, FindingEvidence, Judgement, NodeCoverageState, PathStep,
    Readiness,
};

use super::posture::{delta_of, live_tag_of, posture_of};
use super::props::{
    BehaviorProps, CveProps, EvidenceProps, EvidenceSummary, FindingProps, HopProps,
    JudgementProps, LiveTag, Posture, ScanProps,
};

/// A reasonable threshold past which an entry's reachable-objective set reads as a fan-out
/// (argocd → ~120 secrets), collapsed to `→ ×N` rather than listed as alarms (brief §5/§10).
const FANOUT_THRESHOLD: usize = 8;

/// Map a node key to its kind glyph (workload ▢ / secret 🔑 / host 🖥 / capability ⚡ / …) so a
/// node carries its kind without colour (style guide principle 3). The single source of truth for
/// the node-kind glyph seam — used for the entry column AND every node in the path-viz chain.
fn node_kind_glyph(key: &str) -> &'static str {
    match NodeKey::kind_of(key) {
        "workload" => "\u{25A2}",   // ▢
        "secret" => "\u{1F511}",    // 🔑
        "identity" => "\u{1F464}",  // 👤
        "endpoint" => "\u{2192}",   // →
        "image" => "\u{25A3}",      // ▣
        "host" => "\u{1F5A5}",      // 🖥
        "capability" => "\u{26A1}", // ⚡
        _ => "\u{2022}",            // •
    }
}

/// The glyph for a finding's entry node. An internet foothold is the globe; otherwise the node's
/// kind glyph.
fn entry_glyph(key: &str, foothold: bool) -> String {
    if foothold {
        return "\u{1F310}".to_string(); // 🌐
    }
    node_kind_glyph(key).to_string()
}

/// Project a CVE evidence record into its props (the subordinate severity channel).
fn cve_props(c: &CveEvidence) -> CveProps {
    CveProps {
        id: c.id.clone(),
        severity: c.severity.clone(),
        score: c.score.clone(),
        kev: c.kev,
        epss: c.epss.clone(),
        reachability: c.reachability.clone(),
        fix: c.fix.clone(),
        title: c.title.clone(),
    }
}

/// Project a scanner finding (exposed secret / misconfig / RBAC) into its props.
fn scan_props(f: &FindingEvidence) -> ScanProps {
    ScanProps {
        id: f.id.clone(),
        severity: f.severity.clone(),
        category: f.category.clone(),
        title: f.title.clone(),
    }
}

/// Project a runtime behavior into its props, marking whether it corroborates the chain.
fn behavior_props(b: &Behavior) -> BehaviorProps {
    BehaviorProps {
        variant: b.variant_label().to_string(),
        summary: b.summary(),
        corroborating: b.is_alert(),
    }
}

/// Build the full evidence panel props from an entry's evidence, splitting runtime behaviors
/// into corroborating (alerts) vs context.
fn evidence_props(ev: &EntryEvidence) -> EvidenceProps {
    EvidenceProps {
        cves: ev.cves.iter().map(cve_props).collect(),
        corroborating: ev
            .runtime
            .iter()
            .filter(|b| b.is_alert())
            .map(behavior_props)
            .collect(),
        context: ev
            .runtime
            .iter()
            .filter(|b| !b.is_alert())
            .map(behavior_props)
            .collect(),
        exposed_secrets: ev.exposed_secrets.iter().map(scan_props).collect(),
        misconfigs: ev.misconfigs.iter().map(scan_props).collect(),
        rbac_findings: ev.rbac_findings.iter().map(scan_props).collect(),
    }
}

/// The compact evidence-cluster summary for the row.
fn evidence_summary(ev: &EntryEvidence) -> EvidenceSummary {
    EvidenceSummary {
        cve_count: ev.cves.len(),
        kev: ev.cves.iter().any(|c| c.kev),
        runtime_alerts: ev.runtime.iter().filter(|b| b.is_alert()).count(),
        exposed_secrets: ev.exposed_secrets.len(),
    }
}

/// Map the proven path's hops into the chain-diagram props, marking structural (substrate) hops
/// muted and the cut point. `cut` is the cut signature (`from -[relation]-> to`); a hop matching
/// it is marked. `foothold` makes the very first node (the entry) read as the internet front door
/// (🌐) rather than its bare kind. Each node carries its kind glyph so the chain reads
/// structurally (brief §3).
fn path_props(path: &[PathStep], cut: Option<&str>, foothold: bool) -> Vec<HopProps> {
    path.iter()
        .enumerate()
        .map(|(i, h)| {
            let signature = format!("{} -[{}]-> {}", h.from, h.relation, h.to);
            // The first hop's `from` is the entry: a foothold entry is the internet front door.
            let from_glyph = if i == 0 && foothold {
                "\u{1F310}".to_string() // 🌐
            } else {
                node_kind_glyph(&h.from).to_string()
            };
            HopProps {
                from: NodeKey::short_of(&h.from).to_string(),
                from_glyph,
                relation: h.relation.clone(),
                to: NodeKey::short_of(&h.to).to_string(),
                to_glyph: node_kind_glyph(&h.to).to_string(),
                structural: is_structural_relation(&h.relation),
                is_cut: cut == Some(signature.as_str()),
                // Set by [`multi_path_props`] once all paths are known; a lone path shares nothing.
                shared: false,
            }
        })
        .collect()
}

/// The `from -[relation]-> to` signature of one hop — the same shape as the cut signature, used
/// to find edges SHARED across proven paths.
fn hop_signature(h: &PathStep) -> String {
    format!("{} -[{}]-> {}", h.from, h.relation, h.to)
}

/// Map ALL proven paths to the objective into stacked hop-lists (JEF-281), marking every edge
/// that appears in EVERY path as [`HopProps::shared`] so redundancy — and the reason a chain is
/// no-single-edge-cut — is visible. A single path shares nothing (there is nothing to compare).
/// Falls back to the representative `path` when the complete set is empty, so a finding always
/// renders at least one chain.
fn multi_path_props(
    paths: &[Vec<PathStep>],
    representative: &[PathStep],
    cut: Option<&str>,
    foothold: bool,
) -> Vec<Vec<HopProps>> {
    use std::collections::HashSet;
    let source: Vec<&[PathStep]> = if paths.is_empty() {
        vec![representative]
    } else {
        paths.iter().map(|p| p.as_slice()).collect()
    };
    // Shared edges = the signatures present in EVERY path (the intersection). With one path
    // there is no redundancy to surface, so the set stays empty.
    let shared: HashSet<String> = if source.len() < 2 {
        HashSet::new()
    } else {
        let mut acc: HashSet<String> = source[0].iter().map(hop_signature).collect();
        for p in &source[1..] {
            let sigs: HashSet<String> = p.iter().map(hop_signature).collect();
            acc.retain(|s| sigs.contains(s));
        }
        acc
    };
    source
        .iter()
        .map(|p| {
            let mut hops = path_props(p, cut, foothold);
            for (hop, step) in hops.iter_mut().zip(p.iter()) {
                hop.shared = shared.contains(&hop_signature(step));
            }
            hops
        })
        .collect()
}

/// Whether a relation label names a STRUCTURAL substrate edge (runs-as / runs-image /
/// scheduled-on) — these are rendered muted in the hop-list (brief §5). Mirrors
/// [`crate::engine::graph::Relation::is_structural`] over the label string.
fn is_structural_relation(relation: &str) -> bool {
    matches!(relation, "runs-as" | "runs-image" | "scheduled-on")
}

/// A stable DOM/fragment id for a finding, derived from its entry key. A readable slug
/// (non-alphanumerics collapse to `-`, so it is a safe `id`/anchor) is paired with a short
/// hash of the FULL entry key. The hash is what makes the id **collision-free**: the slug alone
/// is lossy — distinct keys like `secret/app/db` and `secret-app-db` (or `endpoint/a` and
/// `endpoint-a`) both slugify to the same string, so two different rows would otherwise share
/// one `id`/`data-finding`/`aria-controls="detail-<id>"`, and the whole-row toggle would open
/// the wrong adjacent `.row-detail` (`expanded.has(id)` and `getElementById` would match the
/// wrong node). Appending the full-key hash guarantees every distinct entry gets a distinct row
/// + detail id (brief item 2).
fn finding_id(entry: &str) -> String {
    let slug: String = entry
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("f-{slug}-{}", short_hash(entry))
}

/// A short, stable hex hash of a key — the collision-breaking suffix for [`finding_id`]. Uses
/// the FNV-1a 64-bit hash (no dependency, deterministic across runs — unlike `DefaultHasher`'s
/// process-seeded output, which would make the same finding's id change between renders and
/// break the JS's persisted-open-state keying) so two distinct entry keys never share an id.
/// Rendered as 8 hex chars — ample to separate the handful of findings on a page while staying
/// compact.
fn short_hash(s: &str) -> String {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    for byte in s.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{:08x}", hash & 0xffff_ffff)
}

/// The verbatim model judgement props for an entry, if one was captured in the log. Matches by
/// entry key; the newest judgement for the entry wins.
fn judgement_props(entry: &str, judgements: &[Judgement]) -> JudgementProps {
    match judgements.iter().find(|j| j.entry == entry) {
        Some(j) => JudgementProps {
            prompt: j.prompt.clone(),
            reply: j.reply.clone(),
            verdict: Some(j.verdict.clone()),
        },
        None => JudgementProps::default(),
    }
}

/// The set of blind node names from the readiness snapshot (JEF-308) — the runtime-corroboration
/// row's per-node breakdown, filtered to the `Blind` state. Used to add the blind-node caveat to a
/// finding whose node has no live sensor.
pub(super) fn blind_nodes_of(readiness: &Readiness) -> HashSet<String> {
    readiness
        .inputs
        .iter()
        .find(|r| r.id == "runtime-corroboration")
        .map(|r| {
            r.nodes
                .iter()
                .filter(|n| n.state == NodeCoverageState::Blind)
                .map(|n| n.node.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// Map one [`Finding`] into its presentation props. `judgements` is the newest-first judgement
/// snapshot, used to attach the verbatim prompt/reply for the "show model prompt" disclosure.
/// `blind_nodes` is the set of nodes with no live runtime sensor (JEF-308) — a finding on a blind
/// node that isn't corroborated carries a caveat so its calm propose-only reading isn't dishonest.
pub(super) fn finding_props(
    f: &Finding,
    judgements: &[Judgement],
    blind_nodes: &HashSet<String>,
) -> FindingProps {
    let posture = posture_of(f.verdict.as_ref());
    let live_tag = live_tag_of(f.verdict.as_ref());
    FindingProps {
        id: finding_id(&f.entry),
        posture,
        live_tag,
        delta: delta_of(f.recency.as_ref()),
        entry_glyph: entry_glyph(&f.entry, f.foothold),
        entry: NodeKey::short_of(&f.entry).to_string(),
        foothold: f.foothold,
        objective: NodeKey::short_of(&f.objective).to_string(),
        fanout: None, // single-objective rows; fan-out is computed in the collapse pass below.
        replicas: None, // single-pod rows; replica collapse runs in the pass below.
        evidence_summary: evidence_summary(&f.evidence),
        disposition: f.disposition.clone(),
        verdict_summary: f.verdict.as_ref().map(|v| v.summary()),
        path: path_props(&f.path, f.cut.as_deref(), f.foothold),
        paths: multi_path_props(&f.paths, &f.path, f.cut.as_deref(), f.foothold),
        paths_truncated: f.paths_truncated,
        cut: f.cut.clone(),
        evidence: evidence_props(&f.evidence),
        judgement: judgement_props(&f.entry, judgements),
        blind_node_caveat: blind_node_caveat(f, blind_nodes),
        // The live alarming-now signals on this chain's entry (JEF-323) — the same seam the Alerts
        // tab projects from, so the "alarming activity observed" annotation and the tab agree.
        alerts: super::alerts::alarming_signals_of(f),
    }
}

/// The finding-level "runtime-blind on this node" caveat (JEF-424, from the JEF-308 coverage), or
/// `None`. Applies when the finding is NOT live-corroborated AND its workload sits on a node with no
/// live sensor: its calm propose-only reading would be dishonest there, because we can't see whether
/// the path is being exploited — blind ≠ green, absence of a signal is not evidence of safety. This
/// is PRESENTATION METADATA ONLY: it is derived from the SAME `blind_node_set` the Readiness
/// runtime-corroboration row reads (so the two never disagree), and it never touches the verdict,
/// the proposed action, or the report — the finding's decision is unchanged (ADR-0016). A
/// corroborated finding already has a live signal, and a finding whose node is unknown or sensored
/// gets no caveat.
fn blind_node_caveat(f: &Finding, blind_nodes: &HashSet<String>) -> Option<String> {
    if f.corroborated {
        return None;
    }
    let node = f.node.as_ref()?;
    if !blind_nodes.contains(node) {
        return None;
    }
    Some(format!(
        "runtime-blind on {node} \u{2014} no live sensor here, so absence of a signal is not evidence of safety"
    ))
}

/// The urgency rank for the sort (lower = MORE urgent). Urgency is NOT severity (ADR-0016): a
/// corroborated-live breach outranks a model-promoted one, which outranks an escalation, which
/// outranks an awaiting row, which outranks a cleared one (the calm tail).
fn urgency_rank(f: &FindingProps) -> u8 {
    match (f.posture, f.live_tag, &f.delta) {
        // Corroborated-live breach — the loudest.
        (Posture::Breach, LiveTag::Live, _) => 0,
        // Model-promoted breach.
        (Posture::Breach, _, _) => 1,
        // An escalation (newly worsened), regardless of decisive posture.
        (_, _, super::props::DeltaProps::Escalated) => 2,
        // Uncertain — not safe, needs a look.
        (Posture::Uncertain, _, _) => 3,
        // Awaiting judgement.
        (Posture::Awaiting, _, _) => 4,
        // Cleared — the calm tail (collapsed group).
        (Posture::Cleared, _, _) => 5,
    }
}

/// Collapse a group of findings that share an entry into one fan-out row when the entry reaches
/// many objectives (argocd → ~120 secrets), framed as reachable-but-cleared (brief §5). A small
/// reachable set is left as individual rows.
fn collapse_fanout(mut rows: Vec<FindingProps>) -> Vec<FindingProps> {
    use std::collections::HashMap;
    let mut counts: HashMap<String, usize> = HashMap::new();
    for r in &rows {
        *counts.entry(r.entry.clone()).or_default() += 1;
    }
    // Entries that fan out beyond the threshold collapse to a single representative row.
    let mut seen: HashMap<String, ()> = HashMap::new();
    rows.retain(|r| {
        let n = counts.get(&r.entry).copied().unwrap_or(1);
        if n > FANOUT_THRESHOLD {
            // Keep only the first row per fanned-out entry.
            seen.insert(r.entry.clone(), ()).is_none()
        } else {
            true
        }
    });
    for r in &mut rows {
        let n = counts.get(&r.entry).copied().unwrap_or(1);
        if n > FANOUT_THRESHOLD {
            r.fanout = Some(n);
        }
    }
    rows
}

/// Derive the owning-workload group key for a POD entry's short label, or `None` when the label
/// does not CLEARLY name a controller-managed pod (be conservative — never merge unrelated pods,
/// brief item 5). The short label is the `workload/`-stripped key: `<ns>/Pod/<name>`. We collapse
/// only when both (a) the kind segment is exactly `Pod` and (b) the pod name carries a controller
/// replica suffix we recognise — a StatefulSet `name-<ordinal>` (trailing `-<digits>`), a
/// Deployment `name-<rs-hash>-<pod-hash>` (two trailing hash segments), or a DaemonSet / bare
/// ReplicaSet `name-<pod-hash>` (one trailing 5-char hash). The returned key is
/// `<ns>/Pod/<workload-name>`, so replicas of the SAME controller group together while two
/// unrelated pods (different ns or workload stem) never do; a bare/standalone pod (no recognised
/// suffix) returns `None` and stays an individual row. See [`strip_replica_suffix`] for the shapes.
fn workload_group_key(short_entry: &str) -> Option<String> {
    let mut parts = short_entry.splitn(3, '/');
    let ns = parts.next()?;
    let kind = parts.next()?;
    let pod_name = parts.next()?;
    if kind != "Pod" || ns.is_empty() || pod_name.is_empty() {
        return None;
    }
    let workload = strip_replica_suffix(pod_name)?;
    Some(format!("{ns}/Pod/{workload}"))
}

/// Strip a controller-managed pod's replica suffix to recover the owning workload's name, or
/// `None` when the name does not match a recognised controller-pod shape (so we leave it alone).
/// Conservative by construction: a name must split into `stem` + suffix segment(s) with a
/// non-empty stem, and the suffix segments must look like a hash/ordinal — otherwise `None`.
fn strip_replica_suffix(pod_name: &str) -> Option<&str> {
    // StatefulSet: `name-<ordinal>` — a trailing `-<digits>`.
    if let Some((stem, last)) = pod_name.rsplit_once('-')
        && !stem.is_empty()
        && !last.is_empty()
        && last.bytes().all(|b| b.is_ascii_digit())
    {
        return Some(stem);
    }
    // Deployment: `name-<rs-hash>-<pod-hash>` — TWO trailing hash segments (rs hash then pod
    // hash). Recognise the pod-hash (5 lowercase-alnum chars) AND the ReplicaSet hash (5–10
    // lowercase-alnum) so a hyphenated workload name (`my-app-...`) keeps its stem.
    let mut segs = pod_name.rsplitn(3, '-');
    let pod_hash = segs.next()?;
    let rs_hash = segs.next()?;
    let stem = segs.next()?;
    if !stem.is_empty() && is_pod_hash(pod_hash) && is_replicaset_hash(rs_hash) {
        // The stem is everything before the two trailing hash segments.
        let cut = pod_name.len() - pod_hash.len() - rs_hash.len() - 2; // two '-' separators
        return Some(&pod_name[..cut]);
    }
    // DaemonSet / bare ReplicaSet: `name-<pod-hash>` — ONE trailing 5-char hash segment.
    if let Some((stem, last)) = pod_name.rsplit_once('-')
        && !stem.is_empty()
        && is_pod_hash(last)
    {
        return Some(stem);
    }
    None
}

/// A Kubernetes pod-template hash segment: exactly 5 lowercase-alphanumeric chars (the
/// `pod-template-hash` suffix Deployments/ReplicaSets/DaemonSets append) that MIXES at least one
/// letter AND one digit. The mixed-class requirement is the conservative guard: a 5-char tail
/// that is all letters (`shell`, `mysql`) is almost certainly part of the workload NAME, not a
/// hash — treating it as a hash would wrongly merge `debug-shell` with `debug-mysql`. Real
/// `pod-template-hash`es are base-36-random and virtually always carry a digit, so this admits
/// genuine replica hashes while leaving dictionary-word-tailed names un-merged (brief item 5:
/// "if uncertain, leave rows individual").
fn is_pod_hash(seg: &str) -> bool {
    is_mixed_hash(seg, 5, 5)
}

/// A ReplicaSet hash segment: 5–10 chars, same mixed letter+digit rule as [`is_pod_hash`]. The
/// middle segment of a Deployment pod name (`name-<rs-hash>-<pod-hash>`).
fn is_replicaset_hash(seg: &str) -> bool {
    is_mixed_hash(seg, 5, 10)
}

/// Whether `seg` looks like a controller-generated hash: length within `[min, max]`, all
/// lowercase-alphanumeric, and MIXING at least one ASCII letter with at least one ASCII digit.
fn is_mixed_hash(seg: &str, min: usize, max: usize) -> bool {
    if !(min..=max).contains(&seg.len()) {
        return false;
    }
    let mut has_alpha = false;
    let mut has_digit = false;
    for b in seg.bytes() {
        if b.is_ascii_lowercase() {
            has_alpha = true;
        } else if b.is_ascii_digit() {
            has_digit = true;
        } else {
            return false; // not lowercase-alphanumeric
        }
    }
    has_alpha && has_digit
}

/// Collapse pod REPLICAS of the same owning workload into a single representative row (brief item
/// 5). Replicas run the same image, so one merged posture — the WORST/most-urgent among the group
/// (reused [`urgency_rank`]) — is sound. The representative row is relabeled with the workload
/// (`<ns>/<workload-name>`) and carries the replica count (`×N`). Only pods whose name clearly
/// matches a controller replica pattern collapse ([`workload_group_key`] returns `None` otherwise),
/// so unrelated pods and standalone pods are NEVER merged. Mirrors [`collapse_fanout`]'s shape.
fn collapse_pod_replicas(mut rows: Vec<FindingProps>) -> Vec<FindingProps> {
    use std::collections::HashMap;
    // Tally how many rows fall into each workload group, and which group each row belongs to.
    let groups: Vec<Option<String>> = rows.iter().map(|r| workload_group_key(&r.entry)).collect();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for g in groups.iter().flatten() {
        *counts.entry(g.clone()).or_default() += 1;
    }
    // The representative for each multi-replica group is the WORST-posture row (lowest urgency
    // rank); ties broken by entry for determinism so the chosen representative is stable.
    let mut best_idx: HashMap<String, usize> = HashMap::new();
    for (i, g) in groups.iter().enumerate() {
        let Some(key) = g else { continue };
        if counts.get(key).copied().unwrap_or(0) < 2 {
            continue; // a lone pod in its group is not a replica set — leave it individual.
        }
        match best_idx.get(key) {
            Some(&cur) => {
                let better = urgency_rank(&rows[i]) < urgency_rank(&rows[cur])
                    || (urgency_rank(&rows[i]) == urgency_rank(&rows[cur])
                        && rows[i].entry < rows[cur].entry);
                if better {
                    best_idx.insert(key.clone(), i);
                }
            }
            None => {
                best_idx.insert(key.clone(), i);
            }
        }
    }
    // Keep each row UNLESS it belongs to a collapsed group and is not that group's representative.
    let mut keep = Vec::with_capacity(rows.len());
    for (i, g) in groups.iter().enumerate() {
        match g {
            Some(key) if counts.get(key).copied().unwrap_or(0) >= 2 => {
                keep.push(best_idx.get(key) == Some(&i));
            }
            _ => keep.push(true),
        }
    }
    // Relabel + count the surviving representatives.
    let mut idx = 0usize;
    rows.retain(|_| {
        let k = keep[idx];
        idx += 1;
        k
    });
    for r in &mut rows {
        if let Some(key) = workload_group_key(&r.entry) {
            let n = counts.get(&key).copied().unwrap_or(0);
            if n >= 2 {
                r.replicas = Some(n);
                // Relabel to the workload (`<ns>/<workload-name>`), dropping the `Pod/<replica>`
                // tail — the merged row represents the controller, not one pod.
                if let Some((ns, rest)) = key.split_once('/')
                    && let Some(workload) = rest.strip_prefix("Pod/")
                {
                    r.entry = format!("{ns}/{workload}");
                }
            }
        }
    }
    rows
}

/// Map and URGENCY-sort a snapshot of findings into props (brief §5). Only breach-relevant
/// findings are surfaced — the caller passes the breach-relevant set. Pod-replica collapse and
/// fan-out collapse run first, then the urgency sort (stable within a rank, by entry for
/// determinism).
pub(super) fn map_findings(
    findings: &[Finding],
    judgements: &[Judgement],
    blind_nodes: &HashSet<String>,
) -> Vec<FindingProps> {
    let mut rows: Vec<FindingProps> = findings
        .iter()
        .filter(|f| f.breach_relevant)
        .map(|f| finding_props(f, judgements, blind_nodes))
        .collect();
    rows = collapse_pod_replicas(rows);
    rows = collapse_fanout(rows);
    rows.sort_by(|a, b| {
        urgency_rank(a)
            .cmp(&urgency_rank(b))
            .then(a.entry.cmp(&b.entry))
            .then(a.objective.cmp(&b.objective))
    });
    rows
}

#[cfg(test)]
mod tests;
