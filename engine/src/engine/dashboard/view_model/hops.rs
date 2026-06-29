//! The attack path as a TEXT HOP-LIST (JEF-255) — not a graph. v1 rendered the path with a
//! 1.5 MB vendored Mermaid bundle; v2 retires it and shows the proven path as plain,
//! escapable text the operator can read top-to-bottom:
//!
//! ```text
//! web (internet-reachable)
//!  └→ reaches store   ✂ cut here (arm network)
//!     └→ can read secret/app/session-key  ← objective
//! ```
//!
//! Built from the finding's proven `path` steps. Pure data — the renderer (`components::hops`)
//! turns this into nested rows; it never sees a domain type (ADR-0019).

use crate::engine::dashboard::model::{Finding, PathStep};
use crate::engine::graph::NodeKey;

/// One rendered hop of the proven path: the humanized relation + the short node it reaches,
/// and whether THIS hop is the cut point (the single edge the engine would sever).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    /// The humanized relation verb ("reaches", "can read", "mounts", "runs as", "escapes via").
    pub relation: String,
    /// The short node label this hop lands on (namespace stripped).
    pub node: String,
    /// This hop is the proven single-edge cut — the renderer marks it `✂ cut here`.
    pub is_cut: bool,
    /// This hop lands on the objective (the final node) — the renderer marks it `← objective`.
    pub is_objective: bool,
}

/// The whole text hop-list for one entry's chain: the entry head (with its internet-reachable
/// lead) and each downstream hop, the cut point flagged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopList {
    /// The short entry label (the front door the path starts at).
    pub entry: String,
    /// Whether the entry is internet-facing — the renderer leads with "(internet-reachable)".
    pub internet_reachable: bool,
    /// The downstream hops, in path order (entry → … → objective).
    pub hops: Vec<Hop>,
    /// The text cut instruction shown beside the cut hop, when there is a single-edge cut
    /// (e.g. "✂ cut here (arm network)"). `None` when the chain has no clean single cut.
    pub cut_note: Option<String>,
}

/// Build the text hop-list for a finding (JEF-255). The cut hop is the path step whose
/// `from -[relation]-> to` matches the finding's `cut` signature; the cut note names what
/// arming would do. The objective is the path's final `to` (the chain's objective).
pub fn hop_list(f: &Finding) -> HopList {
    let cut_sig = f.cut.as_deref();
    let last_idx = f.path.len().saturating_sub(1);
    let hops = f
        .path
        .iter()
        .enumerate()
        .map(|(i, step)| Hop {
            relation: humanize_relation(&step.relation),
            node: NodeKey::short_of(&step.to).to_string(),
            is_cut: cut_sig.is_some_and(|sig| step_matches_cut(step, sig)),
            is_objective: i == last_idx,
        })
        .collect();
    HopList {
        entry: NodeKey::short_of(&f.entry).to_string(),
        internet_reachable: f.foothold,
        hops,
        cut_note: cut_note(f),
    }
}

/// The cut instruction beside the cut hop. Only a reversible network cut is what arming
/// applies automatically (ADR-0007/0016); the other dispositions are durable GitOps fixes,
/// so the note names the lever honestly rather than implying a one-click cut everywhere.
fn cut_note(f: &Finding) -> Option<String> {
    let _ = f.cut.as_ref()?;
    let note = match f.disposition.as_str() {
        d if d.contains("durable-fix") => "✂ cut here (durable fix — open a PR)",
        d if d.contains("forbidden") => "✂ irreversible — needs a human",
        _ => "✂ cut here (arm network)",
    };
    Some(note.to_string())
}

/// Whether a path step is the proven single-edge cut. The cut signature is
/// `from -[relation]-> to` over the FULL node keys (the same `cut_signature` the engine
/// writes), so we reconstruct the step's signature and compare.
fn step_matches_cut(step: &PathStep, cut_sig: &str) -> bool {
    let step_sig = format!("{} -[{}]-> {}", step.from, step.relation, step.to);
    step_sig == cut_sig
}

/// Humanize a relation token into a plain verb for the hop line. The raw tokens are the
/// graph's edge relations (`reaches/Tcp`, `can-do/get/secrets`, `can-read`, `mounts`,
/// `runs-as`, `escapes-via`); unknown tokens fall through to a cleaned-up form.
pub fn humanize_relation(rel: &str) -> String {
    let head = rel.split('/').next().unwrap_or(rel);
    match head {
        "reaches" => "reaches".to_string(),
        "can-read" | "can-do" => "can read".to_string(),
        "mounts" => "mounts".to_string(),
        "runs-as" => "runs as".to_string(),
        "escapes-via" => "escapes via".to_string(),
        other => other.replace('-', " "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dashboard::model::EntryEvidence;

    fn step(from: &str, rel: &str, to: &str) -> PathStep {
        PathStep {
            from: from.into(),
            relation: rel.into(),
            to: to.into(),
        }
    }

    fn finding_with_path(foothold: bool, cut: Option<&str>, path: Vec<PathStep>) -> Finding {
        Finding {
            entry: "workload/app/Pod/web".into(),
            objective: "secret/app/session-key".into(),
            foothold,
            corroborated: false,
            disposition: "auto-eligible".into(),
            cut: cut.map(str::to_string),
            breach_relevant: true,
            verdict: None,
            path,
            evidence: EntryEvidence::default(),
            recency: None,
        }
    }

    #[test]
    fn builds_hops_with_short_labels_and_marks_objective() {
        let f = finding_with_path(
            true,
            None,
            vec![
                step(
                    "workload/app/Pod/web",
                    "reaches/Tcp",
                    "workload/app/Pod/store",
                ),
                step(
                    "workload/app/Pod/store",
                    "can-read",
                    "secret/app/session-key",
                ),
            ],
        );
        let list = hop_list(&f);
        // `NodeKey::short_of` strips only the FIRST path segment (the node KIND).
        assert_eq!(list.entry, "app/Pod/web");
        assert!(list.internet_reachable);
        assert_eq!(list.hops.len(), 2);
        assert_eq!(list.hops[0].relation, "reaches");
        assert_eq!(list.hops[0].node, "app/Pod/store");
        assert!(!list.hops[0].is_objective);
        assert_eq!(list.hops[1].relation, "can read");
        assert_eq!(list.hops[1].node, "app/session-key");
        assert!(list.hops[1].is_objective);
    }

    #[test]
    fn marks_the_cut_hop_and_names_the_network_lever() {
        let cut = "workload/app/Pod/web -[reaches/Tcp]-> workload/app/Pod/store";
        let f = finding_with_path(
            true,
            Some(cut),
            vec![
                step(
                    "workload/app/Pod/web",
                    "reaches/Tcp",
                    "workload/app/Pod/store",
                ),
                step(
                    "workload/app/Pod/store",
                    "can-read",
                    "secret/app/session-key",
                ),
            ],
        );
        let list = hop_list(&f);
        assert!(list.hops[0].is_cut, "first hop is the cut");
        assert!(!list.hops[1].is_cut);
        assert_eq!(list.cut_note.as_deref(), Some("✂ cut here (arm network)"));
    }

    #[test]
    fn durable_fix_disposition_names_a_pr_not_a_network_cut() {
        let cut = "a -[mounts]-> b";
        let mut f = finding_with_path(false, Some(cut), vec![step("a", "mounts", "b")]);
        f.disposition = "durable-fix PR".into();
        let list = hop_list(&f);
        assert_eq!(
            list.cut_note.as_deref(),
            Some("✂ cut here (durable fix — open a PR)")
        );
    }

    #[test]
    fn no_cut_signature_yields_no_note() {
        let f = finding_with_path(false, None, vec![step("a", "reaches", "b")]);
        assert_eq!(hop_list(&f).cut_note, None);
    }
}
