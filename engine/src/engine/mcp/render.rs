//! Per-entry tiered redaction + the withheld-not-omitted response contract (ADR-0031 §2/§4,
//! JEF-488). Redaction is applied PER ENTRY as it is serialized — never a bulk dump filtered
//! afterward (§2). Every field is present at every tier: below its unlock tier it is a typed
//! SENTINEL string, at/above it is the real value — so a redacted answer is never an empty shape.
//! Each response carries a top-level [`manifest`] `{tier, withheld:[{kind,count,unlock}]}`.
//!
//! The tiers are expressed as WHICH shared scrubbers run ([`scrub`]): `redacted` runs all,
//! `forensic` relaxes the CVE scrubber, `raw` relaxes the name scrubber. NONE ever relaxes a
//! secret-VALUE scrubber, because no value is ever read into a response (§2).

use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::engine::graph::NodeKey;
use crate::engine::redact::{
    redacted_attack_outcome, sanitize, scrub_cve_tokens, scrub_decision_names,
};
use crate::engine::state::{Delta, Finding, Judgement};

use super::tiering::EffectiveTier;

/// Hard cap on distinct ATT&CK techniques surfaced per entry — mirrors the notifier's cap so the
/// two egress paths agree on how much "outcome" a summary discloses.
const ATTACK_CAP: usize = 8;

/// The sentinel for a withheld entry/workload identity (a path/topology fact — forensic).
const S_ENTRY: &str = "[redacted — workload identity; forensic tier required]";
/// The sentinel for withheld proven paths (topology — forensic).
const S_PATHS: &str = "[redacted — proven path/topology; forensic tier required]";
/// The sentinel for a withheld CVE inventory (forensic).
const S_CVES: &str = "[redacted — CVE inventory; forensic tier required]";
/// The sentinel for a withheld judgement prompt/reply (forensic).
const S_JUDGEMENT: &str = "[redacted — judgement prompt+reply; forensic tier required]";
/// The sentinel for a withheld blind-node name (topology — forensic).
const S_NODE: &str = "[redacted — node name; forensic tier required]";
/// The sentinel for withheld objective secret names (raw).
const S_OBJECTIVES: &str = "[redacted — objective/secret names; raw tier required]";
/// The sentinel for the withheld free-text verdict reason (forensic). The model's `why` prose is
/// authored by the judge model and routinely echoes the entry/namespace/peer/path it reasoned over
/// — topology the shared scrubbers CANNOT reliably strip (they only scrub the decision's SECRET
/// names + CVE tokens, not arbitrary workload/node/path strings). So the free-text reason is
/// withheld below `forensic` (where paths/topology are already disclosed), leaving only the static
/// verdict LABEL at `redacted`.
const S_REASON: &str = "[redacted — verdict reason; forensic tier required]";

/// Reduce `text` to the tier's disclosure by composing the shared scrubbers: always [`sanitize`]
/// (structure); below `raw` also [`scrub_decision_names`] (the decision's SECRET names); below
/// `forensic` also [`scrub_cve_tokens`]. This is the exact layering the notifier's redacted payload
/// uses (`super::super::notify`), so the two egress paths cannot drift.
fn scrub(text: &str, tier: EffectiveTier, secret_names: &[&str]) -> String {
    let mut out = sanitize(text);
    if tier < EffectiveTier::Raw {
        out = scrub_decision_names(&out, secret_names);
    }
    if tier < EffectiveTier::Forensic {
        out = scrub_cve_tokens(&out);
    }
    out
}

/// A stable, NON-REVERSIBLE opaque handle for an entry, so a `redacted`-tier client can reference a
/// finding (e.g. to pass to `explain_verdict`) without the entry key — which is itself a
/// path/topology fact — ever appearing in a redacted response. FNV-1a/64, rendered as 16 hex chars
/// (deterministic across runs, unlike a process-seeded hasher).
pub fn entry_ref(entry: &str) -> String {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    for byte in entry.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:016x}")
}

/// The stable Δ label for the freshness block (no free text, no names).
fn delta_label(delta: Delta) -> &'static str {
    match delta {
        Delta::New => "new",
        Delta::Escalated => "escalated",
        Delta::DeEscalated => "de-escalated",
        Delta::Unchanged => "unchanged",
        Delta::Restored => "restored",
    }
}

/// The distilled per-entry facts the tiered renderer draws from — one entry's group of
/// breach-relevant findings folded into the fields each tier is allowed to disclose. Assembled once
/// per entry so redaction is applied per-entry at serialization (never a bulk filter).
pub struct EntryData<'a> {
    /// The entry workload key (a path/topology fact — forensic).
    pub entry: &'a str,
    /// The typed verdict for the entry, if judged.
    pub verdict: Option<&'a crate::engine::reason::adjudicate::Verdict>,
    /// The distinct objective keys reached (their names are secrets — raw).
    pub objectives: Vec<&'a str>,
    /// One representative proven-path chain per finding (topology — forensic).
    pub paths: Vec<String>,
    /// The distinct CVE ids on the entry image, with reachability (forensic).
    pub cves: Vec<(&'a str, &'a str, &'a str, Option<&'a str>)>,
    /// The decision's SECRET names to scrub below `raw` — full keys + bare names of secret-kind
    /// nodes among the objectives and path hops.
    pub secret_names: Vec<String>,
    /// The ATT&CK refs realized (technique IDs surface at every tier).
    pub attacks: Vec<crate::engine::graph::attack::AttackRef>,
    /// Whether the entry's workload sits on a runtime-blind node.
    pub blind: bool,
    /// The entry's node name, if known (topology — forensic).
    pub node: Option<&'a str>,
    /// The entry's Δ since the last pass.
    pub delta: Option<Delta>,
    /// Whether a live runtime signal corroborated the chain.
    pub corroborated: bool,
    /// The verbatim model judgement for the entry, if captured (forensic).
    pub judgement: Option<&'a Judgement>,
}

impl<'a> EntryData<'a> {
    /// Fold a group of breach-relevant findings sharing one entry into the distilled facts. `group`
    /// must be non-empty and every finding must share `entry`.
    pub fn from_group(
        entry: &'a str,
        group: &[&'a Finding],
        judgement: Option<&'a Judgement>,
        blind: bool,
    ) -> EntryData<'a> {
        let mut objectives: Vec<&str> = Vec::new();
        let mut paths: Vec<String> = Vec::new();
        let mut cves: Vec<(&str, &str, &str, Option<&str>)> = Vec::new();
        let mut secrets: BTreeSet<String> = BTreeSet::new();
        let mut attacks: Vec<crate::engine::graph::attack::AttackRef> = Vec::new();
        let mut seen_obj: BTreeSet<&str> = BTreeSet::new();
        let mut seen_cve: BTreeSet<&str> = BTreeSet::new();

        for f in group {
            if seen_obj.insert(f.objective.as_str()) {
                objectives.push(f.objective.as_str());
                collect_secret_name(&f.objective, &mut secrets);
            }
            attacks.push(f.attack);
            paths.push(path_chain(f));
            for step in &f.path {
                collect_secret_name(&step.from, &mut secrets);
                collect_secret_name(&step.to, &mut secrets);
            }
            for cve in &f.evidence.cves {
                if seen_cve.insert(cve.id.as_str()) {
                    cves.push((
                        cve.id.as_str(),
                        cve.severity.as_str(),
                        cve.reachability.as_str(),
                        cve.title.as_deref(),
                    ));
                }
            }
        }

        EntryData {
            entry,
            verdict: group.iter().find_map(|f| f.verdict.as_ref()),
            objectives,
            paths,
            cves,
            secret_names: secrets.into_iter().collect(),
            attacks,
            blind,
            node: group.iter().find_map(|f| f.node.as_deref()),
            delta: group
                .iter()
                .find_map(|f| f.recency.as_ref())
                .map(|r| r.delta),
            corroborated: group.iter().any(|f| f.corroborated),
            judgement,
        }
    }

    /// The secret names as `&str` slices for the shared scrubber.
    fn secret_name_refs(&self) -> Vec<&str> {
        self.secret_names.iter().map(String::as_str).collect()
    }

    /// Render this entry at `tier`, with every field present (real value or typed sentinel).
    pub fn render(&self, tier: EffectiveTier) -> Value {
        let names = self.secret_name_refs();
        let label = self.verdict.map(|v| v.label()).unwrap_or("awaiting");
        let reason = self.reason_field(tier, &names);

        json!({
            "ref": entry_ref(self.entry),
            "verdict": { "label": label, "reason": reason },
            "objective_count": self.objectives.len(),
            "techniques": redacted_attack_outcome(self.attacks.iter(), ATTACK_CAP),
            "coverage": {
                "runtime_blind": self.blind,
                "node": self.node_field(tier),
            },
            "freshness": {
                "delta": self.delta.map(delta_label).unwrap_or("unknown"),
                "corroborated": self.corroborated,
            },
            "entry": self.entry_field(tier, &names),
            "objectives": self.objectives_field(tier, &names),
            "paths": self.paths_field(tier, &names),
            "cve_ids": self.cves_field(tier),
            "judgement": self.judgement_field(tier, &names),
        })
    }

    /// The free-text verdict reason. `awaiting judgement` when no verdict yet (a static, safe
    /// string). Otherwise the model's `why` prose — WITHHELD below `forensic` (it can echo
    /// entry/namespace/peer/path topology the scrubbers can't reliably strip), and the scrubbed prose
    /// at forensic+ (where that topology is already disclosed). The static verdict LABEL always rides
    /// alongside, so `redacted` still carries the decision.
    fn reason_field(&self, tier: EffectiveTier, names: &[&str]) -> Value {
        match self.verdict {
            None => json!("awaiting judgement"),
            Some(_) if tier < EffectiveTier::Forensic => json!(S_REASON),
            Some(v) => json!(scrub(&v.summary(), tier, names)),
        }
    }

    /// The blind-node name — real at forensic+ (topology), sentinel below. `null` when not blind.
    fn node_field(&self, tier: EffectiveTier) -> Value {
        if !self.blind {
            return Value::Null;
        }
        match (tier >= EffectiveTier::Forensic, self.node) {
            (true, Some(node)) => json!(sanitize(node)),
            (true, None) => Value::Null,
            (false, _) => json!(S_NODE),
        }
    }

    /// The entry workload key — real (sanitized) at forensic+, sentinel below.
    fn entry_field(&self, tier: EffectiveTier, names: &[&str]) -> Value {
        if tier >= EffectiveTier::Forensic {
            json!(scrub(self.entry, tier, names))
        } else {
            json!(S_ENTRY)
        }
    }

    /// The objective short labels — present at forensic+ (secret names scrubbed until raw), sentinel
    /// below forensic.
    fn objectives_field(&self, tier: EffectiveTier, names: &[&str]) -> Value {
        if tier < EffectiveTier::Forensic {
            return json!(S_OBJECTIVES);
        }
        let labels: Vec<String> = self
            .objectives
            .iter()
            .map(|o| scrub(NodeKey::short_of(o), tier, names))
            .collect();
        json!(labels)
    }

    /// The proven-path chains — present at forensic+ (secret names scrubbed until raw), sentinel
    /// below forensic.
    fn paths_field(&self, tier: EffectiveTier, names: &[&str]) -> Value {
        if tier < EffectiveTier::Forensic {
            return json!(S_PATHS);
        }
        let chains: Vec<String> = self.paths.iter().map(|p| scrub(p, tier, names)).collect();
        json!(chains)
    }

    /// The CVE inventory — present at forensic+, sentinel below. CVE ids are the crown-jewel the
    /// `forensic` tier unlocks; titles are untrusted free-text, so they are still `sanitize`d.
    fn cves_field(&self, tier: EffectiveTier) -> Value {
        if tier < EffectiveTier::Forensic {
            return json!(S_CVES);
        }
        let rows: Vec<Value> = self
            .cves
            .iter()
            .map(|(id, severity, reachability, title)| {
                json!({
                    "id": sanitize(id),
                    "severity": sanitize(severity),
                    "reachability": sanitize(reachability),
                    "title": title.map(sanitize),
                })
            })
            .collect();
        json!(rows)
    }

    /// The verbatim judgement prompt+reply — present at forensic+ (scrubbed per tier: secret names
    /// stay scrubbed until raw, CVE ids unlocked at forensic), sentinel below. `null` when no
    /// judgement was captured for the entry.
    fn judgement_field(&self, tier: EffectiveTier, names: &[&str]) -> Value {
        let Some(j) = self.judgement else {
            return Value::Null;
        };
        if tier < EffectiveTier::Forensic {
            return json!(S_JUDGEMENT);
        }
        json!({
            "prompt": j.prompt.as_deref().map(|p| scrub(p, tier, names)),
            "reply": j.reply.as_deref().map(|r| scrub(r, tier, names)),
        })
    }

    /// The distinct CVE-id count for the manifest (leaks nothing — a count, ADR-0018 precedent).
    pub fn cve_count(&self) -> usize {
        self.cves.len()
    }

    /// The distinct secret-name count for the manifest.
    pub fn secret_name_count(&self) -> usize {
        // The bare-name/full-key pairs double-count; report the number of distinct SECRET keys by
        // halving is unreliable, so report the objective count (one secret per objective at most) as
        // the honest upper bound of "which secrets".
        self.objectives.len()
    }

    /// The proven-path count for the manifest.
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }
}

/// One representative proven-path chain of a finding as a compact `a → b → c` string over the short
/// node labels (the full keys stay available to the scrubber via the finding's own hops).
fn path_chain(f: &Finding) -> String {
    let mut nodes: Vec<&str> = Vec::new();
    for (i, step) in f.path.iter().enumerate() {
        if i == 0 {
            nodes.push(NodeKey::short_of(&step.from));
        }
        nodes.push(NodeKey::short_of(&step.to));
    }
    if nodes.is_empty() {
        return NodeKey::short_of(&f.entry).to_string();
    }
    nodes.join(" -> ")
}

/// Push a secret-kind node key's full key + bare last segment onto the scrub set. A non-secret node
/// (workload/host/endpoint/…) is topology the `forensic` tier discloses, so it is NOT added.
fn collect_secret_name(key: &str, out: &mut BTreeSet<String>) {
    if NodeKey::kind_of(key) != "secret" {
        return;
    }
    out.insert(key.to_string());
    if let Some((_, bare)) = key.rsplit_once('/') {
        out.insert(bare.to_string());
    }
}

/// One withheld line in the top-level redaction manifest: what kind of cluster fact is withheld at
/// the active tier, how many of them, and which tier unlocks it (or `never`).
pub struct Withheld {
    /// The kind of withheld fact (`entry`, `paths`, `cve_ids`, `judgement`, `objective_names`,
    /// `secret_names`, `secret_values`).
    pub kind: &'static str,
    /// How many are withheld (a count leaks nothing crown-jewel — ADR-0018 precedent).
    pub count: usize,
    /// The tier that unlocks them, or `never`.
    pub unlock: &'static str,
}

impl Withheld {
    fn to_value(&self) -> Value {
        json!({ "kind": self.kind, "count": self.count, "unlock": self.unlock })
    }
}

/// The top-level redaction manifest `{tier, withheld:[{kind,count,unlock}]}` (ADR-0031 §4). Present
/// on EVERY response so a redacted answer is self-describing, never a silently-empty shape.
pub fn manifest(tier: EffectiveTier, withheld: &[Withheld]) -> Value {
    json!({
        "tier": tier.as_str(),
        "withheld": withheld.iter().map(Withheld::to_value).collect::<Vec<_>>(),
    })
}

/// Build the aggregate withheld list for a set of entries rendered at `tier` (the counts sum across
/// entries). `secret_values` is ALWAYS withheld with `unlock:"never"` — values have no unlock tier
/// and no read path (§2), stated explicitly so a client sees the guarantee.
pub fn withheld_for(entries: &[EntryData<'_>], tier: EffectiveTier) -> Vec<Withheld> {
    let secret_values = entries.iter().map(EntryData::secret_name_count).sum();
    let mut out = vec![Withheld {
        kind: "secret_values",
        count: secret_values,
        unlock: "never",
    }];

    if tier < EffectiveTier::Raw {
        out.push(Withheld {
            kind: "secret_names",
            count: entries.iter().map(EntryData::secret_name_count).sum(),
            unlock: "raw",
        });
        out.push(Withheld {
            kind: "objective_names",
            count: entries.iter().map(|e| e.objectives.len()).sum(),
            unlock: "raw",
        });
    }
    if tier < EffectiveTier::Forensic {
        out.push(Withheld {
            kind: "entry",
            count: entries.len(),
            unlock: "forensic",
        });
        out.push(Withheld {
            kind: "paths",
            count: entries.iter().map(EntryData::path_count).sum(),
            unlock: "forensic",
        });
        out.push(Withheld {
            kind: "cve_ids",
            count: entries.iter().map(EntryData::cve_count).sum(),
            unlock: "forensic",
        });
        out.push(Withheld {
            kind: "judgement",
            count: entries.iter().filter(|e| e.judgement.is_some()).count(),
            unlock: "forensic",
        });
        out.push(Withheld {
            kind: "verdict_reason",
            count: entries.iter().filter(|e| e.verdict.is_some()).count(),
            unlock: "forensic",
        });
    }
    out
}
