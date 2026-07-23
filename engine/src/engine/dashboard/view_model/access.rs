//! Map the read-only MCP disclosure audit (JEF-490) into the [`AccessViewProps`] the "Access" tab
//! renders. This is the ONE place the audit rows are REDACTED to the CALLER's own tier: a row that
//! recorded a `raw` pull of a crown-jewel entry shows its target-class ONLY to a viewer whose own
//! verified tier unlocks it (forensic+); a lower-tier viewer sees the SAME withheld-workload
//! sentinel the tool emits — never the target itself. Data layer: touches the audit records +
//! the caller's [`Tier`]; the component never does.
//!
//! The audit `entry` is always a workload identity (or the bulk-scope label) — a forensic-tier fact
//! (topology), never a secret NAME (secrets are objectives, not entries) — so gating the target at
//! `forensic` is both correct and complete. Secret names never ride the audit line at all.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::engine::dashboard::auth::claims::Tier;
use crate::engine::mcp::{AccessRecord, BULK_SCOPE, EffectiveTier, WORKLOAD_IDENTITY_WITHHELD};

use super::posture::human_age;
use super::props::{AccessPullRow, AccessTier, AccessViewProps, StatusStripProps, TierRevealRow};

/// Build the "Access" view's props: the caller's own tier chip, the per-tier reveal list, and the
/// newest-first forensic/raw pulls redacted to the caller's tier. `records` are newest-first (the
/// sink's snapshot order); `durable` selects the honest empty-state caveat. Pure given its inputs.
pub fn build(
    strip: StatusStripProps,
    caller_tier: Tier,
    records: &[AccessRecord],
    durable: bool,
) -> AccessViewProps {
    let now = unix_now();
    let pulls: Vec<AccessPullRow> = records
        .iter()
        .map(|r| pull_row(r, caller_tier, now))
        .collect();
    AccessViewProps {
        strip,
        tier: AccessTier::from_claim(caller_tier),
        reveals: reveal_rows(caller_tier),
        pulls,
        durable,
    }
}

/// Redact one audit record to the CALLER's own tier. `who`/`tool`/`tier`/`when` are always shown
/// (an operator may see THAT a raw pull happened, and by whom); only the target-class is gated —
/// the crux of the tier-aware audit (a lower-tier viewer never learns WHAT a higher-tier pull hit).
fn pull_row(record: &AccessRecord, caller_tier: Tier, now: u64) -> AccessPullRow {
    AccessPullRow {
        when: format!(
            "{} ago",
            human_age(now.saturating_sub(record.time_unix_secs))
        ),
        who: record.subject.clone(),
        tool: record.tool.clone(),
        tier: AccessTier::from_effective(record.tier),
        target: redacted_target(&record.entry, caller_tier),
        raw: record.tier == EffectiveTier::Raw,
    }
}

/// The target-class shown for a pull, redacted to `caller_tier`. The bulk-scope label is a fixed
/// constant (leaks nothing — the same for every viewer), so it's shown verbatim. A specific entry is
/// a workload identity (a forensic-tier fact): shown at forensic+, else the withheld-workload
/// sentinel — the SAME vocabulary the tool uses (`WORKLOAD_IDENTITY_WITHHELD`), one string across
/// tool + screen.
fn redacted_target(entry: &str, caller_tier: Tier) -> String {
    if entry == BULK_SCOPE || caller_tier >= Tier::Forensic {
        entry.to_string()
    } else {
        WORKLOAD_IDENTITY_WITHHELD.to_string()
    }
}

/// The static "what each tier reveals/withholds" list, marking which levels the caller holds. Copy
/// only — no cluster data — so it's identical for every viewer save the `held` flag.
fn reveal_rows(caller_tier: Tier) -> Vec<TierRevealRow> {
    let holds = |tier: Tier| caller_tier >= tier;
    vec![
        TierRevealRow {
            tier: AccessTier::Redacted,
            reveals: "verdicts, counts, technique IDs, coverage & freshness".into(),
            withholds: "nothing cluster-specific is disclosed at this tier".into(),
            held: holds(Tier::Redacted),
        },
        TierRevealRow {
            tier: AccessTier::Forensic,
            reveals:
                "judgement prompt+reply, CVE ids + reachability, proven paths, workload & node \
                      names"
                    .into(),
            withholds: "secret names stay scrubbed".into(),
            held: holds(Tier::Forensic),
        },
        TierRevealRow {
            tier: AccessTier::Raw,
            reveals: "secret names (per-entry only — never a bulk dump)".into(),
            withholds: "secret VALUES — never; no tool has a read path to a value".into(),
            held: holds(Tier::Raw),
        },
    ]
}

/// Seconds since the Unix epoch, saturating to 0 (pre-epoch never occurs for the wall clock).
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
