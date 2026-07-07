//! The ASN dataset: attribute an internet IP to the network **provider** (autonomous
//! system) that announces it — GitHub, Amazon, Cloudflare, OVH — from an OFFLINE dataset
//! (JEF-380).
//!
//! This is the network-egress analogue of the KEV/EPSS feeds ([`super::exploit_intel`],
//! [`super::epss`]): a file synced into the cluster by a CronJob (ADR-0015 feed pattern),
//! which the engine only ever *reads* — no reverse DNS, no WHOIS, no network lookup of any
//! kind (zero egress). The dataset is [iptoasn.com](https://iptoasn.com)'s free,
//! no-license `ip2asn-v4.tsv`: one row per contiguous IPv4 range,
//! `range_start<TAB>range_end<TAB>AS_number<TAB>country<TAB>AS_description`.
//!
//! Two things this buys the adjudicator (JEF-380):
//!   1. **The salient signal** — egress to `OVH SAS [AS16276]` (cheap low-reputation
//!      hosting) is a different risk from egress to `GitHub [AS36459]`; the raw rotating
//!      CDN IP told the model nothing, the provider tells it a lot.
//!   2. **The churn fix** — a CDN (ghcr / sigstore / google / AWS) rotates through dozens of
//!      IPs, so a wide runtime window (JEF-378) saw a churning *set of IPs* that rebuilt the
//!      prompt (and busted the verdict cache) every pass. Collapsing those IPs to their
//!      STABLE provider set (rendered in [`super::peer_class`]) makes the prompt
//!      fingerprint-stable across rotation.
//!
//! Like KEV/EPSS the parse is pure, lenient, and unit-tested; a missing/empty/malformed feed
//! degrades to an empty DB — every internet peer then falls back to its raw `IP:port`, which
//! is exactly today's pre-feed behavior, never a crash. Wrapped in a
//! [`ReloadableFeed`](super::feed_reload::ReloadableFeed) so a daily CronJob refresh
//! hot-swaps without a restart.
//!
//! Memory is kept lean for a Pi (engine limit 256Mi): the ~470k IPv4 ranges are stored as a
//! flat `Vec` of `(u32 start, u32 end, u32 asn, Arc<str> org)` sorted by start (lookup is a
//! binary search), and the org descriptions are **interned** (`Arc<str>`) so the tens of
//! thousands of adjacent ranges announced by the same operator share one allocation —
//! ~20MB resident for the whole v4 table.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

/// The longest input line we will look at. iptoasn rows are short
/// (`1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET` — well under 200 bytes); a longer line is
/// malformed (or hostile) and is skipped before any field work, so a corrupt feed can never
/// drive an unbounded allocation.
const MAX_LINE_LEN: usize = 512;

/// The longest org description we retain. Real AS descriptions are short company names; we
/// cap so a corrupt/hostile row can't bloat memory or the prompt. Truncation is on a char
/// boundary (never mid-codepoint). Injection characters are neutralized at render by the
/// prompt's `fence`/`sanitize`, not here — this cap is purely a size bound.
const MAX_ORG_LEN: usize = 128;

/// A resolved ASN attribution for an IP: the autonomous-system number and the operator's
/// description (borrowed from the interned store). Rendered as `org [ASxxxxx]` by
/// [`super::peer_class`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsnHit<'a> {
    pub asn: u32,
    pub org: &'a str,
}

/// One contiguous IPv4 range announced by a single autonomous system. IPv4 is stored as its
/// `u32` so a range check is two integer comparisons and the table sorts/binary-searches on
/// `start`.
#[derive(Debug, Clone)]
struct AsnRange {
    start: u32,
    end: u32,
    asn: u32,
    /// Interned operator description — shared across every range this AS announces.
    org: Arc<str>,
}

/// The offline IP→ASN table: IPv4 ranges sorted by start, searched by binary search. Empty
/// is the honest default (no dataset wired / unreadable file) — [`Self::lookup`] returns
/// `None` for every IP, so a peer falls back to its raw address exactly as before the feed.
#[derive(Debug, Default, Clone)]
pub struct AsnDb {
    /// Non-overlapping ranges sorted ascending by `start` (iptoasn ships them disjoint;
    /// the sort makes the binary search correct regardless of input order).
    ranges: Vec<AsnRange>,
}

impl AsnDb {
    /// An empty DB — no attribution known. The honest default when no ASN dataset is
    /// configured (or the file is unreadable): every internet peer falls back to its raw
    /// `IP:port`, exactly today's pre-feed behavior.
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many ranges the table carries (for load/reload logs and readiness).
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Attribute an IPv4 address to its announcing AS, or `None` when no range covers it
    /// (an unrouted / private / unknown address). A binary search for the last range whose
    /// `start <= ip`, then a bounds check against its `end`. `AS0` ("Not routed" in the
    /// iptoasn data) is dropped at parse time, so a hit here is always a real attribution.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<AsnHit<'_>> {
        let key = u32::from(ip);
        // The number of ranges whose start is <= key; the covering candidate (if any) is the
        // one just before that partition point.
        let idx = self.ranges.partition_point(|r| r.start <= key);
        let range = self.ranges.get(idx.checked_sub(1)?)?;
        (key <= range.end).then_some(AsnHit {
            asn: range.asn,
            org: &range.org,
        })
    }

    /// Parse the iptoasn `ip2asn-v4.tsv` text. Each row is five TAB-separated fields —
    /// `range_start`, `range_end`, `AS_number`, `country`, `AS_description` — e.g. (tabs shown
    /// as `\t`): `1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET`, `8.8.8.0\t8.8.8.255\t15169\t
    /// US\tGOOGLE`, and the unrouted sentinel `0.0.0.0\t0.255.255.255\t0\tNone\tNot routed`.
    ///
    /// Lenient by contract (mirrors [`EpssStore::parse`](super::epss::EpssStore::parse)): a
    /// line that is over-long, has too few fields, carries a non-numeric range/ASN, or is
    /// inverted (`start > end`) is dropped — a malformed feed yields fewer (or zero) ranges,
    /// never a panic. `AS0` rows ("Not routed") are dropped so an unrouted address reads as
    /// no attribution. Org descriptions are interned and length-capped. The table is sorted
    /// by `start` so [`Self::lookup`] can binary-search it.
    pub fn parse(contents: &str) -> Self {
        // Intern org descriptions: the tens of thousands of adjacent ranges announced by one
        // operator then share a single `Arc<str>` allocation. Dropped after the parse.
        let mut intern: HashMap<String, Arc<str>> = HashMap::new();
        let mut ranges: Vec<AsnRange> = Vec::new();
        for line in contents.lines() {
            let line = line.trim_end_matches(['\r', '\n']);
            // Skip blanks and over-long (malformed/hostile) lines before any field work.
            if line.is_empty() || line.len() > MAX_LINE_LEN {
                continue;
            }
            let mut fields = line.split('\t');
            let (Some(start), Some(end), Some(asn), Some(_country), Some(org)) = (
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
            ) else {
                continue;
            };
            // range_start / range_end are DOTTED IPv4 strings (`1.0.0.0`), stored as their u32
            // so a range check is two integer comparisons; the AS number is a plain integer.
            let (Ok(start), Ok(end), Ok(asn)) = (
                start.trim().parse::<Ipv4Addr>().map(u32::from),
                end.trim().parse::<Ipv4Addr>().map(u32::from),
                asn.trim().parse::<u32>(),
            ) else {
                continue;
            };
            // Inverted range (corrupt row) or the "Not routed" AS0 sentinel — no honest
            // attribution, so drop it (the IP then falls back to its raw address).
            if start > end || asn == 0 {
                continue;
            }
            let org = bounded_org(org);
            if org.is_empty() {
                continue;
            }
            let org = match intern.get(&org) {
                Some(shared) => shared.clone(),
                None => {
                    let shared: Arc<str> = Arc::from(org.as_str());
                    intern.insert(org, shared.clone());
                    shared
                }
            };
            ranges.push(AsnRange {
                start,
                end,
                asn,
                org,
            });
        }
        // Sort by start so lookup can binary-search; the ranges are disjoint in the source,
        // so start order is a total order over the table.
        ranges.sort_by_key(|r| r.start);
        Self { ranges }
    }
}

/// Trim an org description and cap it to [`MAX_ORG_LEN`] characters on a char boundary. Kept
/// deliberately narrow: it only bounds SIZE. The prompt's `fence`/`sanitize` neutralize any
/// injection characters when the value is rendered, so this does not need to.
fn bounded_org(raw: &str) -> String {
    raw.trim().chars().take(MAX_ORG_LEN).collect()
}

#[cfg(test)]
#[path = "asn_tests.rs"]
mod tests;
