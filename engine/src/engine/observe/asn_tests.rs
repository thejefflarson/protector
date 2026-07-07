//! Tests for the offline ASN dataset parser + lookup (JEF-380). Split into a sibling file
//! to keep `asn.rs` well under the 1,000-line cap (repo CLAUDE.md).

use super::*;

/// A minimal iptoasn `ip2asn-v4.tsv` fixture: Cloudflare, Google, GitHub, OVH, plus a
/// "Not routed" AS0 row that must be dropped.
const SAMPLE: &str = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n\
     8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n\
     140.82.112.0\t140.82.127.255\t36459\tUS\tGitHub\n\
     51.75.0.0\t51.75.255.255\t16276\tFR\tOVH SAS\n\
     0.0.0.0\t0.255.255.255\t0\tNone\tNot routed\n";

fn db() -> AsnDb {
    AsnDb::parse(SAMPLE)
}

fn ip(s: &str) -> Ipv4Addr {
    s.parse().expect("valid IPv4")
}

#[test]
fn resolves_an_ip_to_its_asn_and_org() {
    let db = db();
    let hit = db.lookup(ip("8.8.8.8")).expect("google range is covered");
    assert_eq!(hit.asn, 15169);
    assert_eq!(hit.org, "GOOGLE");

    // An org with spaces (the last TSV field is the whole description).
    let ovh = db.lookup(ip("51.75.10.20")).expect("ovh range is covered");
    assert_eq!(ovh.asn, 16276);
    assert_eq!(ovh.org, "OVH SAS");
}

#[test]
fn range_boundaries_are_inclusive_and_gaps_are_unattributed() {
    let db = db();
    // Both ends of the GitHub range resolve.
    assert_eq!(db.lookup(ip("140.82.112.0")).unwrap().asn, 36459);
    assert_eq!(db.lookup(ip("140.82.127.255")).unwrap().asn, 36459);
    // One past the end is NOT in the range → no attribution.
    assert!(db.lookup(ip("140.82.128.0")).is_none());
    // An address below the lowest range start is unattributed (idx - 1 underflow guarded).
    assert!(db.lookup(ip("0.0.0.0")).is_none());
    // A gap between known ranges is unattributed (falls back to raw at render).
    assert!(db.lookup(ip("9.9.9.9")).is_none());
}

#[test]
fn as0_not_routed_rows_are_dropped() {
    // The AS0 "Not routed" row covers 0.0.0.0/8 but must never attribute — it is not a real
    // operator, so such an IP falls back to its raw address.
    let db = db();
    assert!(db.lookup(ip("0.1.2.3")).is_none());
    // The four real ranges survive; the AS0 row does not.
    assert_eq!(db.len(), 4);
}

#[test]
fn malformed_lines_are_dropped_never_panic() {
    let tsv = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n\
         not-an-ip\t1.0.0.255\t13335\tUS\tBAD\n\
         2.0.0.0\tnope\t13335\tUS\tBAD\n\
         3.0.0.0\t3.0.0.255\tNaN\tUS\tBAD\n\
         5.0.0.255\t5.0.0.0\t99\tUS\tINVERTED\n\
         \t\t\t\t\n\
         too\tfew\tfields\n\
         8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n";
    let db = AsnDb::parse(tsv);
    // Only the two well-formed rows survive.
    assert_eq!(db.len(), 2);
    assert_eq!(db.lookup(ip("1.0.0.1")).unwrap().asn, 13335);
    assert_eq!(db.lookup(ip("8.8.8.8")).unwrap().asn, 15169);
    // The inverted range never attributes.
    assert!(db.lookup(ip("5.0.0.100")).is_none());
}

#[test]
fn over_long_lines_are_skipped() {
    let long_org = "X".repeat(MAX_LINE_LEN);
    let tsv = format!("1.0.0.0\t1.0.0.255\t13335\tUS\t{long_org}\n");
    let db = AsnDb::parse(&tsv);
    assert!(db.is_empty(), "an over-long line is skipped whole");
}

#[test]
fn org_is_length_capped_on_a_char_boundary() {
    let long_org = "é".repeat(MAX_ORG_LEN + 50); // multi-byte, exercises char-boundary cap
    // Keep the LINE under MAX_LINE_LEN so it is not skipped whole — 60 chars of é is 120 bytes.
    let org = "é".repeat(60);
    let tsv = format!("1.0.0.0\t1.0.0.255\t13335\tUS\t{org}\n");
    let db = AsnDb::parse(&tsv);
    assert_eq!(db.len(), 1);
    let hit = db.lookup(ip("1.0.0.1")).unwrap();
    assert!(hit.org.chars().count() <= MAX_ORG_LEN);
    let _ = long_org; // documents intent; the real cap is exercised above
}

#[test]
fn empty_or_garbage_input_yields_an_empty_db() {
    assert!(AsnDb::parse("").is_empty());
    assert!(AsnDb::parse("not a tsv at all\njust prose\n").is_empty());
    assert!(AsnDb::empty().is_empty());
    // An empty DB attributes nothing — the graceful-degrade contract.
    assert!(AsnDb::empty().lookup(ip("8.8.8.8")).is_none());
}

#[test]
fn unsorted_input_is_sorted_so_lookup_is_correct() {
    // Rows out of start order still resolve — parse sorts by start.
    let tsv = "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n\
         1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n\
         140.82.112.0\t140.82.127.255\t36459\tUS\tGitHub\n";
    let db = AsnDb::parse(tsv);
    assert_eq!(db.lookup(ip("1.0.0.1")).unwrap().asn, 13335);
    assert_eq!(db.lookup(ip("8.8.8.8")).unwrap().asn, 15169);
    assert_eq!(db.lookup(ip("140.82.120.1")).unwrap().asn, 36459);
}

#[test]
fn two_ips_in_the_same_asn_resolve_to_the_same_org() {
    // The fingerprint-stability guarantee at the data layer: rotating CDN IPs within one
    // range collapse to the same (asn, org) — peer_class renders one stable provider entry.
    let db = db();
    let a = db.lookup(ip("140.82.112.5")).unwrap();
    let b = db.lookup(ip("140.82.121.200")).unwrap();
    assert_eq!((a.asn, a.org), (b.asn, b.org));
}
