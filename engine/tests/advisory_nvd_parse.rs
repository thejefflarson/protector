//! Parse-proof for the feed-fetcher's advisory source (JEF-238, advisory part).
//!
//! The feed-fetcher sidecar (chart `templates/deployment.yaml`) fetches the public NVD
//! CVE JSON 2.0 *recent* + *modified* feeds, gunzips them, and writes the RAW NVD JSON to
//! `/var/lib/protector/feeds/advisory.json` — no `jq`, no transform, no extra container
//! image. The reshape onto the engine's `Advisory` fields happens IN the engine, in
//! `AdvisoryStore::parse`, under the same parse-time length-caps as every other shape. So
//! the acceptance gate of the ticket is exactly this: **the engine parses the raw NVD feed
//! the sidecar drops in, mapping NVD's verbose schema onto summary / cwe / fix_ref.**
//!
//! `fixtures/advisory_nvd_recent_sample.json` is a small, lean slice of a real NVD recent
//! feed (three genuine 2026 CVEs, trimmed to the fields the parser reads) plus one curated
//! multi-CWE / Patch-tagged entry (Log4Shell) to exercise the CWE-list and Patch-reference
//! paths. If the NVD shape ever drifts from what `AdvisoryStore::parse` reads, this fails.

use protector::engine::observe::advisory::AdvisoryStore;

/// Load the committed raw-NVD fixture exactly as the engine would load `advisory.json`
/// from the shared feeds volume the sidecar writes.
fn store() -> AdvisoryStore {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/advisory_nvd_recent_sample.json"
    );
    AdvisoryStore::from_file(path)
}

#[test]
fn engine_parses_the_raw_nvd_feed() {
    let store = store();
    // The fixture carries four NVD entries; every one must parse (none dropped as junk).
    assert_eq!(
        store.len(),
        4,
        "the engine must parse every CVE in the raw NVD feed the sidecar drops in"
    );
}

#[test]
fn nvd_fields_map_onto_advisory_fields() {
    let store = store();

    // A real NVD recent entry: description -> summary, weakness -> cwe, reference -> fix_ref.
    let a = store
        .get("CVE-2026-11911")
        .expect("a parsed NVD entry is keyed by its CVE id");
    assert!(
        a.summary
            .starts_with("The Simple File List plugin for WordPress"),
        "the NVD English description maps onto `summary`"
    );
    assert_eq!(
        a.cwe,
        vec!["CWE-22"],
        "the NVD weakness value maps onto `cwe`"
    );
    // The first NVD reference url maps onto `fix_ref` (none is tagged Patch here). It is a
    // long trac url, so the parser's FIX_REF_CAP (64 chars) truncates it — proving the cap
    // applies to NVD-sourced fix refs too, so a long url can't bloat the prompt.
    assert_eq!(
        a.fix_ref.as_deref(),
        Some("https://plugins.trac.wordpress.org/browser/simple-file-list/tags"),
        "the first NVD reference url maps onto `fix_ref`, truncated to the 64-char cap"
    );
    assert_eq!(
        a.fix_ref.as_ref().unwrap().chars().count(),
        64,
        "an NVD reference url is length-capped by the parser"
    );
}

#[test]
fn multi_cwe_drops_nvd_placeholders_and_prefers_patch_reference() {
    let store = store();
    let a = store
        .get("CVE-2021-44228")
        .expect("the multi-CWE entry parses");
    // NVD-CWE-noinfo is an NVD placeholder, not a real CWE class — it must be dropped; the
    // genuine ids survive, sorted/deduped by the parser.
    assert_eq!(
        a.cwe,
        vec!["CWE-502", "CWE-917"],
        "genuine CWE ids survive; the NVD-CWE-* placeholder is dropped"
    );
    // A Patch-tagged reference is preferred over the first-listed url.
    assert_eq!(
        a.fix_ref.as_deref(),
        Some("https://logging.apache.org/log4j/2.x/security.html"),
        "a Patch-tagged NVD reference is preferred for `fix_ref`"
    );
}

#[test]
fn verbose_nvd_summaries_are_length_capped_by_the_parser() {
    // NVD descriptions are long prose (the WordPress entries run ~700 chars). The engine
    // caps `summary` at parse time (JEF-106), so an oversized NVD entry can never bloat the
    // prompt or the verdict fingerprint — proving the cap holds on real NVD input.
    let store = store();
    let a = store
        .get("CVE-2026-11911")
        .expect("the long-description entry parses");
    assert!(
        a.summary.chars().count() <= 280,
        "the parser caps even a long NVD description (got {})",
        a.summary.chars().count()
    );
    assert!(
        !a.summary.is_empty(),
        "the capped summary is still populated, not dropped"
    );
}
