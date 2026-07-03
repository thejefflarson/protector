//! Render-level tests for the Admission/policy view (the webhook floor, brief §6): the tallies
//! header (never blank, honest at zero), the per-image signing inventory (JEF-262 — every posture,
//! the binary if-enforced, honest empty), the deduped decision rows + the "if enforced" what-if, the
//! real fourth nav tab, and escaping of the untrusted image/subject/reason/identity text. These
//! drive the view_model + component directly (no HTTP, no engine), so they are fast and pure. Kept
//! in their own file so `tests.rs` stays under the 1,000-line cap (CLAUDE.md).

use std::time::SystemTime;

use crate::engine::policy_log::PolicyDecisionRecord;
use crate::engine::state::{BakeStats, Finding, ModelHealth, ReadinessConfig, derive_readiness};

use super::page;
use super::view_model::{build_admission_view, build_status_strip};

/// A readiness snapshot for a fully-covered, actively-judging model (mirrors `tests::judging_readiness`).
fn judging_readiness() -> crate::engine::state::Readiness {
    let config = ReadinessConfig {
        model_attached: true,
        kev_count: 5,
        epss_count: 5,
        journal_durable: true,
        armed: false,
    };
    let mut bake = BakeStats::default();
    bake.signals_by_variant.insert("alert".into(), 1);
    derive_readiness(&config, ModelHealth::Ok, &bake, Some(SystemTime::now()))
}

/// Build the persistent strip from a given findings snapshot (the strip the Admission view carries).
fn strip_from(findings: &[Finding]) -> super::view_model::props::StatusStripProps {
    build_status_strip(
        "prod".into(),
        findings,
        &[],
        &judging_readiness(),
        Some(SystemTime::now()),
    )
}

#[allow(clippy::too_many_arguments)]
fn admission_rec(
    decision: &str,
    subject: &str,
    image: &str,
    signature: &str,
    mesh: &str,
    ns: &str,
    reason: &str,
    would_admit: bool,
) -> PolicyDecisionRecord {
    PolicyDecisionRecord::now(
        "admission",
        decision,
        subject,
        image,
        signature,
        mesh,
        ns,
        reason,
    )
    .with_would_admit(would_admit)
}

/// A signing-sweep observation row (JEF-261 shape): `Image/<ref>` subject, posture in `signature`.
fn signing_rec(image: &str, status: &str, reason: &str) -> PolicyDecisionRecord {
    PolicyDecisionRecord::now(
        "image-signature",
        "allow",
        format!("Image/{image}"),
        image,
        status,
        "",
        "",
        reason,
    )
}

fn render(rows: &[PolicyDecisionRecord]) -> String {
    page::admission_page(&build_admission_view(strip_from(&[]), rows)).into_string()
}

#[test]
fn admission_nav_tab_is_a_real_fourth_surface() {
    // The four tabs are all reachable; the Admission tab links to its real route. The merged
    // Action tab replaces the former Trust + Activity pair.
    let html = render(&[]);
    for tab in ["Findings", "Action", "Readiness", "Admission"] {
        assert!(html.contains(tab), "the nav offers the {tab} tab");
    }
    // The retired tabs are gone from the nav.
    assert!(!html.contains(">Trust<"), "no Trust nav label remains");
    assert!(
        !html.contains(">Activity<"),
        "no Activity nav label remains"
    );
    assert!(
        html.contains("?tab=admission"),
        "the Admission tab links to its real route"
    );
}

#[test]
fn admission_tallies_header_is_never_blank_even_at_zero() {
    // The webhook floor's headline: counts honest at zero, so a healthy cluster is never blank.
    let html = render(&[]);
    assert!(html.contains("admitted"), "the admitted tally is rendered");
    assert!(html.contains("audited"), "the audited tally is rendered");
    assert!(html.contains("denied"), "the denied tally is rendered");
    // And the honest-empty bodies, never read as all-clear.
    assert!(
        html.contains("no admission decisions recorded yet"),
        "an empty log reads as no-decisions, not all-clear"
    );
    assert!(
        html.contains("no images observed yet"),
        "an empty inventory reads as nothing-inspected, not all-clear"
    );
    assert!(html.contains("not an all-clear"));
}

#[test]
fn admission_renders_deduped_rows_with_the_if_enforced_what_if() {
    let mut clean = admission_rec(
        "allow",
        "Deployment/web",
        "ghcr.io/org/web:1",
        "verified",
        "verified",
        "default",
        "",
        true,
    );
    clean.count = 42;
    let rows = vec![
        clean,
        // A would-fail MESH gate → the "if enforced" what-if is would-deny.
        admission_rec(
            "audit",
            "Deployment/legacy",
            "docker.io/legacy:old",
            "verified",
            "would-fail",
            "payments",
            "not mesh-injected",
            false,
        ),
    ];
    let html = render(&rows);
    // The derived admitted count surfaces.
    assert!(html.contains("42"), "the admitted count");
    // The mesh shadow status words ride alongside their glyphs (meaning never by colour alone).
    assert!(html.contains("verified"), "a verified gate");
    assert!(html.contains("would-fail"), "a would-fail gate");
    // The "if enforced" what-if for both directions.
    assert!(html.contains("would admit"), "the admit what-if");
    assert!(html.contains("would deny"), "the would-deny what-if");
    // The subject + image surface (untrusted, escaped by maud).
    assert!(html.contains("Deployment/web"));
    assert!(html.contains("ghcr.io/org/web:1"));
    // The decision log no longer carries a signature gate column — its thead is decision / workload
    // / mesh / if enforced (posture now lives in the inventory).
    let decisions = &html[html.find("admission-rows").unwrap()..];
    assert!(
        !decisions.contains(">signature<"),
        "no signature column header in the decision log"
    );
    assert!(decisions.contains(">mesh<"), "the mesh column remains");
}

#[test]
fn admission_dedup_count_shows_when_above_one() {
    let mut r = admission_rec(
        "allow", "Pod/web", "img:1", "verified", "verified", "ns", "", true,
    );
    r.count = 50;
    let html = render(&[r]);
    assert!(
        html.contains("\u{00D7}50"),
        "the replica-churn dedup count (×50) is shown"
    );
}

#[test]
fn admission_untrusted_image_and_reason_are_escaped() {
    let evil = "<script>alert('x')</script>";
    let rows = vec![admission_rec(
        "deny",
        format!("Pod/{evil}").as_str(),
        format!("img/{evil}").as_str(),
        "verified",
        "would-fail",
        evil,
        format!("unsigned {evil}").as_str(),
        false,
    )];
    let html = render(&rows);
    assert!(
        !html.contains("<script>alert"),
        "raw script must not reach output"
    );
    assert!(html.contains("&lt;script&gt;"), "it is escaped");
}

#[test]
fn admission_fragment_has_no_document_shell() {
    let v = build_admission_view(strip_from(&[]), &[]);
    let frag = page::admission_fragment(&v).into_string();
    assert!(!frag.contains("<!DOCTYPE"), "a fragment carries no doctype");
    assert!(!frag.contains("<html"), "nor a document element");
    // It carries the persistent strip (a poll refreshes coverage/freshness on this tab too).
    assert!(frag.contains("strip"));
}

// ---- signing inventory (JEF-262) render tests -----------------------------------------------

#[test]
fn signing_inventory_renders_every_posture_with_word_and_no_na() {
    let rows = vec![
        signing_rec(
            "ghcr.io/acme/app@sha256:aa",
            "signed",
            "signed by https://github.com/acme/app/.github/workflows/r.yaml@refs/tags/v1 \
             via https://token.actions.githubusercontent.com",
        ),
        signing_rec(
            "docker.io/library/storefront:latest",
            "invalid-signature",
            "signature present but does not verify (untrusted/tampered chain)",
        ),
        signing_rec("docker.io/library/postgres:16", "not-signed", ""),
        signing_rec(
            "registry.k8s.io/pause:3.9",
            "checking",
            "signing posture not yet known (registry/log unreachable)",
        ),
    ];
    let html = render(&rows);
    // Each posture renders its distinct word (never colour alone, and lexically distinct).
    assert!(html.contains("signed"), "signed word");
    assert!(
        html.contains("invalid signature"),
        "invalid word — distinct"
    );
    assert!(html.contains("not signed"), "not-signed word — distinct");
    assert!(html.contains("checking"), "the transient checking word");
    // The binary if-enforced, both directions — never n/a.
    assert!(html.contains("would admit"), "signed would admit");
    assert!(html.contains("would block"), "unsigned/invalid would block");
    // Hard rule: the inventory never shows n/a.
    assert!(
        !inventory_slice(&html).contains("n/a"),
        "the signing inventory never shows n/a"
    );
    // Grouped under the repo header.
    assert!(html.contains("ghcr.io/acme/app"), "the repo group header");
}

#[test]
fn signing_inventory_shows_the_short_signer_and_issuer_badge() {
    let rows = vec![signing_rec(
        "ghcr.io/acme/app@sha256:aa",
        "signed",
        "signed by https://github.com/acme/app/.github/workflows/release.yaml@refs/tags/v1 \
         via https://token.actions.githubusercontent.com",
    )];
    let html = render(&rows);
    assert!(
        html.contains("acme/app"),
        "the short org/repo identity label rides in the signer column"
    );
    assert!(html.contains("github actions"), "the issuer badge");
    // The full SAN is preserved (expand panel + title=), never dropped.
    assert!(
        html.contains("https://github.com/acme/app/.github/workflows/release.yaml@refs/tags/v1"),
        "the full Fulcio SAN is available"
    );
}

/// The signing-inventory slice of a render (from its section to the next section), for asserting
/// structure without matching the decision log below it.
fn inventory_slice(html: &str) -> &str {
    let rest = &html[html.find("signing-inventory").unwrap()..];
    let end = rest
        .find("admission-rows")
        .or_else(|| rest.find("admission-empty"))
        .unwrap_or(rest.len());
    &rest[..end]
}

/// A per-repo baseline-strength row (JEF-266 shape): `SigningStrength/<repo>` subject, the strength
/// word in `signature`.
fn strength_rec(repo: &str, word: &str) -> PolicyDecisionRecord {
    PolicyDecisionRecord::now(
        "signing-strength",
        "allow",
        format!("SigningStrength/{repo}").as_str(),
        repo,
        word,
        "",
        "",
        "first_seen:0",
    )
}

#[test]
fn signing_inventory_is_one_aligned_table_with_repo_group_headers() {
    // The operator's core complaint: it must be ONE table for the whole inventory (columns aligned
    // across every repo), not one mini-table per repo.
    let rows = vec![
        signing_rec("ghcr.io/acme/app@sha256:aa", "not-signed", ""),
        signing_rec("docker.io/library/postgres:16", "not-signed", ""),
    ];
    let html = render(&rows);
    let inv = inventory_slice(&html);
    assert_eq!(
        inv.matches("<table").count(),
        1,
        "the whole inventory is a single aligned table, not one per repo"
    );
    // Each repo is a spanning group-header row, keeping the repo visible without its own table.
    assert!(
        inv.contains("signing-group-head"),
        "repos are group-header rows in the one table"
    );
    assert!(inv.contains("ghcr.io/acme/app"), "the first repo header");
    assert!(
        inv.contains("docker.io/library/postgres"),
        "the second repo header"
    );
}

#[test]
fn signing_rows_are_findings_style_expanders_with_unique_ids() {
    let rows = vec![
        signing_rec("ghcr.io/acme/app@sha256:aa", "not-signed", ""),
        signing_rec(
            "ghcr.io/acme/app@sha256:bb",
            "invalid-signature",
            "tampered",
        ),
    ];
    let html = render(&rows);
    let inv = inventory_slice(&html);
    // Findings-style shape: a .row summary carrying data-signing + an .expander, each paired with a
    // hidden .row-detail pulldown (the same mechanics the client's bindRows toggles).
    assert!(
        inv.contains("data-signing="),
        "rows carry a data-signing id"
    );
    assert!(
        inv.contains("class=\"expander\""),
        "each row has a +/- expander"
    );
    assert_eq!(
        inv.matches("row-detail").count(),
        2,
        "each of the two image rows has its own pulldown"
    );
    // Unique, collision-free ids: the two digests get two DISTINCT data-signing values.
    let ids: Vec<&str> = inv
        .match_indices("data-signing=\"")
        .map(|(i, m)| {
            let start = i + m.len();
            let end = inv[start..].find('"').unwrap() + start;
            &inv[start..end]
        })
        .collect();
    assert_eq!(ids.len(), 2, "one id per image row");
    assert_ne!(ids[0], ids[1], "the two rows carry distinct ids");
    // aria-controls wires each expander to its own detail row.
    for id in ids {
        assert!(
            inv.contains(&format!("aria-controls=\"detail-{id}\"")),
            "the expander points at its paired detail row"
        );
    }
}

#[test]
fn signing_row_pulldown_carries_full_identity_and_baseline_detail() {
    let rows = vec![
        signing_rec(
            "ghcr.io/acme/app@sha256:aa",
            "signed",
            "signed by https://github.com/acme/app/.github/workflows/r.yaml@refs/tags/v1 \
             via https://token.actions.githubusercontent.com",
        ),
        strength_rec("ghcr.io/acme/app", "log-corroborated"),
    ];
    let html = render(&rows);
    // The FULL Fulcio SAN + issuer live in the pulldown (never dropped to the short label alone).
    assert!(
        html.contains("https://github.com/acme/app/.github/workflows/r.yaml@refs/tags/v1"),
        "the full identity is in the pulldown"
    );
    assert!(
        html.contains("https://token.actions.githubusercontent.com"),
        "the full issuer is in the pulldown"
    );
    // The baseline detail prose explains the corroboration (log-corroborated vs local-only).
    assert!(
        html.contains("transparency log"),
        "the baseline detail explains the strength"
    );
}

#[test]
fn signing_regression_before_after_lives_in_the_row_pulldown() {
    let rows = vec![regression_rec(
        "ghcr.io/acme/app",
        "ghcr.io/acme/app:2",
        "regression-identity-established",
        "signed by https://github.com/evil/app/.github/workflows/pwn.yaml@refs/heads/main via \
         https://token.actions.githubusercontent.com | before: \
         https://github.com/acme/app/.github/workflows/r.yaml@refs/tags/v1",
    )];
    let html = render(&rows);
    let inv = inventory_slice(&html);
    // The regression is a loud findings-style row with its own pulldown.
    assert!(
        inv.contains("data-regression="),
        "the regression is a loud row"
    );
    assert!(inv.contains("row-detail"), "with its own pulldown");
    // Both identities in FULL survive in the (always-rendered) detail row markup.
    assert!(inv.contains("https://github.com/acme/app/.github/workflows/r.yaml@refs/tags/v1"));
    assert!(inv.contains("https://github.com/evil/app/.github/workflows/pwn.yaml@refs/heads/main"));
}

#[test]
fn signing_inventory_sorts_loud_repos_before_calm_ones() {
    let rows = vec![
        signing_rec("ghcr.io/clean/app@sha256:aa", "signed", "signed by x via y"),
        signing_rec(
            "docker.io/lib/bad@sha256:bb",
            "invalid-signature",
            "tampered",
        ),
    ];
    let html = render(&rows);
    let inv = inventory_slice(&html);
    // The loud invalid repo's header appears before the calm signed repo's header.
    let bad = inv.find("docker.io/lib/bad").unwrap();
    let clean = inv.find("ghcr.io/clean/app").unwrap();
    assert!(
        bad < clean,
        "the loud (invalid) repo sorts above the signed one"
    );
}

#[test]
fn signing_inventory_escapes_an_attacker_chosen_identity() {
    // The signer identity is untrusted Fulcio-cert free-text — an attacker-chosen SAN must not
    // inject markup (maud auto-escape; never PreEscaped).
    let evil = "<script>alert('pwn')</script>";
    let rows = vec![signing_rec(
        "ghcr.io/acme/app@sha256:aa",
        "signed",
        &format!("signed by {evil} via https://token.actions.githubusercontent.com"),
    )];
    let html = render(&rows);
    assert!(
        !html.contains("<script>alert"),
        "raw script from the identity must not reach output"
    );
    assert!(html.contains("&lt;script&gt;"), "the identity is escaped");
}

// ---- signing-regression banner (JEF-264) render tests --------------------------------------

/// A signing-regression finding row (JEF-264 shape): `SigningRegression/<repo>` subject, the drift
/// token in `signature`, the before→after prose in `reason`.
fn regression_rec(repo: &str, image: &str, signature: &str, reason: &str) -> PolicyDecisionRecord {
    PolicyDecisionRecord::now(
        "signing-regression",
        "allow",
        format!("SigningRegression/{repo}"),
        image,
        signature,
        "",
        "",
        reason,
    )
}

#[test]
fn signing_regression_renders_loud_word_and_before_after_in_full() {
    let rows = vec![regression_rec(
        "ghcr.io/acme/app",
        "ghcr.io/acme/app:2",
        "regression-identity-established",
        "signed by https://github.com/evil/app/.github/workflows/pwn.yaml@refs/heads/main via \
         https://token.actions.githubusercontent.com | before: \
         https://github.com/acme/app/.github/workflows/r.yaml@refs/tags/v1",
    )];
    let html = render(&rows);
    // The loud, lexically-distinct posture word (not the calm "not signed").
    assert!(
        html.contains("signing regression"),
        "the loud regression word is rendered"
    );
    // Both identities in FULL — the before (old signer) and the after (new signer).
    assert!(
        html.contains("https://github.com/acme/app/.github/workflows/r.yaml@refs/tags/v1"),
        "the before signer is shown in full"
    );
    assert!(
        html.contains("https://github.com/evil/app/.github/workflows/pwn.yaml@refs/heads/main"),
        "the after signer is shown in full"
    );
}

#[test]
fn signing_regression_cold_baseline_reads_as_a_weak_lead() {
    let rows = vec![regression_rec(
        "ghcr.io/acme/app",
        "ghcr.io/acme/app:2",
        "regression-unsigned-cold",
        "now not signed (was signed) | before: releng@acme.example",
    )];
    let html = render(&rows);
    assert!(html.contains("signing regression"));
    assert!(
        html.contains("treat as a lead"),
        "a cold-baseline regression is honestly flagged a weak lead"
    );
}

#[test]
fn signing_regression_escapes_an_attacker_chosen_identity() {
    // The before/after signer identities are attacker-influenceable Fulcio SANs — a crafted SAN in a
    // regression row must not inject markup (maud auto-escape; never PreEscaped).
    let evil = "<script>alert('pwn')</script>";
    let rows = vec![regression_rec(
        "ghcr.io/acme/app",
        "ghcr.io/acme/app:2",
        "regression-identity-established",
        &format!(
            "signed by {evil} via https://token.actions.githubusercontent.com | before: {evil}"
        ),
    )];
    let html = render(&rows);
    assert!(
        !html.contains("<script>alert"),
        "raw script from either identity must not reach output"
    );
    assert!(
        html.contains("&lt;script&gt;"),
        "the crafted identity is escaped in the regression banner"
    );
}

#[test]
fn signing_inventory_honest_empty_when_no_images_observed() {
    // Decision rows present, but no signing-sweep observation rows → the inventory is honestly
    // empty, explicitly NOT an all-clear.
    let rows = vec![admission_rec(
        "allow", "Pod/web", "img:1", "verified", "verified", "ns", "", true,
    )];
    let html = render(&rows);
    assert!(html.contains("no images observed yet"));
    assert!(
        html.contains("not an all-clear"),
        "the empty inventory disclaims being an all-clear"
    );
}
