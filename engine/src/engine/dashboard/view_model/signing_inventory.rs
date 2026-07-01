//! Map the signing-sweep rows on the admission-decision log into the per-image signing inventory
//! the Admission view renders (JEF-262 / ADR-0020 Stage 1 render). The sweep (JEF-261) records
//! each observed image as an `image-signature` row keyed `Image/<ref>`, with the posture in the
//! record's `signature` status word (`signed` / `invalid-signature` / `not-signed` / `checking`)
//! and, for a signed image, the signer prose in `reason` (`signed by <identity>[ via <issuer>]`).
//!
//! This layer partitions those observation rows out of the webhook's decision rows, derives a
//! short scannable signer label + issuer badge from the (untrusted) Fulcio SAN, splits each image
//! into its repo + digest/tag, and groups the images under their repo. It NEVER changes how the
//! posture is produced (the producer is JEF-261's sweep); it only shapes it for rendering. Two hard
//! operator rules are encoded here: the posture is always one of the four states — never n/a — and
//! the "if enforced" binary is derived from the posture (only a verifying signature would admit).
//! Data layer: touches `engine::`; the components never do.

use crate::engine::policy_log::PolicyDecisionRecord;

use super::props::{
    RegressionKind, SignerProps, SigningPosture, SigningRegressionProps, SigningRepoProps,
    SigningRowProps,
};

/// The subject prefix the signing sweep keys its posture rows under (`Image/<ref>`). A row whose
/// subject starts with this is an observation row for the inventory, distinct from the webhook's
/// workload decision rows (`Pod/…`, `Deployment/…`).
const IMAGE_SUBJECT_PREFIX: &str = "Image/";

/// The subject prefix the sweep keys a signing-**regression** finding under (`SigningRegression/
/// <repo>`, JEF-264) — one row per repo. Also a signing row (not a webhook decision), so it is
/// partitioned out of the decision tallies and feeds the repo group's regression banner.
const REGRESSION_SUBJECT_PREFIX: &str = "SigningRegression/";

/// The signature-column prefix marking a regression row's drift token (`regression-<kind>-
/// <strength>`), written by `engine::signing_sweep::regression_record`.
const REGRESSION_STATUS_PREFIX: &str = "regression-";

/// The sentinel separating the "after" clause from the baseline "before" signers in a regression
/// row's reason (`<after> | before: <ids>`).
const BEFORE_SEP: &str = " | before: ";

/// Whether a record is a signing-inventory row — a posture observation (`Image/<ref>`) OR a
/// regression finding (`SigningRegression/<repo>`) — as opposed to a webhook workload decision.
/// Both are partitioned out of the Admission view's decision tallies.
pub(super) fn is_inventory_row(r: &PolicyDecisionRecord) -> bool {
    is_observation_row(r) || is_regression_row(r)
}

/// Whether a record is a per-image posture observation row (`Image/<ref>`).
fn is_observation_row(r: &PolicyDecisionRecord) -> bool {
    r.subject.starts_with(IMAGE_SUBJECT_PREFIX)
}

/// Whether a record is a signing-regression finding row (`SigningRegression/<repo>`, JEF-264).
fn is_regression_row(r: &PolicyDecisionRecord) -> bool {
    r.subject.starts_with(REGRESSION_SUBJECT_PREFIX)
}

/// Split an image ref into `(repo, remainder)`: the digest form `repo@sha256:…` splits at the `@`;
/// the tag form `repo:tag` splits at the `:` in the LAST path segment (so a registry port —
/// `registry:5000/org/app` — is never mistaken for a tag). A bare ref with neither has an empty
/// remainder.
fn split_ref(image: &str) -> (&str, &str) {
    if let Some((repo, digest)) = image.split_once('@') {
        return (repo, digest);
    }
    let last_segment = image.rfind('/').map(|i| i + 1).unwrap_or(0);
    if let Some(colon) = image[last_segment..].find(':') {
        let at = last_segment + colon;
        return (&image[..at], &image[at + 1..]);
    }
    (image, "")
}

/// Parse the sweep's signer prose (`signed by <identity>[ via <issuer>]`) into
/// `(identity, issuer)`. Returns `None` when the prose isn't a signer line (a non-signed posture),
/// so a malformed / unexpected reason never fabricates a signer.
fn parse_signer_reason(reason: &str) -> Option<(&str, Option<&str>)> {
    let rest = reason.strip_prefix("signed by ")?;
    match rest.split_once(" via ") {
        Some((identity, issuer)) => Some((identity, Some(issuer))),
        None => Some((rest, None)),
    }
}

/// Derive a short, scannable label from a Fulcio SAN. A GitHub Actions keyless workflow URI
/// (`https://github.com/org/repo/.github/workflows/…@ref`) collapses to `org/repo`; anything else
/// (an email, another host) is kept verbatim and truncated in-row by CSS. The full SAN is always
/// preserved separately for the expand panel + `title=`.
fn short_identity(identity: &str) -> String {
    if let Some(rest) = identity.strip_prefix("https://github.com/") {
        let repo_path = rest.split("/.github/").next().unwrap_or(rest);
        let mut segments = repo_path.split('/');
        if let (Some(org), Some(repo)) = (segments.next(), segments.next())
            && !org.is_empty()
            && !repo.is_empty()
        {
            return format!("{org}/{repo}");
        }
    }
    identity.to_string()
}

/// Derive a short issuer badge from the OIDC issuer URL — the recognised public-good issuers get a
/// friendly word; anything else falls back to the bare host (or the raw value). Empty issuer ⇒
/// empty badge.
fn issuer_badge(issuer: &str) -> String {
    let host = issuer
        .strip_prefix("https://")
        .or_else(|| issuer.strip_prefix("http://"))
        .unwrap_or(issuer)
        .split('/')
        .next()
        .unwrap_or(issuer);
    match host {
        "token.actions.githubusercontent.com" => "github actions".to_string(),
        "accounts.google.com" => "google".to_string(),
        "oauth2.sigstore.dev" => "sigstore".to_string(),
        "" => String::new(),
        other => other.to_string(),
    }
}

/// Build the signer props for a signed image from the sweep's `reason` prose, or `None` when the
/// reason carries no signer line.
fn signer_from_reason(reason: &str) -> Option<SignerProps> {
    let (identity, issuer) = parse_signer_reason(reason)?;
    Some(SignerProps {
        identity_short: short_identity(identity),
        identity_full: identity.to_string(),
        issuer_badge: issuer.map(issuer_badge).unwrap_or_default(),
        issuer_full: issuer.map(|s| s.to_string()),
    })
}

/// Project one observation record into its inventory row. The posture always resolves to one of the
/// four states (never n/a); the signer is attached only for a verifying signature.
fn signing_row(r: &PolicyDecisionRecord) -> SigningRowProps {
    let posture = SigningPosture::parse(&r.signature);
    let (_, remainder) = split_ref(&r.image);
    let signer = if posture == SigningPosture::Signed {
        signer_from_reason(&r.reason)
    } else {
        None
    };
    SigningRowProps {
        image: r.image.clone(),
        label: if remainder.is_empty() {
            r.image.clone()
        } else {
            remainder.to_string()
        },
        posture,
        signer,
        detail: r.reason.clone(),
        count: r.count,
    }
}

/// Parse a signing-regression row (`SigningRegression/<repo>`, JEF-264) into `(repo, props)`, or
/// `None` when the row isn't a well-formed regression row. The row is self-describing (the sweep
/// writes the drift token in `signature` and the before→after prose in `reason`); nothing here
/// reaches the baseline store. Every identity that comes back is UNTRUSTED — escaped at render.
fn parse_regression(r: &PolicyDecisionRecord) -> Option<(String, SigningRegressionProps)> {
    let repo = r
        .subject
        .strip_prefix(REGRESSION_SUBJECT_PREFIX)?
        .to_string();
    // signature = "regression-<kind>-<strength>" (strength ∈ established/cold).
    let token = r.signature.strip_prefix(REGRESSION_STATUS_PREFIX)?;
    let (kind_word, strength) = token.rsplit_once('-')?;
    let established = match strength {
        "established" => true,
        "cold" => false,
        _ => return None,
    };
    let kind = RegressionKind::parse(kind_word);

    // reason = "<after clause> | before: <id1>, <id2>, …".
    let (after_clause, before) = r.reason.split_once(BEFORE_SEP).unwrap_or((&r.reason, ""));
    let before_identities: Vec<String> = before
        .split(", ")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    // The "after" identity only exists for an identity-change (its clause reuses the observation
    // row's `signed by <id>[ via <issuer>]` prose, so the same parser reads it).
    let (after_identity, after_issuer) = match kind {
        RegressionKind::IdentityChange => match parse_signer_reason(after_clause) {
            Some((identity, issuer)) => (Some(identity.to_string()), issuer.map(str::to_string)),
            None => (None, None),
        },
        _ => (None, None),
    };

    Some((
        repo,
        SigningRegressionProps {
            kind,
            established,
            before_identities,
            after_identity,
            after_issuer,
            image: r.image.clone(),
        },
    ))
}

/// The standing regressions, one per repo (newest wins), preserving newest-first order. Shared by
/// [`build`] (to attach the banner) and [`counts`] (to feed the status-strip honesty model), so the
/// render and the strip can never disagree about what regressions stand.
fn regressions_by_repo(rows: &[PolicyDecisionRecord]) -> Vec<(String, SigningRegressionProps)> {
    let mut out: Vec<(String, SigningRegressionProps)> = Vec::new();
    for record in rows.iter().filter(|r| is_regression_row(r)) {
        if let Some((repo, props)) = parse_regression(record)
            && !out.iter().any(|(existing, _)| *existing == repo)
        {
            out.push((repo, props));
        }
    }
    out
}

/// The standing signing-regression counts for the status strip (JEF-264): `(established, cold)` —
/// established-baseline regressions count toward breach, cold-baseline ones toward uncertain. Both
/// forbid the green all-clear. Counted per repo (a repo is one standing regression regardless of how
/// many bad digests it served).
pub(super) fn counts(rows: &[PolicyDecisionRecord]) -> (usize, usize) {
    let mut established = 0;
    let mut cold = 0;
    for (_, reg) in regressions_by_repo(rows) {
        if reg.established {
            established += 1;
        } else {
            cold += 1;
        }
    }
    (established, cold)
}

/// Build the signing inventory from the admission-decision log rows: the observation rows (`Image/
/// <ref>`) grouped under their repo (JEF-262), each repo carrying its standing signing-regression
/// banner (`SigningRegression/<repo>`, JEF-264) when one stands. Repo groups preserve first-seen
/// order (the caller passes newest-first rows), so a steady inventory renders stably. The webhook's
/// workload decision rows are ignored — they drive the decision log, not the inventory.
pub(super) fn build(rows: &[PolicyDecisionRecord]) -> Vec<SigningRepoProps> {
    let mut groups: Vec<SigningRepoProps> = Vec::new();
    for record in rows.iter().filter(|r| is_observation_row(r)) {
        let (repo, _) = split_ref(&record.image);
        let row = signing_row(record);
        match groups.iter_mut().find(|g| g.repo == repo) {
            Some(group) => group.images.push(row),
            None => groups.push(SigningRepoProps {
                repo: repo.to_string(),
                images: vec![row],
                regression: None,
            }),
        }
    }
    // Attach the standing regression to its repo group, creating the group if the regressed image
    // has aged out of the observation window (the regression must still surface loudly).
    for (repo, regression) in regressions_by_repo(rows) {
        match groups.iter_mut().find(|g| g.repo == repo) {
            Some(group) => group.regression = Some(regression),
            None => groups.push(SigningRepoProps {
                repo,
                images: Vec::new(),
                regression: Some(regression),
            }),
        }
    }
    groups
}

#[cfg(test)]
mod tests;
