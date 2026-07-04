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
//! the "if enforced" column is always a definite continuity verdict — would-admit / would-block /
//! uncertain (JEF-297). That verdict is baseline-relative CONTINUITY (ADR-0020), not the raw
//! posture: a calm, consistent posture admits, only a genuine regression against the repo's
//! established baseline blocks, and a cold-baseline regression reads uncertain. The regression is
//! read from the SAME `SigningRegression/<repo>` rows the sweep recorded (JEF-264/280) — the single
//! source of truth a continuity gate (JEF-265) enforces, so the column can never disagree with what
//! enforcement blocks. Data layer: touches `engine::`; the components never do.

use std::collections::HashMap;

use crate::engine::policy_log::PolicyDecisionRecord;

use std::collections::HashSet;

use super::props::{
    ExceptionAcceptedProps, ProvenanceChangeProps, ProvenancePosture, ProvenanceProps,
    RegressionKind, RepoStrength, SignerProps, SigningEnforcement, SigningPosture,
    SigningRegressionProps, SigningRepoProps, SigningRowProps,
};

/// The DOM-id prefix for an image summary/detail row (`si-<slug>-<hash>`).
const IMAGE_ID_PREFIX: &str = "si";
/// The DOM-id prefix for a signing-regression summary/detail row (`sr-<slug>-<hash>`). A distinct
/// prefix from images guarantees a bare image ref that equals its repo can never collide with the
/// repo's regression row.
const REGRESSION_ID_PREFIX: &str = "sr";
/// The DOM-id prefix for a provenance-change summary/detail row (`pc-<slug>-<hash>`, JEF-275) — a
/// distinct namespace from image + signing-regression rows so a repo carrying both a signing
/// regression and a provenance change never shares an id.
const PROVENANCE_CHANGE_ID_PREFIX: &str = "pc";

/// The subject prefix the signing sweep keys its posture rows under (`Image/<ref>`). A row whose
/// subject starts with this is an observation row for the inventory, distinct from the webhook's
/// workload decision rows (`Pod/…`, `Deployment/…`).
const IMAGE_SUBJECT_PREFIX: &str = "Image/";

/// The subject prefix the sweep keys a signing-**regression** finding under (`SigningRegression/
/// <repo>`, JEF-264) — one row per repo. Also a signing row (not a webhook decision), so it is
/// partitioned out of the decision tallies and feeds the repo group's regression banner.
const REGRESSION_SUBJECT_PREFIX: &str = "SigningRegression/";

/// The subject prefix the sweep keys an **"exception accepted"** finding under
/// (`SigningException/<repo>`, JEF-265) — a regression the operator has scoped-out via a recorded
/// exception. A signing row (not a webhook decision), partitioned out of the tallies; it feeds the
/// repo group's CALM "exception accepted" banner and marks its image's enforcement chip, and it is
/// NOT a regression row so it never counts toward breach.
const EXCEPTION_SUBJECT_PREFIX: &str = "SigningException/";

/// The signature-column prefix marking an exception row's token (`exception-<kind>-<strength>`),
/// written by `engine::signing_sweep::exception_record`.
const EXCEPTION_STATUS_PREFIX: &str = "exception-";

/// The DOM-id prefix for an exception-accepted summary/detail row (`ex-<slug>-<hash>`) — a distinct
/// namespace from image / regression / provenance rows.
const EXCEPTION_ID_PREFIX: &str = "ex";

/// The subject prefix the sweep keys a per-repo baseline-**strength** row under (`SigningStrength/
/// <repo>`, JEF-266) — one row per repo, log-corroborated vs local-only. A signing row (not a
/// webhook decision), partitioned out of the tallies and feeding the repo group's strength badge.
const STRENGTH_SUBJECT_PREFIX: &str = "SigningStrength/";

/// The subject prefix the provenance sweep keys a per-image provenance observation under
/// (`Provenance/<ref>`, JEF-275). A signing-inventory row (not a webhook decision), partitioned out
/// of the decision tallies and joined onto its image row as the provenance column.
const PROVENANCE_SUBJECT_PREFIX: &str = "Provenance/";

/// The subject prefix the provenance sweep keys a provenance-**change** finding under
/// (`ProvenanceChange/<repo>`, JEF-275) — one row per repo, feeding the repo group's provenance-change
/// banner. A signing row, partitioned out of the tallies.
const PROVENANCE_CHANGE_SUBJECT_PREFIX: &str = "ProvenanceChange/";

/// The signature-column prefix marking a provenance-change row's drift token
/// (`provenance-change-<strength>`), written by `engine::provenance_sweep::change_record`.
const PROVENANCE_CHANGE_STATUS_PREFIX: &str = "provenance-change-";

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
    is_observation_row(r)
        || is_regression_row(r)
        || is_exception_row(r)
        || is_strength_row(r)
        || is_provenance_row(r)
        || is_provenance_change_row(r)
}

/// Whether a record is an "exception accepted" finding row (`SigningException/<repo>`, JEF-265).
fn is_exception_row(r: &PolicyDecisionRecord) -> bool {
    r.subject.starts_with(EXCEPTION_SUBJECT_PREFIX)
}

/// Whether a record is a per-image provenance observation row (`Provenance/<ref>`, JEF-275).
fn is_provenance_row(r: &PolicyDecisionRecord) -> bool {
    r.subject.starts_with(PROVENANCE_SUBJECT_PREFIX)
}

/// Whether a record is a provenance-change finding row (`ProvenanceChange/<repo>`, JEF-275).
fn is_provenance_change_row(r: &PolicyDecisionRecord) -> bool {
    r.subject.starts_with(PROVENANCE_CHANGE_SUBJECT_PREFIX)
}

/// Whether a record is a per-image posture observation row (`Image/<ref>`).
fn is_observation_row(r: &PolicyDecisionRecord) -> bool {
    r.subject.starts_with(IMAGE_SUBJECT_PREFIX)
}

/// Whether a record is a signing-regression finding row (`SigningRegression/<repo>`, JEF-264).
fn is_regression_row(r: &PolicyDecisionRecord) -> bool {
    r.subject.starts_with(REGRESSION_SUBJECT_PREFIX)
}

/// Whether a record is a per-repo baseline-strength row (`SigningStrength/<repo>`, JEF-266).
fn is_strength_row(r: &PolicyDecisionRecord) -> bool {
    r.subject.starts_with(STRENGTH_SUBJECT_PREFIX)
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

/// Parse the provenance sweep's posture prose (`built by <builder> from <source>`) into
/// `(builder, source)`. Returns `None` when the prose isn't a provenance line (a non-verified
/// posture), so a malformed / unexpected reason never fabricates a provenance. `rsplit` on the LAST
/// ` from ` so a builder URI containing the token cannot mis-split the source.
fn parse_provenance_reason(reason: &str) -> Option<(&str, &str)> {
    let rest = reason.strip_prefix("built by ")?;
    let (builder, source) = rest.rsplit_once(" from ")?;
    Some((builder, source))
}

/// Derive a short, scannable source-repo label. `github.com/org/repo` (and any `host/org/repo`)
/// collapses to `org/repo`; a shorter path is kept verbatim. The full source is preserved for the
/// expand panel + `title=`.
fn short_source(source: &str) -> String {
    let segments: Vec<&str> = source.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() >= 3 {
        // host / org / repo[/...] → org/repo
        format!("{}/{}", segments[1], segments[2])
    } else {
        source.to_string()
    }
}

/// Build the per-image provenance lookup (JEF-275) from the `Provenance/<ref>` rows: image ref →
/// (posture, verified source+builder). Reuses `short_identity` for the builder label (a GitHub
/// Actions workflow URI → `org/repo`) so the provenance column reads like the signer column.
fn provenance_by_image(
    rows: &[PolicyDecisionRecord],
) -> HashMap<String, (ProvenancePosture, Option<ProvenanceProps>)> {
    let mut out = HashMap::new();
    for r in rows.iter().filter(|r| is_provenance_row(r)) {
        let posture = ProvenancePosture::parse(&r.signature);
        let info = if posture == ProvenancePosture::Verified {
            parse_provenance_reason(&r.reason).map(|(builder, source)| ProvenanceProps {
                source_short: short_source(source),
                source_full: source.to_string(),
                builder_short: short_identity(builder),
                builder_full: builder.to_string(),
            })
        } else {
            None
        };
        // Newest row wins (the caller passes newest-first): only insert if not already set.
        out.entry(r.image.clone()).or_insert((posture, info));
    }
    out
}

/// A stable, collision-free DOM/fragment id for a signing row, `<prefix>-<slug>-<hash>` (mirrors
/// the findings `finding_id`). The slug alone is lossy — distinct keys can slugify alike — so the
/// short FNV hash of the FULL key is what guarantees two rows never share an `id`/`data-signing`/
/// `aria-controls`; a distinct prefix per row-kind (image vs regression) keeps the two namespaces
/// apart. The result is `[a-z0-9-]` only, so it is always a safe attribute value.
fn signing_dom_id(prefix: &str, key: &str) -> String {
    let slug: String = key
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("{prefix}-{slug}-{}", short_hash(key))
}

/// A short, stable hex hash of a key — the collision-breaking suffix for [`signing_dom_id`]. FNV-1a
/// 64-bit (no dependency, deterministic across runs — unlike `DefaultHasher`'s process-seeded
/// output, which would change the id between renders and break the client's persisted open-state
/// keying), rendered as 8 hex chars.
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

/// The attention rank of a posture for the loud-first sort: invalid (loudest) < not signed <
/// unverifiable < checking < signed-key-based < signed (calmest, sinks to the bottom). The two calm
/// signed states sink last; unverifiable ranks just above the transient. Mirrors the findings
/// urgency-sort spirit.
fn posture_rank(p: SigningPosture) -> u8 {
    match p {
        SigningPosture::Invalid => 0,
        SigningPosture::NotSigned => 1,
        SigningPosture::Unverifiable => 2,
        SigningPosture::Checking => 3,
        SigningPosture::SignedKeyBased => 4,
        SigningPosture::Signed => 5,
    }
}

/// The attention rank of a repo group: a standing regression is the loudest (floats above every
/// clean repo), otherwise the group ranks by its loudest image posture. An empty group (regression
/// aged out, no images) with no regression sorts last.
fn group_rank(g: &SigningRepoProps) -> u8 {
    if g.regression.is_some() || g.provenance_change.is_some() {
        return 0;
    }
    g.images
        .iter()
        .map(|i| posture_rank(i.posture))
        .min()
        .map(|r| r.saturating_add(1))
        .unwrap_or(u8::MAX)
}

/// Project one observation record into its inventory row. The posture always resolves to one of the
/// four states (never n/a); the signer is attached only for a verifying signature; the "if enforced"
/// continuity verdict is derived from `regressing` (JEF-297), not the raw posture.
fn signing_row(
    r: &PolicyDecisionRecord,
    provenance: &HashMap<String, (ProvenancePosture, Option<ProvenanceProps>)>,
    regressing: &HashMap<String, bool>,
    excepted: &HashSet<String>,
) -> SigningRowProps {
    let posture = SigningPosture::parse(&r.signature);
    let (_, remainder) = split_ref(&r.image);
    let signer = if posture == SigningPosture::Signed {
        signer_from_reason(&r.reason)
    } else {
        None
    };
    // Join the provenance axis (JEF-275) onto the image row. Absent when the provenance sweep is off
    // or observed no provenance for this image — the honest calm default, never n/a.
    let (provenance_posture, provenance_info) = provenance
        .get(&r.image)
        .cloned()
        .unwrap_or((ProvenancePosture::Absent, None));
    // The baseline-relative continuity verdict (JEF-297): a standing signing-regression for THIS
    // image (`Some(established)`) drives would-block (established) / uncertain (cold); no regression
    // is continuous (would-admit). A genuinely-invalid posture blocks outright (the loud channel).
    // An image the operator has scoped-out via a recorded exception (JEF-265) overrides to the
    // DISTINCT "exception accepted" chip — calm, but never a green would-admit.
    let enforcement = if excepted.contains(&r.image) {
        SigningEnforcement::ExceptionAccepted
    } else {
        SigningEnforcement::for_image(posture, regressing.get(&r.image).copied())
    };
    SigningRowProps {
        dom_id: signing_dom_id(IMAGE_ID_PREFIX, &r.image),
        image: r.image.clone(),
        label: if remainder.is_empty() {
            r.image.clone()
        } else {
            remainder.to_string()
        },
        posture,
        signer,
        provenance: provenance_posture,
        provenance_info,
        detail: r.reason.clone(),
        enforcement,
        count: r.count,
    }
}

/// The per-IMAGE signing-regression lookup (JEF-297): image ref → whether the regressed baseline was
/// `established` (`true`) or cold (`false`). Read from the SAME `SigningRegression/<repo>` rows the
/// sweep recorded (JEF-264/280) — the recorded drift verdict a continuity gate (JEF-265) enforces —
/// so the "if enforced" column can never disagree with what enforcement blocks.
///
/// Unlike [`regressions_by_repo`] (one banner per repo), this keys per image: the sweep records one
/// regression row per regressing image, so every downgraded/regressed digest under a repo gets its
/// own would-block, while the repo's calm/continuous images still admit. Newest-first order wins
/// (the caller passes newest-first rows), matching the banner. The strength is parsed from the
/// self-describing `regression-<kind>-<strength>` token exactly as [`parse_regression`] does.
fn regressing_images(rows: &[PolicyDecisionRecord]) -> HashMap<String, bool> {
    let mut out: HashMap<String, bool> = HashMap::new();
    for r in rows.iter().filter(|r| is_regression_row(r)) {
        let Some(token) = r.signature.strip_prefix(REGRESSION_STATUS_PREFIX) else {
            continue;
        };
        let Some((_, strength)) = token.rsplit_once('-') else {
            continue;
        };
        let established = match strength {
            "established" => true,
            "cold" => false,
            _ => continue,
        };
        // Newest-first: the first (newest) regression for an image wins its verdict.
        out.entry(r.image.clone()).or_insert(established);
    }
    out
}

/// Parse a provenance-change row (`ProvenanceChange/<repo>`, JEF-275) into `(repo, props)`, or `None`
/// when the row isn't well-formed. Self-describing (the sweep writes the drift token in `signature`
/// and the before→after prose in `reason`); nothing here reaches the baseline store. Every
/// builder/source that comes back is UNTRUSTED — escaped at render.
fn parse_provenance_change(r: &PolicyDecisionRecord) -> Option<(String, ProvenanceChangeProps)> {
    let repo = r
        .subject
        .strip_prefix(PROVENANCE_CHANGE_SUBJECT_PREFIX)?
        .to_string();
    // signature = "provenance-change-<strength>" (strength ∈ established/cold).
    let strength = r.signature.strip_prefix(PROVENANCE_CHANGE_STATUS_PREFIX)?;
    let established = match strength {
        "established" => true,
        "cold" => false,
        _ => return None,
    };
    // reason = "built by <builder> from <source> | before: <b1>, <b2>, …".
    let (after_clause, before) = r.reason.split_once(BEFORE_SEP).unwrap_or((&r.reason, ""));
    let (after_builder, after_source) = parse_provenance_reason(after_clause)
        .map(|(b, s)| (b.to_string(), s.to_string()))
        .unwrap_or_default();
    let before_builders: Vec<String> = before
        .split(", ")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    Some((
        repo.clone(),
        ProvenanceChangeProps {
            dom_id: signing_dom_id(PROVENANCE_CHANGE_ID_PREFIX, &repo),
            established,
            before_builders,
            after_builder,
            after_source,
            image: r.image.clone(),
        },
    ))
}

/// The standing provenance changes, one per repo (newest wins), preserving newest-first order.
fn provenance_changes_by_repo(
    rows: &[PolicyDecisionRecord],
) -> Vec<(String, ProvenanceChangeProps)> {
    let mut out: Vec<(String, ProvenanceChangeProps)> = Vec::new();
    for record in rows.iter().filter(|r| is_provenance_change_row(r)) {
        if let Some((repo, props)) = parse_provenance_change(record)
            && !out.iter().any(|(existing, _)| *existing == repo)
        {
            out.push((repo, props));
        }
    }
    out
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
        repo.clone(),
        SigningRegressionProps {
            dom_id: signing_dom_id(REGRESSION_ID_PREFIX, &repo),
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

/// Parse an "exception accepted" row (`SigningException/<repo>`, JEF-265) into `(repo, props)`, or
/// `None` when malformed. Self-describing exactly like a regression row but with the
/// `exception-<kind>-<strength>` token, so it reuses the same before→after parsing. Every identity
/// is UNTRUSTED — escaped at render.
fn parse_exception(r: &PolicyDecisionRecord) -> Option<(String, ExceptionAcceptedProps)> {
    let repo = r
        .subject
        .strip_prefix(EXCEPTION_SUBJECT_PREFIX)?
        .to_string();
    let token = r.signature.strip_prefix(EXCEPTION_STATUS_PREFIX)?;
    let (kind_word, strength) = token.rsplit_once('-')?;
    let established = match strength {
        "established" => true,
        "cold" => false,
        _ => return None,
    };
    let kind = RegressionKind::parse(kind_word);

    let (after_clause, before) = r.reason.split_once(BEFORE_SEP).unwrap_or((&r.reason, ""));
    let before_identities: Vec<String> = before
        .split(", ")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let after_identity = match kind {
        RegressionKind::IdentityChange => {
            parse_signer_reason(after_clause).map(|(identity, _)| identity.to_string())
        }
        _ => None,
    };

    Some((
        repo.clone(),
        ExceptionAcceptedProps {
            dom_id: signing_dom_id(EXCEPTION_ID_PREFIX, &repo),
            kind,
            established,
            before_identities,
            after_identity,
            image: r.image.clone(),
        },
    ))
}

/// The standing accepted exceptions, one per repo (newest wins), preserving newest-first order.
fn exceptions_by_repo(rows: &[PolicyDecisionRecord]) -> Vec<(String, ExceptionAcceptedProps)> {
    let mut out: Vec<(String, ExceptionAcceptedProps)> = Vec::new();
    for record in rows.iter().filter(|r| is_exception_row(r)) {
        if let Some((repo, props)) = parse_exception(record)
            && !out.iter().any(|(existing, _)| *existing == repo)
        {
            out.push((repo, props));
        }
    }
    out
}

/// The set of image refs covered by a standing accepted exception (JEF-265), so [`signing_row`] can
/// mark their enforcement chip as "exception accepted" rather than a would-block / would-admit.
fn excepted_images(rows: &[PolicyDecisionRecord]) -> HashSet<String> {
    rows.iter()
        .filter(|r| is_exception_row(r))
        .map(|r| r.image.clone())
        .collect()
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

/// The standing baseline strength per repo (JEF-266), newest wins — `(repo, strength)`. Only
/// `log-corroborated` / `local-only` words map to a badge; anything else is skipped.
fn strengths_by_repo(rows: &[PolicyDecisionRecord]) -> Vec<(String, RepoStrength)> {
    let mut out: Vec<(String, RepoStrength)> = Vec::new();
    for record in rows.iter().filter(|r| is_strength_row(r)) {
        let Some(repo) = record.subject.strip_prefix(STRENGTH_SUBJECT_PREFIX) else {
            continue;
        };
        let strength = RepoStrength::parse(&record.signature);
        if strength != RepoStrength::Unknown && !out.iter().any(|(existing, _)| existing == repo) {
            out.push((repo.to_string(), strength));
        }
    }
    out
}

/// Build the signing inventory from the admission-decision log rows: the observation rows (`Image/
/// <ref>`) grouped under their repo (JEF-262), each repo carrying its standing signing-regression
/// banner (`SigningRegression/<repo>`, JEF-264) when one stands and its baseline-strength badge
/// (`SigningStrength/<repo>`, JEF-266). Repo groups preserve first-seen order (the caller passes
/// newest-first rows), so a steady inventory renders stably. The webhook's workload decision rows
/// are ignored — they drive the decision log, not the inventory.
pub(super) fn build(rows: &[PolicyDecisionRecord]) -> Vec<SigningRepoProps> {
    let provenance = provenance_by_image(rows);
    let regressing = regressing_images(rows);
    let excepted = excepted_images(rows);
    let mut groups: Vec<SigningRepoProps> = Vec::new();
    for record in rows.iter().filter(|r| is_observation_row(r)) {
        let (repo, _) = split_ref(&record.image);
        let row = signing_row(record, &provenance, &regressing, &excepted);
        match groups.iter_mut().find(|g| g.repo == repo) {
            Some(group) => group.images.push(row),
            None => groups.push(SigningRepoProps {
                repo: repo.to_string(),
                images: vec![row],
                regression: None,
                exception: None,
                provenance_change: None,
                strength: RepoStrength::Unknown,
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
                exception: None,
                provenance_change: None,
                strength: RepoStrength::Unknown,
            }),
        }
    }
    // Attach the standing "exception accepted" (JEF-265) to its repo group — calm + distinctly
    // labelled, kept visible, never counted toward breach — creating the group if the excepted
    // image has aged out of the observation window.
    for (repo, exception) in exceptions_by_repo(rows) {
        match groups.iter_mut().find(|g| g.repo == repo) {
            Some(group) => group.exception = Some(exception),
            None => groups.push(SigningRepoProps {
                repo,
                images: Vec::new(),
                regression: None,
                exception: Some(exception),
                provenance_change: None,
                strength: RepoStrength::Unknown,
            }),
        }
    }
    // Attach the standing provenance change (JEF-275) to its repo group, creating the group if the
    // drifted image has aged out of the observation window (the change must still surface loudly).
    for (repo, change) in provenance_changes_by_repo(rows) {
        match groups.iter_mut().find(|g| g.repo == repo) {
            Some(group) => group.provenance_change = Some(change),
            None => groups.push(SigningRepoProps {
                repo,
                images: Vec::new(),
                regression: None,
                exception: None,
                provenance_change: Some(change),
                strength: RepoStrength::Unknown,
            }),
        }
    }
    // Attach each repo's baseline strength badge (JEF-266) to its existing group.
    for (repo, strength) in strengths_by_repo(rows) {
        if let Some(group) = groups.iter_mut().find(|g| g.repo == repo) {
            group.strength = strength;
        }
    }
    // Loud-first ordering (mirrors the findings urgency sort): images within a group float the
    // loudest posture up, and groups float a standing regression / the loudest image to the top —
    // most-attention-worthy on top. Both sorts are STABLE, so equal-urgency rows/groups keep their
    // first-seen (newest-first) order and a steady inventory renders stably across polls.
    for group in &mut groups {
        group.images.sort_by_key(|img| posture_rank(img.posture));
    }
    groups.sort_by_key(group_rank);
    groups
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod enforcement_tests;
