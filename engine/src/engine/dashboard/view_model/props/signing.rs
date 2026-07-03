//! Signing-inventory presentation props (JEF-262 / ADR-0020 Stage 1 render) + the
//! signing-regression banner (JEF-264): the observed signing posture of EVERY image, as a
//! dedicated inventory section, and — when a repo's signed history drifts — the loud regression
//! banner over its rows.
//!
//! Two hard operator rules for the inventory: the posture is ALWAYS signed / invalid signature /
//! not signed (or the transient checking) — never n/a; and the "if enforced" column is ALWAYS the
//! binary would-admit / would-block — never n/a. Every string here is UNTRUSTED at render (a Fulcio
//! SAN / image ref is attacker-influenceable): the components escape it (maud auto-escape; NEVER
//! `PreEscaped`). Split out of the parent `props` module to keep both files under the repo's
//! 1,000-line cap (CLAUDE.md); re-exported flat, so `props::SigningPosture` etc. resolve unchanged.

/// An image's observed signing posture — the presentation mirror of the domain
/// `signature::posture::SigningPosture` (mapped at the view_model boundary so components never
/// import the domain type). NEVER n/a: observation always reaches a posture, and a registry blip
/// is the explicit transient [`Checking`](Self::Checking), not a fabricated clean. Carried as
/// colour + glyph + word so meaning never rides on colour alone. [`Invalid`](Self::Invalid) is the
/// LOUD channel — visually and lexically distinct from a calm [`NotSigned`](Self::NotSigned).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningPosture {
    /// A signature is present and verifies (the signer rides [`SigningRowProps::signer`]).
    Signed,
    /// A signature artifact is present but does NOT verify — the loud, alarming case. Distinct
    /// from (and more alarming than) [`NotSigned`](Self::NotSigned).
    Invalid,
    /// No signature at all — calm (no baseline yet), never loud, but never a green pass either.
    NotSigned,
    /// Transient: the registry / transparency log was unreachable, so the posture is not yet
    /// known. Never read as clean; resolves into a resting posture on a later pass.
    Checking,
}

impl SigningPosture {
    /// Parse the engine's low-cardinality status word (`SigningPosture::status()`) into the
    /// presentation enum. An unknown / empty word reads as the transient
    /// [`Checking`](Self::Checking) rather than a fabricated resting posture — never a false clean.
    pub fn parse(word: &str) -> SigningPosture {
        match word {
            "signed" => SigningPosture::Signed,
            "invalid-signature" => SigningPosture::Invalid,
            "not-signed" => SigningPosture::NotSigned,
            _ => SigningPosture::Checking,
        }
    }

    /// The CSS token suffix (`--sign-{kind}`) for this posture.
    pub fn token(self) -> &'static str {
        match self {
            SigningPosture::Signed => "signed",
            SigningPosture::Invalid => "invalid",
            SigningPosture::NotSigned => "notsigned",
            SigningPosture::Checking => "checking",
        }
    }

    /// The glyph carrying the posture without colour — each distinct so `invalid` reads apart from
    /// `not signed` and `signed` even in greyscale.
    pub fn glyph(self) -> &'static str {
        match self {
            SigningPosture::Signed => "\u{2713}",    // ✓ present + verified
            SigningPosture::Invalid => "\u{2715}",   // ✕ present but broken — the loud channel
            SigningPosture::NotSigned => "\u{25CB}", // ○ open — nothing there, calm
            SigningPosture::Checking => "\u{25CC}",  // ◌ dotted — transient
        }
    }

    /// The word — always present alongside colour + glyph, and lexically distinct per state.
    pub fn word(self) -> &'static str {
        match self {
            SigningPosture::Signed => "signed",
            SigningPosture::Invalid => "invalid signature",
            SigningPosture::NotSigned => "not signed",
            SigningPosture::Checking => "checking\u{2026}",
        }
    }

    /// The binary "if enforced" counterfactual: only a verifying [`Signed`](Self::Signed) image
    /// would be admitted by a signature gate; every other posture (invalid / not signed / the
    /// unverifiable transient) would be blocked. Fail-closed — never n/a (operator rule #2).
    pub fn would_admit(self) -> bool {
        matches!(self, SigningPosture::Signed)
    }
}

/// The signer learned from a verified Fulcio cert (only present when [`SigningPosture::Signed`]).
/// Both the identity and issuer are UNTRUSTED third-party free-text (an attacker-influenceable cert
/// subject) — the component escapes them at render (maud auto-escape; NEVER `PreEscaped`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerProps {
    /// A short, scannable label derived from the Fulcio SAN (a GitHub Actions workflow URI →
    /// `org/repo`; an email kept as-is; otherwise the raw identity, truncated in-row by CSS). Shown
    /// in the row.
    pub identity_short: String,
    /// The full Fulcio SAN — shown in the expand panel and the `title=`, so the truncated in-row
    /// label never hides the real signer.
    pub identity_full: String,
    /// A short issuer badge derived from the OIDC issuer (`github actions` / `google` / `sigstore`
    /// / the host), or empty when the cert carried no issuer.
    pub issuer_badge: String,
    /// The full OIDC issuer URL for the expand panel, or `None` when the cert carried none.
    pub issuer_full: Option<String>,
}

/// One image row in the signing inventory (JEF-262). Plain presentation data only — mapped from the
/// engine `PolicyDecisionRecord` at the view_model boundary. Every string is UNTRUSTED at render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningRowProps {
    /// A stable, collision-free DOM/fragment id for this image's summary + detail rows — the key
    /// the client toggles/persists across the /fragment poll (mirrors `FindingProps::id`). Derived
    /// in the view_model from the FULL image ref (a readable slug + a short hash of the ref, so two
    /// images that slugify alike still get distinct ids). Never untrusted free-text: it is
    /// `[a-z0-9-]` only, so it is safe as an `id`/`data-*`/`aria-controls` value.
    pub dom_id: String,
    /// The full image ref (registry/repo + digest/tag), untrusted — shown in the expand panel and
    /// the `title=`.
    pub image: String,
    /// The in-row image label: the digest/tag remainder under the repo group (falls back to the
    /// full ref when the image carries no tag/digest), untrusted.
    pub label: String,
    pub posture: SigningPosture,
    /// The signer, present only when [`posture`](Self::posture) is [`SigningPosture::Signed`].
    pub signer: Option<SignerProps>,
    /// The human-facing posture prose for the expand panel (why invalid / still checking); empty
    /// for a plain not-signed, which needs no prose. Untrusted.
    pub detail: String,
    /// How many times this exact image was observed (the dedup count).
    pub count: u64,
}

/// The strength of a repo's learned signing baseline (JEF-266, ADR-0020 §4): whether the public
/// Rekor transparency log corroborates its history (real provenance) or it rests on local
/// trust-on-first-sight alone. Surfaced as a small header badge so the operator can weigh a
/// baseline's evidence honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoStrength {
    /// The public transparency log vouches for this repo's signing history — a STRONGER baseline.
    LogCorroborated,
    /// Trust-on-first-local-sight only — the weaker default, and the only state when the Rekor lane
    /// is off. Honestly flagged so a fresh baseline is not read as ground truth.
    LocalOnly,
    /// No strength row observed for this repo (no learned baseline yet) — no badge.
    Unknown,
}

impl RepoStrength {
    /// Parse the strength row's low-cardinality word (`log-corroborated` / `local-only`).
    pub fn parse(word: &str) -> RepoStrength {
        match word {
            "log-corroborated" => RepoStrength::LogCorroborated,
            "local-only" => RepoStrength::LocalOnly,
            _ => RepoStrength::Unknown,
        }
    }

    /// The CSS token suffix + `data-strength` value for this strength (fixed, never untrusted text).
    pub fn token(self) -> &'static str {
        match self {
            RepoStrength::LogCorroborated => "corroborated",
            RepoStrength::LocalOnly => "local",
            RepoStrength::Unknown => "unknown",
        }
    }

    /// The badge word shown in the baseline column.
    pub fn word(self) -> &'static str {
        match self {
            RepoStrength::LogCorroborated => "log-corroborated",
            RepoStrength::LocalOnly => "new baseline (local only)",
            RepoStrength::Unknown => "",
        }
    }

    /// The honest baseline prose for the row's expand panel: what the strength means for how much
    /// the operator should trust this repo's learned signing history. `Unknown` is stated as "no
    /// baseline learned yet" — never implied as an all-clear.
    pub fn detail(self) -> &'static str {
        match self {
            RepoStrength::LogCorroborated => {
                "log-corroborated \u{2014} the public transparency log vouches for this repo's \
                 signing history (a stronger baseline than local trust-on-first-sight)."
            }
            RepoStrength::LocalOnly => {
                "new baseline (local only) \u{2014} trust-on-first-sight; the public transparency \
                 log has not yet corroborated this repo's signing history."
            }
            RepoStrength::Unknown => "no signing baseline learned for this repo yet.",
        }
    }
}

/// A repo group in the signing inventory: one registry/repo header with the images observed under
/// it (JEF-262 — the inventory unit is the image, grouped under its repo), plus an optional loud
/// signing-regression banner (JEF-264) when the repo's signed history has drifted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningRepoProps {
    /// The registry/repo the images share (the group header), untrusted.
    pub repo: String,
    /// The images observed under this repo.
    pub images: Vec<SigningRowProps>,
    /// A standing signing regression against this repo's baseline (JEF-264), rendered as the LOUD
    /// channel above the image rows; `None` when the repo is continuous.
    pub regression: Option<SigningRegressionProps>,
    /// The strength of this repo's baseline (JEF-266): log-corroborated vs local-only, rendered as
    /// a small header badge. [`RepoStrength::Unknown`] when no baseline strength was observed.
    pub strength: RepoStrength,
}

/// Which kind of signing regression a repo drifted into (JEF-264) — the presentation mirror of the
/// engine `signing_drift::RegressionKind`. The LOUD channel: visually + lexically distinct from the
/// calm [`SigningPosture::NotSigned`]. Carried as glyph + word so meaning never rides on colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegressionKind {
    /// A repo with signed history now serves an unsigned image.
    Unsigned,
    /// A repo with signed history now serves an image whose signature does not verify.
    Invalid,
    /// A repo is now signed by an identity never before seen under it (a new signer).
    IdentityChange,
    /// Registry↔log divergence (JEF-266): the registry serves a signature the public transparency
    /// log has NO entry for (a signature that never reached the append-only log).
    DivergenceRegistrySigned,
    /// Registry↔log divergence (JEF-266): the transparency log records a signature the registry now
    /// serves UNSIGNED (a signature stripped at the registry while the log remembers it).
    DivergenceLogSigned,
}

impl RegressionKind {
    /// Parse the recorded drift kind word (`unsigned` / `invalid` / `identity`). An unknown word
    /// reads as [`Unsigned`](Self::Unsigned) — a conservative "signing regression" default rather
    /// than a fabricated calm state (a regression row exists, so it is never continuous).
    pub fn parse(word: &str) -> RegressionKind {
        match word {
            "invalid" => RegressionKind::Invalid,
            "identity" => RegressionKind::IdentityChange,
            "divergence-registry" => RegressionKind::DivergenceRegistrySigned,
            "divergence-log" => RegressionKind::DivergenceLogSigned,
            _ => RegressionKind::Unsigned,
        }
    }

    /// The CSS token suffix (`--regression-{kind}`) for this kind.
    pub fn token(self) -> &'static str {
        match self {
            RegressionKind::Unsigned => "unsigned",
            RegressionKind::Invalid => "invalid",
            RegressionKind::IdentityChange => "identity",
            RegressionKind::DivergenceRegistrySigned => "divergence-registry",
            RegressionKind::DivergenceLogSigned => "divergence-log",
        }
    }

    /// The loud headline word for the regression banner — always the literal "signing regression"
    /// prefix (visually + lexically distinct from calm "not signed"), qualified by what drifted.
    pub fn word(self) -> &'static str {
        match self {
            RegressionKind::Unsigned => "signing regression \u{2014} now unsigned",
            RegressionKind::Invalid => "signing regression \u{2014} now invalid signature",
            RegressionKind::IdentityChange => "signing regression \u{2014} new signer",
            RegressionKind::DivergenceRegistrySigned | RegressionKind::DivergenceLogSigned => {
                "signing regression \u{2014} registry\u{2194}log divergence"
            }
        }
    }

    /// The "after" prose for an unsigned/invalid regression (the identity-change case shows the new
    /// signer instead).
    pub fn after_word(self) -> &'static str {
        match self {
            RegressionKind::Unsigned => "no signature present",
            RegressionKind::Invalid => "signature present but does not verify",
            RegressionKind::IdentityChange => "signed by a new identity",
            RegressionKind::DivergenceRegistrySigned => {
                "registry serves a signature absent from the public transparency log"
            }
            RegressionKind::DivergenceLogSigned => {
                "the transparency log records a signature the registry now serves unsigned"
            }
        }
    }
}

/// A standing signing-regression banner for a repo group (JEF-264, ADR-0020 §3): the repo's signed
/// history drifted — now unsigned/invalid, or signed by a new identity. Audit-only (the image is
/// still admitted); rendered as the LOUD breach-rail channel with the FULL before→after identities.
///
/// Every identity/issuer string is UNTRUSTED Fulcio cert text — the component escapes it via maud
/// interpolation (NEVER `PreEscaped`, never concatenated into markup, never a `class=`/CSS value).
/// The full identities are shown deliberately (not the shortened `org/repo` label): the point is to
/// show the operator EXACTLY what changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningRegressionProps {
    /// A stable, collision-free DOM/fragment id for the regression's summary + detail rows (the key
    /// the client toggles/persists). Derived in the view_model from the repo, with a distinct
    /// prefix from image rows so an image whose ref equals its repo can never share an id. `[a-z0-9-]`
    /// only — safe as an `id`/`data-*`/`aria-controls` value.
    pub dom_id: String,
    /// What drifted (unsigned / invalid / new signer).
    pub kind: RegressionKind,
    /// Whether the baseline was established (a strong breach signal) or cold/freshly-learned (a
    /// weak lead — reduced intensity, "treat as a lead", maps to uncertain).
    pub established: bool,
    /// The baseline signer identities in FULL (the "before"), UNTRUSTED — escaped at render.
    pub before_identities: Vec<String>,
    /// The new signer identity in FULL (the "after") for an identity-change; `None` for an
    /// unsigned/invalid regression. UNTRUSTED — escaped at render.
    pub after_identity: Option<String>,
    /// The new signer's issuer in full, if the cert carried one. UNTRUSTED — escaped at render.
    pub after_issuer: Option<String>,
    /// The image ref that regressed (the "after" image), UNTRUSTED — escaped at render.
    pub image: String,
}
