//! Signing-inventory presentation props (JEF-262 / ADR-0020 Stage 1 render) + the
//! signing-regression banner (JEF-264): the observed signing posture of EVERY image, as a
//! dedicated inventory section, and — when a repo's signed history drifts — the loud regression
//! banner over its rows.
//!
//! Two hard operator rules for the inventory: the posture is ALWAYS one of the honest resting
//! states — keyless-verified / signed-key-based / unverifiable-here / invalid / not-signed (or the
//! transient checking) — never n/a; and the "if enforced" column is ALWAYS a definite
//! continuity verdict — would-admit / would-block / uncertain — never n/a. That verdict is
//! baseline-relative continuity (JEF-297, ADR-0020), NOT the raw posture: a calm, consistent
//! posture admits, only a genuine REGRESSION against the repo's established baseline blocks, and a
//! regression against a cold/freshly-learned baseline reads UNCERTAIN (non-green, never a hard
//! block). See [`SigningEnforcement`]. Every string here is UNTRUSTED at render (a Fulcio SAN /
//! image ref is attacker-influenceable): the components escape it (maud auto-escape; NEVER
//! `PreEscaped`). Split out of the parent `props` module to keep both files under the repo's
//! 1,000-line cap (CLAUDE.md); re-exported flat, so `props::SigningPosture` etc. resolve unchanged.

/// An image's observed signing posture — the presentation mirror of the domain
/// `signature::posture::SigningPosture` (mapped at the view_model boundary so components never
/// import the domain type). NEVER n/a: observation always reaches a posture, and a registry blip
/// is the explicit transient [`Checking`](Self::Checking), not a fabricated clean. Carried as
/// colour + glyph + word so meaning never rides on colour alone. [`Invalid`](Self::Invalid) is the
/// LOUD channel — visually and lexically distinct from a calm [`NotSigned`](Self::NotSigned).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningPosture {
    /// Keyless-verified: a signature is present and verifies against Fulcio + Rekor (the signer
    /// rides [`SigningRowProps::signer`]). The one trusted-identity posture. Calm.
    Signed,
    /// Signed with a key-based cosign signature (JEF-276): a verified transparency-log bundle but no
    /// Fulcio identity — real and log-included, signer opaque. CALM, never the loud channel.
    SignedKeyBased,
    /// A signature is present but could not be verified against our trust root (JEF-276): a
    /// Rekor/TUF variance, honestly "couldn't verify here" — NOT "forged". Calm-ish, distinct from
    /// the loud [`Invalid`](Self::Invalid).
    Unverifiable,
    /// A signature artifact is present but GENUINELY fails to verify — the loud, alarming case.
    /// Distinct from (and more alarming than) every other state.
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
            "signed-key-based" => SigningPosture::SignedKeyBased,
            "unverifiable" => SigningPosture::Unverifiable,
            "invalid-signature" => SigningPosture::Invalid,
            "not-signed" => SigningPosture::NotSigned,
            _ => SigningPosture::Checking,
        }
    }

    /// The CSS token suffix (`--sign-{kind}`) for this posture.
    pub fn token(self) -> &'static str {
        match self {
            SigningPosture::Signed => "signed",
            SigningPosture::SignedKeyBased => "signedkey",
            SigningPosture::Unverifiable => "unverifiable",
            SigningPosture::Invalid => "invalid",
            SigningPosture::NotSigned => "notsigned",
            SigningPosture::Checking => "checking",
        }
    }

    /// The glyph carrying the posture without colour — each distinct so `invalid` reads apart from
    /// the calm signed/key-based/unverifiable/not-signed states even in greyscale.
    pub fn glyph(self) -> &'static str {
        match self {
            SigningPosture::Signed => "\u{2713}", // ✓ present + keyless-verified
            SigningPosture::SignedKeyBased => "\u{2714}", // ✔ signed, opaque signer — calm
            SigningPosture::Unverifiable => "\u{25D0}", // ◐ present, unverified here — calm-ish
            SigningPosture::Invalid => "\u{2715}", // ✕ present but broken — the loud channel
            SigningPosture::NotSigned => "\u{25CB}", // ○ open — nothing there, calm
            SigningPosture::Checking => "\u{25CC}", // ◌ dotted — transient
        }
    }

    /// The word — always present alongside colour + glyph, and lexically distinct per state.
    pub fn word(self) -> &'static str {
        match self {
            SigningPosture::Signed => "signed",
            SigningPosture::SignedKeyBased => "signed (key-based)",
            SigningPosture::Unverifiable => "unverifiable here",
            SigningPosture::Invalid => "invalid signature",
            SigningPosture::NotSigned => "not signed",
            SigningPosture::Checking => "checking\u{2026}",
        }
    }

    /// Whether this posture is the RESERVED loud channel: a signature artifact that GENUINELY fails
    /// to verify (tampered payload / a Fulcio cert whose Rekor inclusion does not hold). Distinct
    /// from every calm state. A genuinely-broken signature is never admissible independent of any
    /// baseline, so the continuity verdict blocks it outright (see
    /// [`SigningEnforcement::for_image`]) — an attacker cannot dodge the would-block by keeping a
    /// repo's baseline cold.
    pub fn is_genuinely_invalid(self) -> bool {
        matches!(self, SigningPosture::Invalid)
    }
}

/// The baseline-relative "if enforced" verdict for an image's signing posture (JEF-297, ADR-0020) —
/// the counterfactual a signature-continuity gate (JEF-265) would apply. It is deliberately NOT the
/// raw posture: the pre-ADR-0020 single-identity gate (would-admit ⇔ keyless-Fulcio) showed the
/// entire key-based-signed fleet as would-block, contradicting JEF-276 (key-based is calm) and
/// ADR-0020 (block on REGRESSION from baseline, not on keyless-ness). The verdict here is the
/// negation of a REGRESSION: a calm, consistent posture with no drift vs its baseline admits; only a
/// genuine drift blocks.
///
/// Three definite states (never n/a — operator rule #2):
///   * [`WouldAdmit`](Self::WouldAdmit) — continuous vs the baseline: keyless-verified `Signed`,
///     consistent key-based / unverifiable-here, or not-signed where the repo was never signed
///     (TOFU). No regression stands for the image.
///   * [`WouldBlock`](Self::WouldBlock) — a genuine regression against an ESTABLISHED baseline
///     (signing downgrade / identity change / signed→unsigned / signed→invalid), OR a genuinely
///     invalid signature (the loud channel, inadmissible independent of baseline).
///   * [`Uncertain`](Self::Uncertain) — a regression against a COLD/freshly-learned baseline: a weak
///     lead (JEF-280 cold=uncertain). Non-green, but NOT a hard block — honours the cold-baseline
///     honesty invariant (a fresh baseline is the weakest evidence, never enforced as breach).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningEnforcement {
    /// Continuous vs baseline — a continuity gate would admit. The calm/consistent resting state.
    WouldAdmit,
    /// A genuine regression against an established baseline, or a genuinely-invalid signature — a
    /// continuity gate would block. The loud channel.
    WouldBlock,
    /// A regression against a cold/freshly-learned baseline — a weak lead: non-green, not a block.
    Uncertain,
    /// A regression the operator has explicitly opted out of via a scoped, recorded "exception
    /// accepted" (JEF-265): the continuity gate ADMITS this image (only this repo/image, only this
    /// drift), so it is calm — but DISTINCTLY labelled (never "signed"/cleared-green), stays visible,
    /// and does not count toward breach. A DIFFERENT subsequent change re-flags as a loud block.
    ExceptionAccepted,
}

impl SigningEnforcement {
    /// The continuity verdict for one image, given its posture and whether a signing-regression
    /// stands for that image (and, when it does, whether the regressed baseline was `established`).
    ///
    /// The drift verdict is the SINGLE source of truth: it is the SAME recorded
    /// [`SigningDrift::Regression`](crate::engine::supply_chain::signing_drift::SigningDrift) the sweep (JEF-264 /
    /// JEF-280) classified via [`classify`](crate::engine::supply_chain::signing_drift::classify) and a continuity
    /// gate (JEF-265) would enforce — the view never re-derives it, so the "if enforced" column can
    /// never disagree with what enforcement actually blocks (`block == regression`).
    ///
    /// `regression`: `Some(established)` when a signing-regression stands for the image (`true` ⇒ an
    /// established baseline, `false` ⇒ cold); `None` when the image is continuous. A genuinely
    /// [`invalid`](SigningPosture::is_genuinely_invalid) posture blocks outright regardless — a
    /// broken signature is never admissible, and short-circuiting it keeps an attacker from evading
    /// the would-block by keeping the repo's baseline cold.
    pub fn for_image(posture: SigningPosture, regression: Option<bool>) -> SigningEnforcement {
        if posture.is_genuinely_invalid() {
            return SigningEnforcement::WouldBlock;
        }
        match regression {
            Some(true) => SigningEnforcement::WouldBlock,
            Some(false) => SigningEnforcement::Uncertain,
            None => SigningEnforcement::WouldAdmit,
        }
    }

    /// The CSS token suffix (`--enforced-{token}`) + the fixed low-cardinality word for this verdict.
    /// Both are constant strings, never untrusted text.
    pub fn token(self) -> &'static str {
        match self {
            SigningEnforcement::WouldAdmit => "admit",
            SigningEnforcement::WouldBlock => "block",
            SigningEnforcement::Uncertain => "uncertain",
            SigningEnforcement::ExceptionAccepted => "exception",
        }
    }

    /// The word shown alongside colour + glyph, lexically distinct per verdict. The exception word is
    /// deliberately its OWN phrase — never "signed" / "admit" — so an opted-out drift never reads as
    /// a clean pass.
    pub fn word(self) -> &'static str {
        match self {
            SigningEnforcement::WouldAdmit => "would admit",
            SigningEnforcement::WouldBlock => "would block",
            SigningEnforcement::Uncertain => "uncertain",
            SigningEnforcement::ExceptionAccepted => "exception accepted",
        }
    }

    /// The glyph carrying the verdict without colour — each distinct so meaning survives greyscale.
    pub fn glyph(self) -> &'static str {
        match self {
            SigningEnforcement::WouldAdmit => "\u{2713}", // ✓ admit
            SigningEnforcement::WouldBlock => "\u{2715}", // ✕ block — the loud channel
            SigningEnforcement::Uncertain => "\u{25D0}",  // ◐ half — weak lead, non-green
            SigningEnforcement::ExceptionAccepted => "\u{25C8}", // ◈ distinct — scoped opt-out
        }
    }
}

/// An image's observed build-provenance posture (JEF-275 / ADR-0020 §5) — the presentation mirror of
/// the domain `signature::provenance::ProvenancePosture` (mapped at the view_model boundary so
/// components never import the domain type). NEVER n/a: observation always reaches a posture, and a
/// registry blip is the explicit transient [`Checking`](Self::Checking), not a fabricated clean.
/// Carried as colour + glyph + word so meaning never rides on colour alone.
///
/// SECURITY: only [`Verified`](Self::Verified) confers a trusted build. [`Absent`](Self::Absent) —
/// the common case today — is calm (like a not-signed image), NEVER an alarm, but never a trusted
/// build either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvenancePosture {
    /// A SLSA build-provenance attestation verified against Fulcio + Rekor and yielded a builder
    /// identity (which rides [`SigningRowProps::provenance_info`]). The one trusted-build posture.
    Verified,
    /// A provenance attestation is present but could not be verified against our trust root, or
    /// verified but carried no builder identity. Honest "present, not trusted here" — never trusted.
    Unverifiable,
    /// No provenance attestation at all — the common case today. Calm, never an alarm, but never a
    /// trusted build either.
    Absent,
    /// Transient: the registry / transparency log was unreachable, so the posture is not yet known.
    /// Never read as clean; resolves into a resting posture on a later pass.
    Checking,
}

impl ProvenancePosture {
    /// Parse the engine's low-cardinality status word (`ProvenancePosture::status()`). An unknown /
    /// empty word reads as the transient [`Checking`](Self::Checking) rather than a fabricated
    /// resting posture — never a false "no provenance", never a false "verified".
    pub fn parse(word: &str) -> ProvenancePosture {
        match word {
            "provenance-verified" => ProvenancePosture::Verified,
            "provenance-unverifiable" => ProvenancePosture::Unverifiable,
            "no-provenance" => ProvenancePosture::Absent,
            _ => ProvenancePosture::Checking,
        }
    }

    /// The CSS token suffix (`--prov-{kind}`) + `data-provenance` value (fixed, never untrusted).
    pub fn token(self) -> &'static str {
        match self {
            ProvenancePosture::Verified => "verified",
            ProvenancePosture::Unverifiable => "unverifiable",
            ProvenancePosture::Absent => "absent",
            ProvenancePosture::Checking => "checking",
        }
    }

    /// The glyph carrying the posture without colour.
    pub fn glyph(self) -> &'static str {
        match self {
            ProvenancePosture::Verified => "\u{2713}", // ✓ verified build
            ProvenancePosture::Unverifiable => "\u{25D0}", // ◐ present, not trusted here
            ProvenancePosture::Absent => "\u{25CB}",   // ○ open — none, calm
            ProvenancePosture::Checking => "\u{25CC}", // ◌ dotted — transient
        }
    }

    /// The word — always present alongside colour + glyph, lexically distinct per state.
    pub fn word(self) -> &'static str {
        match self {
            ProvenancePosture::Verified => "provenance",
            ProvenancePosture::Unverifiable => "unverifiable",
            ProvenancePosture::Absent => "no provenance",
            ProvenancePosture::Checking => "checking\u{2026}",
        }
    }

    /// Whether this posture confers a trusted build (only [`Verified`](Self::Verified)). The honesty
    /// side: absent / unverifiable / checking never read as a trusted build.
    pub fn is_verified(self) -> bool {
        matches!(self, ProvenancePosture::Verified)
    }
}

/// The build provenance learned from a VERIFIED SLSA attestation (only present when
/// [`ProvenancePosture::Verified`]). Both fields are UNTRUSTED predicate text — the component escapes
/// them at render (maud auto-escape; NEVER `PreEscaped`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProvenanceProps {
    /// A short, scannable source-repo label (`org/repo` from `github.com/org/repo`), shown in-row.
    pub source_short: String,
    /// The full source repo, shown in the expand panel + `title=`.
    pub source_full: String,
    /// A short builder label (`org/repo` from a GitHub Actions workflow URI), shown in-row.
    pub builder_short: String,
    /// The full builder identity (SLSA `builder.id`), shown in the expand panel + `title=`.
    pub builder_full: String,
}

/// The signer learned from a verified Fulcio cert (only present when [`SigningPosture::Signed`]).
/// Both the identity and issuer are UNTRUSTED third-party free-text (an attacker-influenceable cert
/// subject) — the component escapes them at render (maud auto-escape; NEVER `PreEscaped`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
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
    /// The observed build-provenance posture (JEF-275) — the second continuity axis, rendered as its
    /// own column. [`ProvenancePosture::Absent`] (the common case today) renders calm, never n/a.
    pub provenance: ProvenancePosture,
    /// The verified build provenance (source + builder), present only when
    /// [`provenance`](Self::provenance) is [`ProvenancePosture::Verified`]. UNTRUSTED — escaped.
    pub provenance_info: Option<ProvenanceProps>,
    /// The human-facing posture prose for the expand panel (why invalid / still checking); empty
    /// for a plain not-signed, which needs no prose. Untrusted.
    pub detail: String,
    /// The baseline-relative "if enforced" continuity verdict for this image (JEF-297) — would-admit
    /// / would-block / uncertain, derived from whether a signing-regression stands for this image,
    /// NOT from the raw posture. See [`SigningEnforcement`].
    pub enforcement: SigningEnforcement,
    /// How many times this exact image was observed (the dedup count).
    pub count: u64,
}

/// The strength of a repo's learned signing baseline (JEF-266, ADR-0020 §4): whether the public
/// Rekor transparency log corroborates its history (real provenance) or it rests on local
/// trust-on-first-sight alone. Surfaced as a small header badge so the operator can weigh a
/// baseline's evidence honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct SigningRepoProps {
    /// The registry/repo the images share (the group header), untrusted.
    pub repo: String,
    /// The images observed under this repo.
    pub images: Vec<SigningRowProps>,
    /// A standing signing regression against this repo's baseline (JEF-264), rendered as the LOUD
    /// channel above the image rows; `None` when the repo is continuous.
    pub regression: Option<SigningRegressionProps>,
    /// A standing "exception accepted" (JEF-265): a regression the operator has opted out of via a
    /// scoped, recorded exception. Rendered CALM + distinctly labelled "exception accepted" (never
    /// the loud regression channel, never green-cleared), kept visible, and NOT counted toward
    /// breach. `None` when no accepted exception stands for this repo.
    pub exception: Option<ExceptionAcceptedProps>,
    /// A standing build-provenance change against this repo's provenance baseline (JEF-275), rendered
    /// as the LOUD channel above the image rows (distinct from a signing regression — a repo can have
    /// both); `None` when the repo's provenance is continuous.
    pub provenance_change: Option<ProvenanceChangeProps>,
    /// The strength of this repo's baseline (JEF-266): log-corroborated vs local-only, rendered as
    /// a small header badge. [`RepoStrength::Unknown`] when no baseline strength was observed.
    pub strength: RepoStrength,
}

/// A standing build-provenance change banner for a repo group (JEF-275, ADR-0020 §5): the repo's
/// established provenance identity drifted — an image was built by an unexpected builder or from an
/// unexpected source. Audit-only (the image is still admitted); rendered as the LOUD channel with the
/// FULL before→after builder identities.
///
/// Every builder/source string is UNTRUSTED predicate text — the component escapes it via maud
/// interpolation (NEVER `PreEscaped`, never a `class=`/CSS value). The full identities are shown
/// deliberately: the point is to show the operator EXACTLY what changed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProvenanceChangeProps {
    /// A stable, collision-free DOM/fragment id (a distinct prefix from image + signing-regression
    /// rows). `[a-z0-9-]` only — safe as an `id`/`data-*`/`aria-controls` value.
    pub dom_id: String,
    /// Whether the baseline was established (a strong signal) or cold/freshly-learned (a weak lead).
    pub established: bool,
    /// The baseline builder identities in FULL (the "before"), UNTRUSTED — escaped at render.
    pub before_builders: Vec<String>,
    /// The new (deviating) builder identity in FULL (the "after"), UNTRUSTED — escaped at render.
    pub after_builder: String,
    /// The new (deviating) source repo in FULL (the "after"), UNTRUSTED — escaped at render.
    pub after_source: String,
    /// The image ref that drifted (the "after" image), UNTRUSTED — escaped at render.
    pub image: String,
}

/// A standing "exception accepted" banner for a repo group (JEF-265, ADR-0020 Stage 3): a signing
/// regression the operator has explicitly opted out of via a scoped, recorded exception. It is
/// deliberately CALM (not the loud breach-rail regression channel) yet DISTINCTLY labelled
/// "exception accepted" — never "signed"/cleared-green — and stays VISIBLE so the opt-out is never
/// hidden. It does not count toward breach. A DIFFERENT subsequent change re-flags loud (that is a
/// fresh regression the exception's fingerprint no longer covers).
///
/// Every identity string is UNTRUSTED Fulcio SAN text — the component escapes it via maud
/// interpolation (NEVER `PreEscaped`, never a `class=`/CSS value). The before→after is shown so the
/// operator sees EXACTLY what was accepted.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExceptionAcceptedProps {
    /// A stable, collision-free DOM/fragment id (a distinct prefix from image + regression rows).
    /// `[a-z0-9-]` only — safe as an `id`/`data-*`/`aria-controls` value.
    pub dom_id: String,
    /// What drifted (the accepted change) — reuses the regression kind vocabulary.
    pub kind: RegressionKind,
    /// Whether the accepted regression's baseline was established (a strong signal, accepted) or
    /// cold (a weak lead). Shown so the operator knows the weight of what they accepted.
    pub established: bool,
    /// The baseline signer identities in FULL (the "before"), UNTRUSTED — escaped at render.
    pub before_identities: Vec<String>,
    /// The new (accepted) signer identity in FULL, for an identity-change; `None` otherwise.
    /// UNTRUSTED — escaped at render.
    pub after_identity: Option<String>,
    /// The image ref the accepted exception covers (the "after" image), UNTRUSTED — escaped.
    pub image: String,
}

/// Which kind of signing regression a repo drifted into (JEF-264) — the presentation mirror of the
/// engine `signing_drift::RegressionKind`. The LOUD channel: visually + lexically distinct from the
/// calm [`SigningPosture::NotSigned`]. Carried as glyph + word so meaning never rides on colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
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
    /// Signing downgrade (JEF-280): a repo whose established baseline was keyless-verified now
    /// serves a key-based signature (Rekor bundle, no Fulcio identity) — a lesser posture that,
    /// against a keyless baseline, is the registry-substitution signal.
    DowngradeKeyBased,
    /// Signing downgrade (JEF-280): a repo whose established baseline was keyless-verified now
    /// serves a signature unverifiable against our trust root — a lesser posture that, against a
    /// keyless baseline, is the registry-substitution / trust-root-drift signal.
    DowngradeUnverifiable,
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
            "downgrade-key-based" => RegressionKind::DowngradeKeyBased,
            "downgrade-unverifiable" => RegressionKind::DowngradeUnverifiable,
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
            RegressionKind::DowngradeKeyBased => "downgrade-key-based",
            RegressionKind::DowngradeUnverifiable => "downgrade-unverifiable",
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
            RegressionKind::DowngradeKeyBased | RegressionKind::DowngradeUnverifiable => {
                "signing regression \u{2014} signing downgrade"
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
            RegressionKind::DowngradeKeyBased => {
                "now key-based \u{2014} no keyless identity (was keyless-verified)"
            }
            RegressionKind::DowngradeUnverifiable => {
                "now unverifiable against our trust root (was keyless-verified)"
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
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
