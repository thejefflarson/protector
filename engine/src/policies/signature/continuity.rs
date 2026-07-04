//! ADR-0020 Stage 3 (JEF-265) — the admission-time signing-**CONTINUITY** gate: the first code
//! that makes protector actually BLOCK admission on a signing signal, plus its scoped
//! "exception accepted" opt-out and the back-compat identity **PIN**.
//!
//! ## What it does (and, more importantly, what it does NOT)
//!
//! In **enforced scope only** (the shared `EnforceScope`; audit-everywhere by default), a signing
//! **regression** against a repo's ESTABLISHED baseline DENIES admission. The block predicate is
//! the DOMAIN verdict [`SigningDrift::would_block`] — the exact semantic JEF-297's presentation
//! `SigningEnforcement` projects, so "would block" in the inventory and "denied" at admission are
//! the same fact. Everything else admits:
//!
//!   * **Unconfigured ⇒ zero behavior change.** A [`ContinuityGate`] is only wired when the
//!     operator supplies an observer; absent that, [`SignaturePolicy`](super::SignaturePolicy)
//!     never even constructs one, so an out-of-the-box deploy is byte-identical shadow.
//!   * **Cold-start NEVER denies.** A freshly-learned / not-yet-`established` baseline is weak
//!     evidence (TOFU) — [`SigningDrift::would_block`] returns `false` for it, so admission admits
//!     (audit).
//!   * **Read-only on the baseline.** The gate holds a [`SharedSigningBaseline`] and only ever
//!     reads it. The analysis-engine sweep is the sole writer; admission can never teach a baseline,
//!     so it can't become its own poisoning oracle.
//!
//! ## "exception accepted" — scoped, recorded CONFIG, never a global mute
//!
//! [`SigningExceptions`] is a mounted-file / env config keyed by `repo:` OR exact `image:` ref, each
//! pinned to the drift FINGERPRINT it accepts. It admits ONLY that key's CURRENT drift; every other
//! repo stays enforced, and a DIFFERENT subsequent change re-flags loud (the fingerprint no longer
//! matches). There is deliberately NO global "disable signature continuity" switch and no dashboard
//! write path (ADR-0016: presentation is never a gate).
//!
//! ## The PIN — the old prefix gate as one pinned special case
//!
//! [`SigningPin`] is "repo prefix `X` must always be signed by identity matching `Y`" — a manually
//! asserted established baseline, equivalent to what TOFU would learn but declared up front. It is
//! the ADR-0020 pinned special case of the pre-ADR-0020 `PROTECTOR_GATED_PREFIXES` +
//! `PROTECTOR_IDENTITY_REGEXP` gate, preserving today's behavior.

use std::sync::Arc;

use regex::Regex;

use crate::engine::signing_drift::{RegressionKind, SigningDrift, classify};
use crate::engine::state::SharedSigningBaseline;

use super::posture::{SigningObserver, SigningPosture};
use super::{normalize_registry_host, repo_key};

/// The scope one "exception accepted" applies to: an exact image ref, or a whole `registry/repo`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ExceptionScope {
    /// The image's `repo_key` must equal this — the whole repo is opted out (for the one accepted
    /// drift), but no other repo is touched.
    Repo(String),
    /// The image ref must equal this exactly — a single image is opted out.
    Image(String),
}

/// One recorded, scoped "exception accepted" (JEF-265): a CONFIG entry opting ONE repo or image out
/// of continuity enforcement for ONE specific drift. Never a global mute (ADR-0020): it admits ONLY
/// its key and, because it is pinned to the drift [`fingerprint`](RegressionKind::fingerprint) it
/// accepts, a DIFFERENT subsequent change re-flags loud.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SigningException {
    scope: ExceptionScope,
    /// The drift fingerprint this accepts (`unsigned` / `invalid` / `downgrade-key-based` /
    /// `downgrade-unverifiable` / `identity:<new-id>`), matched against a regression's
    /// [`RegressionKind::fingerprint`].
    fingerprint: String,
}

/// The parsed set of "exception accepted" entries (JEF-265). Loaded from a mounted file and/or an
/// env var; empty when neither is configured (nothing is excepted — every repo stays enforced).
#[derive(Debug, Clone, Default)]
pub struct SigningExceptions {
    exceptions: Vec<SigningException>,
}

impl SigningExceptions {
    /// Parse a spec: one exception per line (file) or per `;`-separated entry (env). Each entry is
    /// `<scope> <fingerprint>`, where `<scope>` is `repo:<registry/repo>` or `image:<full ref>`.
    /// Blank lines and `#` comments are ignored. A malformed entry is skipped (fail-safe: a
    /// bad exception must never silently widen what is admitted — it simply doesn't except anything).
    pub fn parse(spec: &str) -> Self {
        let mut exceptions = Vec::new();
        for raw in spec.split(['\n', ';']) {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((scope_tok, fingerprint)) = line.split_once(char::is_whitespace) else {
                continue;
            };
            let fingerprint = fingerprint.trim();
            if fingerprint.is_empty() {
                continue;
            }
            let scope = if let Some(repo) = scope_tok.strip_prefix("repo:") {
                ExceptionScope::Repo(repo.trim().to_string())
            } else if let Some(image) = scope_tok.strip_prefix("image:") {
                ExceptionScope::Image(image.trim().to_string())
            } else {
                continue;
            };
            exceptions.push(SigningException {
                scope,
                fingerprint: fingerprint.to_string(),
            });
        }
        Self { exceptions }
    }

    /// Load from an optional mounted file plus an env spec, merged. A missing/unreadable file
    /// contributes nothing (never an error — a bad mount degrades to "no exceptions", the safe
    /// direction: more enforced, never less).
    pub fn from_sources(file: Option<&str>, env_spec: &str) -> Self {
        let mut merged = Self::parse(env_spec);
        if let Some(path) = file
            && let Ok(contents) = std::fs::read_to_string(path)
        {
            merged.exceptions.extend(Self::parse(&contents).exceptions);
        }
        merged
    }

    pub fn is_empty(&self) -> bool {
        self.exceptions.is_empty()
    }

    /// Whether a recorded exception covers this image's regression `kind`. Scoped (the image's exact
    /// ref OR its `repo_key`) AND fingerprinted (the exact accepted change), so it admits only this
    /// key's current drift and a different change re-flags.
    pub fn accepts(&self, image: &str, kind: &RegressionKind) -> bool {
        let repo = repo_key(image);
        let fingerprint = kind.fingerprint();
        self.exceptions.iter().any(|e| {
            e.fingerprint == fingerprint
                && match &e.scope {
                    ExceptionScope::Image(ref_) => ref_ == image,
                    ExceptionScope::Repo(r) => *r == repo,
                }
        })
    }
}

/// A back-compat identity PIN (JEF-265, ADR-0020): "every image under `prefix` must always be signed
/// by an identity matching `identity`". A manually-asserted established baseline — the exact semantic
/// of the pre-ADR-0020 prefix-gated single-identity gate. A pinned image that is not keyless-`Signed`
/// by a matching identity is a would-block regardless of any LEARNED baseline.
pub struct SigningPin {
    prefix: String,
    identity: Regex,
}

impl SigningPin {
    /// Build a pin from a `prefix` and a signer-identity regexp. Returns `None` on an un-compilable
    /// regexp (skipped, logged by the caller) so one bad pin never aborts startup.
    pub fn new(prefix: &str, identity_regexp: &str) -> Option<Self> {
        let identity = Regex::new(identity_regexp).ok()?;
        Some(Self {
            prefix: prefix.to_string(),
            identity,
        })
    }

    /// Whether this pin governs `image` (its normalized ref starts with the pinned prefix — the same
    /// host-normalization the legacy gate uses, so a case/port variant can't slip the pin).
    fn applies(&self, image: &str) -> bool {
        normalize_registry_host(image).starts_with(&self.prefix)
    }

    /// Whether `posture` satisfies the pin: a keyless-`Signed` posture whose identity matches. A
    /// key-based / unverifiable / unsigned / invalid posture — or a different signer — does not.
    fn satisfied(&self, posture: &SigningPosture) -> bool {
        match posture {
            SigningPosture::Signed(signer) => self.identity.is_match(&signer.identity),
            _ => false,
        }
    }
}

/// The admission-time signing-continuity gate (JEF-265). Wired into
/// [`SignaturePolicy`](super::SignaturePolicy) only when an observer is configured; absent, the
/// policy is byte-identical shadow.
pub struct ContinuityGate {
    /// Observes the ARRIVING image's posture (shares the sweep's TTL cache + `max_images` bound and
    /// the sanctioned outbound path — no new egress).
    observer: Arc<SigningObserver>,
    /// The read-only, engine-written baseline snapshot. NEVER mutated here.
    baseline: SharedSigningBaseline,
    /// The scoped, recorded "exception accepted" config.
    exceptions: SigningExceptions,
    /// The back-compat identity pins.
    pins: Vec<SigningPin>,
    /// Upper bound on distinct images classified per request (mirrors the gated cap so a Pod with
    /// many containers can't amplify verification).
    max_images: usize,
}

impl ContinuityGate {
    pub fn new(
        observer: Arc<SigningObserver>,
        baseline: SharedSigningBaseline,
        exceptions: SigningExceptions,
        pins: Vec<SigningPin>,
        max_images: usize,
    ) -> Self {
        Self {
            observer,
            baseline,
            exceptions,
            pins,
            max_images,
        }
    }

    /// The continuity verdict for a Pod's images: `Some(reason)` if any image would be BLOCKED by a
    /// signature-continuity gate (an established regression, a genuinely-invalid signature, or a pin
    /// violation) that no accepted exception covers; `None` if every image is continuous / cold /
    /// excepted. PURE of enforcement scope — the caller ([`EnforceScope`](crate::policy::EnforceScope))
    /// turns a block into `Deny` (in scope) vs `Audit` (out of scope). Bounded by `max_images`.
    pub async fn evaluate(&self, images: &[String]) -> Option<String> {
        let mut distinct: Vec<&String> = Vec::new();
        for image in images {
            if !distinct.contains(&image) {
                distinct.push(image);
            }
        }
        let mut blocked = Vec::new();
        for image in distinct.into_iter().take(self.max_images) {
            let posture = self.observer.observe(image).await;
            if let Some(reason) = self.block_reason(image, &posture) {
                blocked.push(reason);
            }
        }
        if blocked.is_empty() {
            None
        } else {
            Some(blocked.join("; "))
        }
    }

    /// The block reason for one image, or `None` if it is admissible (continuous / cold / excepted).
    /// Pins first (a manually-asserted baseline is authoritative), then learned-baseline continuity.
    fn block_reason(&self, image: &str, posture: &SigningPosture) -> Option<String> {
        // 1. Pins — the back-compat identity gate. A pinned repo must be keyless-signed by the pinned
        //    identity; anything else would-block. An "exception accepted" can still opt out a
        //    specific pin-violating drift (same scoped/fingerprinted rule as a learned regression).
        for pin in &self.pins {
            if pin.applies(image) && !pin.satisfied(posture) {
                let kind = pin_violation_kind(posture);
                if self.exceptions.accepts(image, &kind) {
                    return None;
                }
                return Some(format!(
                    "pinned repo requires a trusted signer but {} is {}",
                    image,
                    posture.status()
                ));
            }
        }

        // 2. Learned-baseline continuity (the ADR-0020 thesis). `would_block` == an established
        //    regression OR a genuinely-invalid signature; cold regressions are uncertain (admit).
        let repo = repo_key(image);
        let baseline = self.baseline.get(&repo);
        let drift = classify(baseline.as_ref(), posture);
        if !drift.would_block(posture) {
            return None;
        }
        // A block-worthy drift stands. Honor a scoped exception pinned to THIS drift.
        let kind = match &drift {
            SigningDrift::Regression { kind, .. } => kind.clone(),
            // `would_block` on a non-regression drift means a genuinely-invalid posture (the loud
            // channel — e.g. invalid with no baseline classifies Continuous). Its fingerprint is
            // `invalid`, so an operator can accept exactly that.
            _ => RegressionKind::Invalid,
        };
        if self.exceptions.accepts(image, &kind) {
            return None;
        }
        Some(format!(
            "signing regression on {repo}: {} ({})",
            posture.status(),
            kind.word()
        ))
    }
}

/// The [`RegressionKind`] a pin violation corresponds to, so a pin-violating drift can be accepted
/// by the SAME fingerprinted exception mechanism as a learned regression. A pinned repo serving an
/// unsigned image maps to `Unsigned`, a different keyless signer to an `IdentityChange`, and the
/// calm-but-untrusted / invalid postures to their kinds.
fn pin_violation_kind(posture: &SigningPosture) -> RegressionKind {
    match posture {
        SigningPosture::Signed(signer) => RegressionKind::IdentityChange {
            new_identity: signer.identity.clone(),
            new_issuer: signer.issuer.clone(),
        },
        SigningPosture::InvalidSignature => RegressionKind::Invalid,
        SigningPosture::SignedKeyBased => RegressionKind::Downgrade {
            to: super::PostureRank::KeyBased,
        },
        SigningPosture::UnverifiableHere => RegressionKind::Downgrade {
            to: super::PostureRank::Unverifiable,
        },
        // NotSigned / Checking ⇒ treat as unsigned for acceptance purposes.
        _ => RegressionKind::Unsigned,
    }
}

#[cfg(test)]
#[path = "continuity_tests.rs"]
mod tests;
