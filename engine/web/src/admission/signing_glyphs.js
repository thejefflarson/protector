// Presentation lookup tables for the signing inventory (ADR-0025 / JEF-400). The JSON ships each
// signing posture / provenance posture / continuity verdict / regression kind / baseline strength
// as a STABLE kebab-case string tag; these tables map that tag to its CSS token + glyph + word,
// exactly as the maud `SigningPosture::glyph/word/token` etc. do in Rust. Every state keeps
// GLYPH + WORD + colour token so meaning never rides on colour alone (the STYLEGUIDE a11y gate).
//
// This is PRESENTATION ONLY, not honesty derivation: the client never re-derives a posture or a
// continuity verdict — those are the server's decided tags. Mapping a known tag to its fixed
// glyph/word is the same static table maud compiles in; it introduces no new judgement. An unknown
// tag defaults to the transient/loud safe reading (never a fabricated clean/green).

/** Signing posture wire tag → { token, glyph, word }. Mirrors `SigningPosture`. */
export const POSTURE = {
  signed: { token: "signed", glyph: "\u{2713}", word: "signed" }, // ✓
  "signed-key-based": { token: "signedkey", glyph: "\u{2714}", word: "signed (key-based)" }, // ✔
  unverifiable: { token: "unverifiable", glyph: "\u{25D0}", word: "unverifiable here" }, // ◐
  invalid: { token: "invalid", glyph: "\u{2715}", word: "invalid signature" }, // ✕ — loud
  "not-signed": { token: "notsigned", glyph: "\u{25CB}", word: "not signed" }, // ○
  checking: { token: "checking", glyph: "\u{25CC}", word: "checking\u{2026}" }, // ◌
};

/** Look up a signing posture, defaulting to the transient `checking` (never a false clean). */
export function posture(tag) {
  return POSTURE[tag] || POSTURE.checking;
}

/** Whether a posture is the reserved LOUD invalid channel (the attention keyline). */
export function isInvalid(tag) {
  return tag === "invalid";
}

/** Provenance posture wire tag → { token, glyph, word }. Mirrors `ProvenancePosture`. */
export const PROVENANCE = {
  verified: { token: "verified", glyph: "\u{2713}", word: "provenance" }, // ✓
  unverifiable: { token: "unverifiable", glyph: "\u{25D0}", word: "unverifiable" }, // ◐
  absent: { token: "absent", glyph: "\u{25CB}", word: "no provenance" }, // ○
  checking: { token: "checking", glyph: "\u{25CC}", word: "checking\u{2026}" }, // ◌
};

/** Look up a provenance posture, defaulting to the transient `checking`. */
export function provenance(tag) {
  return PROVENANCE[tag] || PROVENANCE.checking;
}

/** Continuity "if enforced" verdict wire tag → { token, glyph, word }. Mirrors `SigningEnforcement`. */
export const ENFORCEMENT = {
  "would-admit": { token: "admit", glyph: "\u{2713}", word: "would admit" }, // ✓
  "would-block": { token: "block", glyph: "\u{2715}", word: "would block" }, // ✕ — loud
  uncertain: { token: "uncertain", glyph: "\u{25D0}", word: "uncertain" }, // ◐
  "exception-accepted": { token: "exception", glyph: "\u{25C8}", word: "exception accepted" }, // ◈
};

/** Look up a continuity verdict, defaulting to `uncertain` (non-green, never a false admit). */
export function enforcement(tag) {
  return ENFORCEMENT[tag] || ENFORCEMENT.uncertain;
}

// Regression kind: the JSON ships the enum's kebab tag (`identity-change`,
// `divergence-registry-signed`, …); the maud `data-regression` attribute uses the SHORTER
// `.token()` (`identity`, `divergence-registry`, …). This table maps the WIRE TAG to the loud
// headline word, the "after" prose, and the `.token()` CSS value, so both the copy and the DOM
// attribute stay at maud parity.
const DASH = "\u{2014}";
export const REGRESSION = {
  unsigned: {
    token: "unsigned",
    word: `signing regression ${DASH} now unsigned`,
    after: "no signature present",
  },
  invalid: {
    token: "invalid",
    word: `signing regression ${DASH} now invalid signature`,
    after: "signature present but does not verify",
  },
  "identity-change": {
    token: "identity",
    word: `signing regression ${DASH} new signer`,
    after: "signed by a new identity",
  },
  "divergence-registry-signed": {
    token: "divergence-registry",
    word: `signing regression ${DASH} registry\u{2194}log divergence`,
    after: "registry serves a signature absent from the public transparency log",
  },
  "divergence-log-signed": {
    token: "divergence-log",
    word: `signing regression ${DASH} registry\u{2194}log divergence`,
    after: "the transparency log records a signature the registry now serves unsigned",
  },
  "downgrade-key-based": {
    token: "downgrade-key-based",
    word: `signing regression ${DASH} signing downgrade`,
    after: `now key-based ${DASH} no keyless identity (was keyless-verified)`,
  },
  "downgrade-unverifiable": {
    token: "downgrade-unverifiable",
    word: `signing regression ${DASH} signing downgrade`,
    after: "now unverifiable against our trust root (was keyless-verified)",
  },
};

/** Look up a regression kind by its WIRE tag, defaulting to `unsigned` (a conservative regression,
 *  never a false calm — a regression row always exists when this is called). */
export function regression(tag) {
  return REGRESSION[tag] || REGRESSION.unsigned;
}

/** Baseline strength wire tag → { token, word, detail }. Mirrors `RepoStrength`. */
export const STRENGTH = {
  "log-corroborated": {
    token: "corroborated",
    word: "log-corroborated",
    detail: `log-corroborated ${DASH} the public transparency log vouches for this repo's signing history (a stronger baseline than local trust-on-first-sight).`,
  },
  "local-only": {
    token: "local",
    word: "new baseline (local only)",
    detail: `new baseline (local only) ${DASH} trust-on-first-sight; the public transparency log has not yet corroborated this repo's signing history.`,
  },
  unknown: {
    token: "unknown",
    word: "",
    detail: "no signing baseline learned for this repo yet.",
  },
};

/** Look up a baseline strength, defaulting to `unknown` (no badge, honest "none learned"). */
export function strength(tag) {
  return STRENGTH[tag] || STRENGTH.unknown;
}
