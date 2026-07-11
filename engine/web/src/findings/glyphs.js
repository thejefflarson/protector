// Presentation lookup tables for the Findings view (ADR-0025 / JEF-397). The JSON ships each
// posture / live-tag / delta as a STABLE lowercase string TAG (`"breach"`, `"live"`, `"new"`);
// these tables map that tag to its glyph + word, exactly as the maud `Posture::glyph/word` etc. do
// in Rust. Every posture keeps GLYPH + WORD + colour token so meaning never rides on colour alone
// (the STYLEGUIDE a11y gate).
//
// This is PRESENTATION ONLY, not honesty derivation: the client never decides "is this cleared?" —
// that decision is the server's `is-cleared` token. Mapping a known tag to its fixed glyph is the
// same static table maud compiles in; it introduces no new judgement.

/** Posture tag → { glyph, word }. Mirrors `props::Posture::glyph/word`. */
export const POSTURE = {
  breach: { glyph: "\u{25CF}", word: "BREACH" }, // ● filled
  cleared: { glyph: "\u{25CB}", word: "no exploit evidence" }, // ○ open
  uncertain: { glyph: "\u{25D0}", word: "uncertain" }, // ◐ half
  awaiting: { glyph: "\u{25CC}", word: "awaiting judgement" }, // ◌ dotted
};

/**
 * Look up a posture's presentation, defaulting safely to `awaiting` (never green) for an unknown
 * tag — an unrecognised posture must never render as the cleared/green reading.
 * @param {string} tag
 */
export function posture(tag) {
  return POSTURE[tag] || POSTURE.awaiting;
}

/** Delta `kind` tag → { token, glyph }. Mirrors `props::DeltaProps::token/glyph`. The steady
 * `unchanged` case has no token/glyph (it shows the muted age instead). */
export const DELTA = {
  new: { token: "new", glyph: "\u{2605}" }, // ★
  escalated: { token: "up", glyph: "\u{25B2}" }, // ▲
  "de-escalated": { token: "down", glyph: "\u{25BC}" }, // ▼
  restored: { token: "restored", glyph: "\u{21BA}" }, // ↺
};
