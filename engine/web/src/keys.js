// Per-view reconcile keys for the secondary dashboard views (ADR-0025 / JEF-400). The Findings
// table keys on a server-supplied stable `finding.id`; the four secondary views vary only in how
// their row key is derived, and this module owns that single per-view variation so the components
// stay declarative:
//
//  - Action / Readiness rows DO carry a stable anchor (the entry key / `ReadinessRowProps.id`).
//  - Admission decision rows have NO id -> keyed on their `(subject, image, decision)` tuple, so the
//    dedup `count` updates smoothly IN PLACE rather than the row tearing and re-inserting.
//  - Alerts are a CURRENT-WINDOW projection, NOT a log, with no stable id BY DESIGN -> keyed on a
//    content hash of `(kind, signal, workload, on-chain)`. An identical alarm that persists across
//    passes hashes the same -> reconciles to the same node (no flicker); a genuinely new alarm
//    hashes differently -> a new node. We deliberately DO NOT fabricate a persistent id (that would
//    imply a durability the projection does not have).
//
// `contentHash` is a small, stable, non-cryptographic string hash (FNV-1a) -- it is only a
// reconcile discriminator (collisions merely merge two rows visually for one pass; they are never
// a security boundary), so a fast 32-bit hash is exactly right.

/**
 * A stable 32-bit FNV-1a hash of a string, as an unsigned hex string. Deterministic across passes
 * and processes (no randomness), so the SAME content always produces the SAME key.
 * @param {string} str
 * @returns {string}
 */
export function contentHash(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    // FNV prime 16777619, kept in 32-bit range via Math.imul.
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16);
}

// A field separator for the hashed tuple. A collision here is harmless (two rows merely merge
// visually for one pass -- never a security boundary), so an exact injective join is not required;
// a single space is enough to keep ordinary field values from running together.
const SEP = " ";

/**
 * The content key for one Alerts row (JEF-400): a hash of `(kind, signal, workload, on-chain)`.
 * An identical alarm persisting across passes yields the same key (reconciles in place, no
 * flicker); a genuinely different alarm yields a new key (a new node). NOT a fabricated id.
 * @param {{ kind?: string, signal?: string, workload?: string, "on-chain"?: string|null }} a
 * @returns {string}
 */
export function alertKey(a) {
  const parts = [a.kind, a.signal, a.workload, a["on-chain"] ?? ""];
  return `alert-${contentHash(parts.join(SEP))}`;
}

/**
 * The tuple key for one Admission decision row (JEF-400): the `(subject, image, decision)` tuple
 * the server itself dedups on. Two passes of the same tuple reconcile to the same node, so the
 * `count` updates in place. Hashed so an untrusted subject/image can never break the key syntax.
 * @param {{ subject?: string, image?: string, decision?: string }} r
 * @returns {string}
 */
export function decisionKey(r) {
  const parts = [r.subject ?? "", r.image ?? "", r.decision ?? ""];
  return `decision-${contentHash(parts.join(SEP))}`;
}
