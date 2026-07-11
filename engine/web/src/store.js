// The dashboard v4 client store (ADR-0025 / JEF-397): one small, framework-agnostic state
// container keyed by STABLE domain id. It holds the client's whole view state — the active tab
// (mirrors `?tab=`), which finding rows and which "show model prompt" disclosures are open, the
// last-good snapshot, and the connection status/freshness — and notifies subscribers on change.
//
// The client performs ZERO honesty derivation (ADR-0025): the store carries the server's snapshot
// verbatim and never recomputes "is this green?". Honesty tokens (`all-clear`, per-row `posture`)
// come decided in the JSON and are only DISPLAYED.
//
// Expansion/disclosure sets are seeded from — and written back to — the SAME sessionStorage keys
// the v3 client used (`protector.expanded` / `protector.prompts`), so an operator's open rows
// survive a soft reload and the migration from maud is invisible to them.

/** @typedef {"first-load" | "live" | "stale"} Status */

/** The sessionStorage key for the set of expanded finding-row ids (kept from v3). */
export const EXPANDED_KEY = "protector.expanded";
/** The sessionStorage key for the set of open "show model prompt" disclosure ids (kept from v3). */
export const PROMPT_KEY = "protector.prompts";

/**
 * A sessionStorage-backed Set of ids: survives a soft reload (not a new session). Tolerates a
 * disabled/failing sessionStorage by degrading to an in-memory Set — the store never throws.
 * @param {string} key
 * @returns {Set<string>}
 */
export function loadSet(key) {
  try {
    const raw = sessionStorage.getItem(key);
    return new Set(raw ? JSON.parse(raw) : []);
  } catch {
    return new Set();
  }
}

/**
 * @param {string} key
 * @param {Set<string>} set
 */
function saveSet(key, set) {
  try {
    sessionStorage.setItem(key, JSON.stringify([...set]));
  } catch {
    /* sessionStorage unavailable — the in-memory Set is still authoritative this session. */
  }
}

/**
 * The client store. A minimal observable: `getState()` reads a plain snapshot, `subscribe()`
 * registers a listener, and the mutators below are the ONLY way to change state (each notifies).
 * There is no reducer ceremony — the surface is small on purpose (ADR-0025 file-size discipline).
 */
export class Store {
  /**
   * @param {{ activeTab?: string }} [seed] the server-known active tab (from `data-tab`), so the
   *   first paint's tab matches the document without waiting for a fetch.
   */
  constructor(seed = {}) {
    /** @type {Set<() => void>} */
    this.listeners = new Set();
    /** @type {{ activeTab: string, expandedRows: Set<string>, openPrompts: Set<string>,
     *           data: unknown, status: Status, lastGoodAt: number | null }} */
    this.state = {
      activeTab: seed.activeTab || "findings",
      expandedRows: loadSet(EXPANDED_KEY),
      openPrompts: loadSet(PROMPT_KEY),
      data: null,
      status: "first-load",
      lastGoodAt: null,
    };
  }

  /** A read-only snapshot of the current state. */
  getState() {
    return this.state;
  }

  /**
   * Register a listener; returns an unsubscribe fn.
   * @param {() => void} fn
   */
  subscribe(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  /** @private */
  emit() {
    for (const fn of this.listeners) fn();
  }

  /**
   * Record a successful snapshot: the view goes LIVE and the freshness clock resets. This never
   * touches expansion/disclosure state — a poll must not collapse what the operator opened.
   * @param {unknown} data
   */
  applySnapshot(data) {
    this.state = { ...this.state, data, status: "live", lastGoodAt: Date.now() };
    this.emit();
  }

  /**
   * Mark the connection stale: keep showing the last-good snapshot (never blank, never a false
   * all-clear) but tell the operator we are not updating. No-op before the first snapshot lands —
   * "first-load" (connecting…) is the honest state then, not "stale".
   */
  markStale() {
    if (this.state.status === "first-load") return;
    if (this.state.status === "stale") return;
    this.state = { ...this.state, status: "stale" };
    this.emit();
  }

  /** Whether a finding row is currently expanded. @param {string} id */
  isExpanded(id) {
    return this.state.expandedRows.has(id);
  }

  /**
   * Toggle a finding row's expansion, persisting to sessionStorage (v3-compatible key).
   * @param {string} id
   */
  toggleRow(id) {
    const next = new Set(this.state.expandedRows);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    saveSet(EXPANDED_KEY, next);
    this.state = { ...this.state, expandedRows: next };
    this.emit();
  }

  /** Whether a "show model prompt" disclosure is open. @param {string} id */
  isPromptOpen(id) {
    return this.state.openPrompts.has(id);
  }

  /**
   * Set a disclosure's open state, persisting to sessionStorage (v3-compatible key). Called from
   * the native `<details>` toggle event so the store mirrors the DOM, not the other way around.
   * @param {string} id
   * @param {boolean} open
   */
  setPromptOpen(id, open) {
    const has = this.state.openPrompts.has(id);
    if (open === has) return;
    const next = new Set(this.state.openPrompts);
    if (open) next.add(id);
    else next.delete(id);
    saveSet(PROMPT_KEY, next);
    this.state = { ...this.state, openPrompts: next };
    this.emit();
  }

  /**
   * Purge ids that no longer exist from the persisted expansion/disclosure sets (called after a
   * gone-finding's tombstone clears) so stale ids don't accumulate in sessionStorage forever.
   * @param {Iterable<string>} ids
   */
  purge(ids) {
    let touched = false;
    const rows = new Set(this.state.expandedRows);
    const prompts = new Set(this.state.openPrompts);
    for (const id of ids) {
      if (rows.delete(id)) touched = true;
      if (prompts.delete(id)) touched = true;
    }
    if (!touched) return;
    saveSet(EXPANDED_KEY, rows);
    saveSet(PROMPT_KEY, prompts);
    this.state = { ...this.state, expandedRows: rows, openPrompts: prompts };
    this.emit();
  }

  /**
   * Switch the active tab (client-side view swap). The caller owns the `history.pushState`; this
   * only moves the state so the render follows.
   * @param {string} tab
   */
  setActiveTab(tab) {
    if (this.state.activeTab === tab) return;
    this.state = { ...this.state, activeTab: tab };
    this.emit();
  }
}
