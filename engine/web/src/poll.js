// The dashboard v4 poll engine (ADR-0025 / JEF-397). It fetches the active tab's same-origin JSON
// snapshot every 5s and feeds it to the store. Two rules ported verbatim from the v3 client:
//
//  1. Same-origin only. The URL is always relative (`/api/{tab}.json`), so the strict CSP
//     `connect-src 'self'` is the hard floor — the client can reach nothing but its own origin.
//  2. Defer-apply-while-text-selection. Reconciling mid-selection can rip away the text the
//     operator is dragging across (a model verdict they're copying). When a non-collapsed
//     selection is anchored inside the live app, we SKIP applying this tick; the next tick lands
//     once the selection clears. (The keyed reconcile no longer nukes scroll, so the v3
//     scroll-restore hack is gone — only the selection guard survives.)
//
// A failed poll does NOT throw or blank the view: it marks the store STALE, so the last-good
// snapshot stays on screen under an honest "not updating — this is a connection problem, not an
// all-clear" banner (never a stale green).

/** The poll cadence — 5s, matching the v3 client. */
export const POLL_MS = 5000;

/**
 * The same-origin snapshot URL for a tab. Relative by construction, so it is always same-origin
 * (the CSP forbids anything else). The tab vocabulary is fixed and server-owned.
 * @param {string} tab
 */
export function snapshotUrl(tab) {
  return `/api/${tab}.json`;
}

/**
 * Whether the operator has an ACTIVE, non-collapsed text selection anchored inside `container`.
 * A collapsed caret or a selection elsewhere on the page does not stall the refresh.
 * @param {Node} container
 * @returns {boolean}
 */
export function hasLiveSelection(container) {
  const sel = typeof window !== "undefined" ? window.getSelection?.() : null;
  if (!sel || sel.rangeCount === 0 || sel.isCollapsed) return false;
  const range = sel.getRangeAt(0);
  if (range.collapsed) return false;
  return container.contains(range.commonAncestorContainer);
}

/**
 * Start polling. Fetches immediately, then every {@link POLL_MS}. Returns a stop fn that clears the
 * interval and cancels in-flight application (the last fetch's result is ignored after stop).
 *
 * @param {object} opts
 * @param {import("./store.js").Store} opts.store the store to feed snapshots / staleness into.
 * @param {() => string} opts.tab reads the CURRENT active tab (so a client tab-swap repoints the
 *   poll without a restart).
 * @param {() => (Node | null)} opts.liveRegion reads the DOM node the selection guard checks.
 * @param {typeof fetch} [opts.fetchImpl] injectable fetch (tests pass a stub; default is global).
 * @param {(ms: number, fn: () => void) => number} [opts.setIntervalImpl]
 * @param {(id: number) => void} [opts.clearIntervalImpl]
 * @returns {() => void} stop
 */
export function startPolling(opts) {
  const {
    store,
    tab,
    liveRegion,
    fetchImpl = typeof fetch !== "undefined" ? fetch : undefined,
    setIntervalImpl = setInterval,
    clearIntervalImpl = clearInterval,
  } = opts;
  let live = true;

  const tick = async () => {
    try {
      const res = await fetchImpl(snapshotUrl(tab()), {
        headers: { accept: "application/json" },
      });
      if (!live) return;
      if (!res.ok) {
        store.markStale();
        return;
      }
      const snapshot = await res.json();
      if (!live) return;
      // Never apply a snapshot mid-selection — it would rip away the text being copied. The next
      // tick applies once the selection clears; the store stays LIVE (not stale) meanwhile.
      const region = liveRegion();
      if (region && hasLiveSelection(region)) return;
      store.applySnapshot(snapshot);
    } catch {
      // Transport failure (offline, DNS, 5xx thrown): keep the last-good render, say we're stale.
      if (live) store.markStale();
    }
  };

  tick();
  const handle = setIntervalImpl(POLL_MS, tick);
  return () => {
    live = false;
    clearIntervalImpl(handle);
  };
}
