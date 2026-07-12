// The dashboard v4 app shell (ADR-0025 / ADR-0027 / ADR-0028): the mounted Preact tree. `App` owns
// the ONLY shared client state — the active tab, the last-good snapshot, the persistent status
// strip, the connection status, and the freshness clock — each a plain `useState` (JEF-411: no
// store, no reducer, no Context). Everything else (which rows are expanded, which disclosures are
// open) is LOCAL component state, ephemeral by design.
//
// The strip is its OWN useState, decoupled from the per-tab `data` (JEF-410): it persists global
// posture across a tab swap so the header never tears down. Honesty stays server-derived (ADR-0027):
// the client only displays the strip's tokens; it never recomputes "is this green?".
//
// The connection banner is the only `aria-live="polite"` region (the STRIP HEADLINE — not the
// table): first-load says "connecting to the engine…", stale says the load-bearing two-sentence
// "Not updating … This is a connection problem, not an all-clear." Live says nothing (no chrome).

import { useCallback, useEffect, useState } from "preact/hooks";
import { startPolling } from "./poll.js";
import { StatusStrip } from "./strip.jsx";
import { FindingsView } from "./findings/table.jsx";
import { AlertsView } from "./alerts/view.jsx";
import { ActionView } from "./action/view.jsx";
import { ReadinessView } from "./readiness/view.jsx";
import { AdmissionView } from "./admission/view.jsx";

const TABS = [
  { id: "findings", label: "Findings", href: "/" },
  { id: "alerts", label: "Alerts", href: "/?tab=alerts" },
  { id: "action", label: "Action", href: "/?tab=action" },
  { id: "readiness", label: "Readiness", href: "/?tab=readiness" },
  { id: "admission", label: "Admission", href: "/?tab=admission" },
];

/**
 * @param {object} props
 * @param {string} [props.initialTab] the server-known active tab (from `data-tab`), so the first
 *   paint's tab matches the document without waiting for a fetch.
 * @param {() => (Node | null)} [props.liveRegion] resolves the DOM node the selection guard checks
 *   (defaults to this app's root once mounted).
 */
export function App({ initialTab = "findings", liveRegion }) {
  // The five shared fields, each a plain useState (JEF-411).
  const [activeTab, setActiveTab] = useState(initialTab);
  const [data, setData] = useState(null);
  // The persistent status strip (global cluster posture), its OWN useState decoupled from the
  // per-tab `data` so a tab swap (which nulls `data`) never tears the header down (JEF-410). Null
  // before the first snapshot (blank is honest — absent is never a green all-clear).
  const [strip, setStrip] = useState(null);
  const [status, setStatus] = useState("first-load");
  const [lastGoodAt, setLastGoodAt] = useState(null);

  // A successful snapshot: go LIVE and reset the freshness clock. Persist the global posture from
  // this snapshot's `strip` (present in every tab's payload); keep the last strip if a snapshot
  // omits it, so the header never blanks (JEF-410).
  const applySnapshot = useCallback((snap) => {
    setData(snap);
    setStrip((prev) => (snap && snap.strip ? snap.strip : prev));
    setStatus("live");
    setLastGoodAt(Date.now());
  }, []);

  // Mark the connection stale: keep the last-good snapshot on screen (never blank, never a false
  // all-clear). No-op before the first snapshot — "first-load" (connecting…) is honest then.
  const markStale = useCallback(() => {
    setStatus((s) => (s === "first-load" ? s : "stale"));
  }, []);

  // Poll the ACTIVE tab; a client tab-swap RESTARTS the poll (keyed on [activeTab]) so the new tab
  // refetches IMMEDIATELY (fixing the up-to-5s blank after a swap — JEF-408) rather than waiting for
  // the next interval. `() => activeTab` is correct: the effect restarts per swap, re-closing over
  // the fresh value. The selection guard checks this app's own subtree.
  useEffect(
    () =>
      startPolling({
        tab: () => activeTab,
        onSnapshot: applySnapshot,
        onStale: markStale,
        liveRegion: liveRegion || (() => document.getElementById("dash-app")),
      }),
    [activeTab, applySnapshot, markStale, liveRegion],
  );

  // Swap the active tab (client-side view swap). Drop the previous tab's snapshot — each tab has its
  // own JSON shape, so rendering the old snapshot under the new view would be wrong — but do NOT
  // touch `strip`: it is global posture that persists across the swap (JEF-410).
  const swapTab = useCallback((tab) => {
    setActiveTab(tab);
    setData(null);
  }, []);

  return (
    <div id="dash-app" class="dash-app" data-tab={activeTab}>
      <StatusStrip strip={strip} />
      <ConnectionBanner status={status} lastGoodAt={lastGoodAt} />
      <TabNav activeTab={activeTab} onSwap={swapTab} />
      <ActiveView activeTab={activeTab} data={data} />
    </div>
  );
}

/**
 * The honest connection banner — the ONLY `aria-live="polite"` region. Never green: it says nothing
 * when live (no false reassurance), "connecting…" on first load, and the load-bearing stale copy
 * (whose 2nd sentence forbids reading silence as an all-clear) when the poll is failing.
 */
function ConnectionBanner({ status, lastGoodAt }) {
  return (
    <div class="dash-conn" role="status" aria-live="polite">
      {status === "first-load" ? (
        <p class="dash-conn-msg dash-conn-connecting muted">connecting to the engine…</p>
      ) : status === "stale" ? (
        <p class="dash-conn-msg dash-conn-stale">
          Not updating — showing what we last saw {agoSeconds(lastGoodAt)}s ago. This is a
          connection problem, not an all-clear.
        </p>
      ) : null}
    </div>
  );
}

/** Whole seconds since `at` (ms epoch), floored at 0 — for the stale banner's "NNs ago". */
function agoSeconds(at) {
  if (!at) return 0;
  return Math.max(0, Math.floor((Date.now() - at) / 1000));
}

/**
 * The tab nav — real `<a href="?tab=…">` links (progressive enhancement) intercepted for a
 * client-side view swap via `history.pushState`. A plain-navigation modifier (ctrl/⌘/middle-click)
 * is NOT intercepted so open-in-new-tab still works.
 */
function TabNav({ activeTab, onSwap }) {
  const onClick = (e, tab) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
      return; // let the browser handle a modified click (new tab, etc.)
    }
    // Every tab is Preact-rendered (JEF-398), so every swap is a local client-side view swap — no
    // full navigation, no maud fallback.
    e.preventDefault();
    history.pushState({ tab: tab.id }, "", tab.href);
    onSwap(tab.id);
  };
  useEffect(() => {
    const onPop = () => onSwap(tabFromLocation());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [onSwap]);

  return (
    <nav class="tabs" aria-label="dashboard sections">
      {TABS.map((tab) => {
        const active = tab.id === activeTab;
        return (
          <a
            key={tab.id}
            class={active ? "tab tab-active" : "tab"}
            href={tab.href}
            aria-current={active ? "page" : undefined}
            onClick={(e) => onClick(e, tab)}
          >
            {tab.label}
          </a>
        );
      })}
    </nav>
  );
}

/** Read the active tab from `?tab=` (the same vocabulary the server's `TabQuery` resolves). */
export function tabFromLocation() {
  const t = new URLSearchParams(window.location.search).get("tab");
  if (t === "alerts" || t === "action" || t === "readiness" || t === "admission") return t;
  return "findings";
}

/**
 * Render the active view (all five tabs are ported — JEF-400). Before the active tab's first
 * snapshot lands (initial mount, or right after a client tab-swap that cleared the previous tab's
 * data) the body is a quiet placeholder — never a flashed empty table, and never the wrong tab's
 * stale snapshot. Each view is a pure `view`-only render (JEF-411 — no store prop).
 */
function ActiveView({ activeTab, data }) {
  if (!data) {
    // First paint / just after a tab-swap: keep the body quiet (the banner carries any connection
    // state). A bare view container keeps the layout stable without asserting an empty result.
    return <main class={`view view-${activeTab}`} />;
  }
  switch (activeTab) {
    case "alerts":
      return <AlertsView view={data} />;
    case "action":
      return <ActionView view={data} />;
    case "readiness":
      return <ReadinessView view={data} />;
    case "admission":
      return <AdmissionView view={data} />;
    default:
      return <FindingsView view={data} />;
  }
}
