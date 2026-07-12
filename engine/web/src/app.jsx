// The dashboard v4 app shell (ADR-0025): the mounted Preact tree below the SERVER-RENDERED status
// strip. The strip stays server-rendered for first-paint honesty (a JS failure must never leave a
// stale green) — this shell renders only the connection banner, the tab nav (progressive-
// enhancement: real `<a href>` links intercepted for a client-side view swap), and the active view.
// All five views (Findings / Alerts / Action / Readiness / Admission) are Preact-rendered (JEF-398):
// the engine is Preact-only, so every tab-swap is a local client view swap — no maud fallback.
//
// The connection banner is the only `aria-live="polite"` region (the STRIP HEADLINE — not the
// table): first-load says "connecting to the engine…", stale says the load-bearing two-sentence
// "Not updating … This is a connection problem, not an all-clear." Live says nothing (no chrome).

import { useEffect, useState } from "preact/hooks";
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
 * @param {import("./store.js").Store} props.store the client store.
 * @param {() => (Node | null)} [props.liveRegion] resolves the DOM node the selection guard checks
 *   (defaults to this app's root once mounted).
 */
export function App({ store, liveRegion }) {
  const [, force] = useState(0);
  useEffect(() => store.subscribe(() => force((n) => n + 1)), [store]);

  const activeTab = store.getState().activeTab;
  // Poll the ACTIVE tab; a client tab-swap RESTARTS the poll so the new tab refetches IMMEDIATELY
  // (fixing the up-to-5s blank after a swap — JEF-408) rather than waiting for the next interval.
  // The selection guard checks this app's own subtree.
  useEffect(() => {
    const stop = startPolling({
      store,
      tab: () => store.getState().activeTab,
      liveRegion: liveRegion || (() => document.getElementById("dash-app")),
    });
    return stop;
  }, [store, liveRegion, activeTab]);

  const state = store.getState();
  return (
    <div id="dash-app" class="dash-app" data-tab={state.activeTab}>
      {/* The persistent status strip — the honesty spine on every view. Before the first snapshot
          lands there is no strip data, so nothing renders here (blank is honest — absent is never a
          green all-clear; the ConnectionBanner already says "connecting…"). */}
      <StatusStrip strip={state.data?.strip} />
      <ConnectionBanner status={state.status} lastGoodAt={state.lastGoodAt} />
      <TabNav activeTab={state.activeTab} store={store} />
      <ActiveView store={store} state={state} />
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
function TabNav({ activeTab, store }) {
  const onClick = (e, tab) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
      return; // let the browser handle a modified click (new tab, etc.)
    }
    // Every tab is Preact-rendered (JEF-398), so every swap is a local client-side view swap — no
    // full navigation, no maud fallback.
    e.preventDefault();
    history.pushState({ tab: tab.id }, "", tab.href);
    store.setActiveTab(tab.id);
  };
  useEffect(() => {
    const onPop = () => store.setActiveTab(tabFromLocation());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [store]);

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
 * stale snapshot. Each view is otherwise a pure `view + store` render.
 */
function ActiveView({ store, state }) {
  if (!state.data) {
    // First paint / just after a tab-swap: keep the body quiet (the banner carries any connection
    // state). A bare view container keeps the layout stable without asserting an empty result.
    return <main class={`view view-${state.activeTab}`} />;
  }
  switch (state.activeTab) {
    case "alerts":
      return <AlertsView view={state.data} />;
    case "action":
      return <ActionView view={state.data} store={store} />;
    case "readiness":
      return <ReadinessView view={state.data} store={store} />;
    case "admission":
      return <AdmissionView view={state.data} store={store} />;
    default:
      return <FindingsView view={state.data} store={store} />;
  }
}
