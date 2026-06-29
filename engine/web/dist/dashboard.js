// Protector dashboard — zero-dependency client script (served same-origin).
//
// Two jobs, both observational (the dashboard never acts):
//   1. Persist which finding rows — and which "show model prompt" disclosures — are open across
//      live-poll swaps, keyed by finding id, so a refresh never collapses what the operator opened.
//   2. Poll /fragment for the active tab and swap the live region in place, preserving scroll,
//      open state, and the current tab/filter query.
//
// No third-party code, no egress: it only talks to its own origin's /fragment.

(() => {
  "use strict";

  const LIVE_ID = "live";
  const POLL_MS = 5000;
  const EXPANDED_KEY = "protector.expanded";
  const PROMPT_KEY = "protector.prompts";

  // A sessionStorage-backed Set: survives a /fragment swap and a soft reload, not a new session.
  const loadSet = (key) => {
    try {
      return new Set(JSON.parse(sessionStorage.getItem(key) ?? "[]"));
    } catch {
      return new Set();
    }
  };
  const saveSet = (key, set) => {
    try {
      sessionStorage.setItem(key, JSON.stringify([...set]));
    } catch {
      /* sessionStorage unavailable — degrade to in-memory only */
    }
  };

  const expanded = loadSet(EXPANDED_KEY);
  const promptsOpen = loadSet(PROMPT_KEY);

  // Reflect a finding row's open state: the `open` class (CSS reveals the paired .row-detail),
  // the +/- expander glyph, and aria-expanded.
  const applyRowState = (row, isOpen) => {
    row.classList.toggle("open", isOpen);
    const btn = row.querySelector(".expander");
    if (!btn) return;
    btn.setAttribute("aria-expanded", String(isOpen));
    const glyph = btn.querySelector(".expander-glyph");
    if (glyph) glyph.textContent = isOpen ? "−" : "+"; // − when open, + when closed
  };

  const toggleRow = (row) => {
    const id = row.dataset.finding;
    if (!id) return;
    const isOpen = !expanded.has(id);
    isOpen ? expanded.add(id) : expanded.delete(id);
    saveSet(EXPANDED_KEY, expanded);
    applyRowState(row, isOpen);
  };

  // Summary rows are click/keyboard toggles for their detail row; restore persisted state on bind.
  const bindRows = (root) => {
    for (const row of root.querySelectorAll("tr.row[data-finding]")) {
      applyRowState(row, expanded.has(row.dataset.finding));
      // The whole row is the toggle; the expander button's click bubbles here too (one handler).
      row.addEventListener("click", () => toggleRow(row));
    }
  };

  // The "show model prompt" disclosures persist their open state, so a poll never collapses one the
  // operator is mid-read.
  const bindPrompts = (root) => {
    for (const el of root.querySelectorAll("details.model-prompt[data-prompt]")) {
      const pid = el.dataset.prompt;
      el.open = promptsOpen.has(pid); // set before listening so it doesn't self-fire a save
      const summary = el.querySelector("summary");
      summary?.setAttribute("aria-expanded", String(el.open));
      el.addEventListener("toggle", () => {
        el.open ? promptsOpen.add(pid) : promptsOpen.delete(pid);
        saveSet(PROMPT_KEY, promptsOpen);
        summary?.setAttribute("aria-expanded", String(el.open));
      });
    }
  };

  const bindLive = (root) => {
    bindRows(root);
    bindPrompts(root);
  };

  // The active tab's fragment URL, preserving the current query (tab/filter) — back-button correct.
  const fragmentUrl = () => `/fragment${window.location.search || ""}`;

  // Poll /fragment and swap the live region in place, preserving scroll + open state.
  const poll = async () => {
    try {
      const res = await fetch(fragmentUrl(), { headers: { "X-Requested-With": "fragment" } });
      if (!res.ok) throw new Error(`fragment ${res.status}`);
      const html = await res.text();
      const live = document.getElementById(LIVE_ID);
      if (!live) return;
      const { scrollY } = window;
      live.innerHTML = html;
      bindLive(live);
      window.scrollTo(0, scrollY); // the swap reflows the list; keep the operator's position
    } catch {
      // A failed poll leaves the last good render; the honest banner follows once a fragment lands.
    }
  };

  const start = () => {
    const live = document.getElementById(LIVE_ID);
    if (live) bindLive(live);
    window.setInterval(poll, POLL_MS);
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
