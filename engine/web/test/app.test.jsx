// App-shell tab-navigation tests (ADR-0025 / JEF-398 / JEF-411): the engine is Preact-only, so EVERY
// tab-swap — including to a secondary view — is a local client view swap (history.pushState + local
// state update), never a full server navigation. `App` owns the active tab as a plain useState now
// (no store — JEF-411); these tests drive it and assert via the DOM.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, fireEvent, cleanup } from "@testing-library/preact";

// Stub the poll so a nav test never fires a real fetch/interval — we assert navigation, not polling.
vi.mock("../src/poll.js", () => ({ startPolling: () => () => {} }));
const { App } = await import("../src/app.jsx");

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

/** Render the app shell on a given active tab. */
function mount(initialTab = "findings") {
  const { container } = render(<App initialTab={initialTab} liveRegion={() => null} />);
  return { container };
}

describe("Preact-only tab navigation", () => {
  it("intercepts a swap to EVERY tab — no full navigation, active tab repoints locally", () => {
    const { container } = mount("findings");
    const pushState = vi.spyOn(history, "pushState");

    for (const id of ["alerts", "action", "readiness", "admission", "findings"]) {
      const link = container.querySelector(`a.tab[href="${hrefFor(id)}"]`);
      expect(link, `${id} tab link is present`).toBeTruthy();
      const clicked = fireEvent.click(link);
      // The default (real navigation) is prevented for every tab now.
      expect(clicked, `${id} swap is intercepted (default prevented)`).toBe(false);
      // The active tab is now this one — its nav link carries aria-current="page".
      expect(container.querySelector(`a.tab[href="${hrefFor(id)}"]`).getAttribute("aria-current")).toBe(
        "page",
      );
    }
    expect(pushState).toHaveBeenCalledTimes(5);
    pushState.mockRestore();
  });

  it("does NOT intercept a modified click (open-in-new-tab still works)", () => {
    const { container } = mount("findings");
    const pushState = vi.spyOn(history, "pushState");
    const link = container.querySelector('a.tab[href="/?tab=alerts"]');
    // A ⌘/ctrl click must fall through to the browser: the handler bails, so no client swap happens
    // (active tab unchanged, pushState never called). jsdom then logs an un-implemented navigation —
    // the proof the default was NOT prevented.
    fireEvent.click(link, { metaKey: true });
    expect(pushState).not.toHaveBeenCalled();
    // Findings is still the active tab.
    expect(container.querySelector('a.tab[href="/"]').getAttribute("aria-current")).toBe("page");
    pushState.mockRestore();
  });
});

/** The nav href vocabulary the app renders (mirrors the server `?tab=` routes). */
function hrefFor(id) {
  return id === "findings" ? "/" : `/?tab=${id}`;
}
