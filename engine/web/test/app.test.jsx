// App-shell tab-navigation tests (ADR-0025 / JEF-398): the engine is Preact-only, so EVERY tab-swap
// — including to a secondary view — is a local client view swap (history.pushState + store update),
// never a full server navigation. This would FAIL under the old per-tab-flag special-case, which let
// a swap to a "still-maud" tab fall through to a real navigation.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, fireEvent, cleanup } from "@testing-library/preact";
import { Store } from "../src/store.js";
import { findingsView } from "./fixtures.js";

// Stub the poll so a nav test never fires a real fetch/interval — we assert navigation, not polling.
vi.mock("../src/poll.js", () => ({ startPolling: () => () => {} }));
const { App } = await import("../src/app.jsx");

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

/** Render the app shell with a seeded store on a given active tab. */
function mount(activeTab = "findings") {
  const store = new Store({ activeTab });
  store.applySnapshot(findingsView([]));
  const { container } = render(<App store={store} liveRegion={() => null} />);
  return { store, container };
}

describe("Preact-only tab navigation", () => {
  it("intercepts a swap to EVERY tab — no full navigation, store repoints locally", () => {
    const { store, container } = mount("findings");
    const pushState = vi.spyOn(history, "pushState");

    for (const id of ["alerts", "action", "readiness", "admission", "findings"]) {
      const link = container.querySelector(`a.tab[href="${hrefFor(id)}"]`);
      expect(link, `${id} tab link is present`).toBeTruthy();
      const clicked = fireEvent.click(link);
      // The default (real navigation) is prevented for every tab now.
      expect(clicked, `${id} swap is intercepted (default prevented)`).toBe(false);
      expect(store.getState().activeTab).toBe(id);
    }
    expect(pushState).toHaveBeenCalledTimes(5);
    pushState.mockRestore();
  });

  it("does NOT intercept a modified click (open-in-new-tab still works)", () => {
    const { store, container } = mount("findings");
    const pushState = vi.spyOn(history, "pushState");
    const link = container.querySelector('a.tab[href="/?tab=alerts"]');
    // A ⌘/ctrl click must fall through to the browser: the handler bails, so no client swap happens
    // (store unchanged, pushState never called). jsdom then logs an un-implemented navigation — the
    // proof the default was NOT prevented.
    fireEvent.click(link, { metaKey: true });
    expect(pushState).not.toHaveBeenCalled();
    expect(store.getState().activeTab).toBe("findings");
    pushState.mockRestore();
  });
});

/** The nav href vocabulary the app renders (mirrors the server `?tab=` routes). */
function hrefFor(id) {
  return id === "findings" ? "/" : `/?tab=${id}`;
}
