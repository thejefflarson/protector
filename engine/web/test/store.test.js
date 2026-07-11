// Unit tests for the client store (ADR-0025 / JEF-397): sessionStorage seeding on the v3-compatible
// keys, snapshot-vs-staleness status transitions (never "stale" before the first snapshot), and
// the expansion/disclosure mutators + purge. The store is where a bug would silently drop operator
// state, so its contract is pinned directly.

import { describe, it, expect, beforeEach } from "vitest";
import { Store, EXPANDED_KEY, PROMPT_KEY } from "../src/store.js";

beforeEach(() => sessionStorage.clear());

describe("Store seeding", () => {
  it("seeds expanded rows and open prompts from the v3 sessionStorage keys", () => {
    sessionStorage.setItem(EXPANDED_KEY, JSON.stringify(["row-1", "row-2"]));
    sessionStorage.setItem(PROMPT_KEY, JSON.stringify(["row-1"]));
    const store = new Store();
    expect(store.isExpanded("row-1")).toBe(true);
    expect(store.isExpanded("row-2")).toBe(true);
    expect(store.isPromptOpen("row-1")).toBe(true);
    expect(store.isPromptOpen("row-2")).toBe(false);
  });

  it("tolerates corrupt sessionStorage by starting empty", () => {
    sessionStorage.setItem(EXPANDED_KEY, "{not json");
    const store = new Store();
    expect(store.getState().expandedRows.size).toBe(0);
  });

  it("defaults the active tab to findings, or the seeded tab", () => {
    expect(new Store().getState().activeTab).toBe("findings");
    expect(new Store({ activeTab: "alerts" }).getState().activeTab).toBe("alerts");
  });
});

describe("status transitions", () => {
  it("starts first-load and never goes stale before a snapshot lands", () => {
    const store = new Store();
    expect(store.getState().status).toBe("first-load");
    store.markStale();
    expect(store.getState().status).toBe("first-load"); // still first-load — honest "connecting…"
  });

  it("goes live on a snapshot and stamps lastGoodAt", () => {
    const store = new Store();
    store.applySnapshot({ findings: [] });
    expect(store.getState().status).toBe("live");
    expect(store.getState().lastGoodAt).toBeTypeOf("number");
  });

  it("goes stale after a snapshot, keeping the last-good data", () => {
    const store = new Store();
    store.applySnapshot({ findings: [{ id: "a" }] });
    store.markStale();
    expect(store.getState().status).toBe("stale");
    expect(store.getState().data).toEqual({ findings: [{ id: "a" }] }); // last-good kept, not blanked
  });
});

describe("expansion + disclosure mutators", () => {
  it("toggles a row and persists to sessionStorage", () => {
    const store = new Store();
    store.toggleRow("r1");
    expect(store.isExpanded("r1")).toBe(true);
    expect(JSON.parse(sessionStorage.getItem(EXPANDED_KEY))).toContain("r1");
    store.toggleRow("r1");
    expect(store.isExpanded("r1")).toBe(false);
  });

  it("sets a prompt open state idempotently", () => {
    const store = new Store();
    let notifications = 0;
    store.subscribe(() => notifications++);
    store.setPromptOpen("p1", true);
    store.setPromptOpen("p1", true); // no-op — same state
    expect(notifications).toBe(1);
    expect(store.isPromptOpen("p1")).toBe(true);
  });

  it("purges cleared ids from both persisted sets", () => {
    const store = new Store();
    store.toggleRow("gone");
    store.setPromptOpen("gone", true);
    store.purge(["gone"]);
    expect(store.isExpanded("gone")).toBe(false);
    expect(store.isPromptOpen("gone")).toBe(false);
    expect(JSON.parse(sessionStorage.getItem(EXPANDED_KEY))).not.toContain("gone");
  });
});

describe("subscribe", () => {
  it("notifies listeners on change and stops after unsubscribe", () => {
    const store = new Store();
    let n = 0;
    const off = store.subscribe(() => n++);
    store.toggleRow("a");
    off();
    store.toggleRow("b");
    expect(n).toBe(1);
  });
});
