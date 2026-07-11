// Unit tests for the poll engine (ADR-0025 / JEF-397): same-origin URL construction, the
// defer-apply-while-text-selection rule (ported from v3), and stale-not-blank on a failed poll.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { snapshotUrl, startPolling, hasLiveSelection } from "../src/poll.js";
import { Store } from "../src/store.js";

beforeEach(() => sessionStorage.clear());

describe("snapshotUrl", () => {
  it("is always a relative, same-origin path per tab", () => {
    expect(snapshotUrl("findings")).toBe("/api/findings.json");
    expect(snapshotUrl("alerts")).toBe("/api/alerts.json");
    expect(snapshotUrl("findings").startsWith("http")).toBe(false);
  });
});

/** A fetch stub returning one JSON payload, then holding. */
const okFetch = (payload) =>
  vi.fn().mockResolvedValue({ ok: true, json: async () => payload });

/** Run one immediate tick (the poll fetches once on start) with a never-firing interval. */
function startOnce(opts) {
  const noopInterval = () => 0;
  return startPolling({ setIntervalImpl: noopInterval, clearIntervalImpl: () => {}, ...opts });
}

describe("startPolling", () => {
  it("applies a fetched snapshot to the store (goes live)", async () => {
    const store = new Store();
    startOnce({
      store,
      tab: () => "findings",
      liveRegion: () => null,
      fetchImpl: okFetch({ findings: [{ id: "a" }] }),
    });
    await vi.waitFor(() => expect(store.getState().status).toBe("live"));
    expect(store.getState().data).toEqual({ findings: [{ id: "a" }] });
  });

  it("marks the store STALE (not blank) on a non-ok response", async () => {
    const store = new Store();
    store.applySnapshot({ findings: [{ id: "keep" }] }); // a prior good render
    startOnce({
      store,
      tab: () => "findings",
      liveRegion: () => null,
      fetchImpl: vi.fn().mockResolvedValue({ ok: false, status: 503 }),
    });
    await vi.waitFor(() => expect(store.getState().status).toBe("stale"));
    expect(store.getState().data).toEqual({ findings: [{ id: "keep" }] }); // last-good kept
  });

  it("marks stale on a thrown transport error", async () => {
    const store = new Store();
    store.applySnapshot({ findings: [] });
    startOnce({
      store,
      tab: () => "findings",
      liveRegion: () => null,
      fetchImpl: vi.fn().mockRejectedValue(new Error("offline")),
    });
    await vi.waitFor(() => expect(store.getState().status).toBe("stale"));
  });

  it("DEFERS applying a snapshot while a selection is anchored in the live region", async () => {
    const store = new Store();
    const region = document.createElement("div");
    region.textContent = "some selectable model verdict";
    document.body.appendChild(region);

    // Anchor a real, non-collapsed selection inside the region.
    const range = document.createRange();
    range.selectNodeContents(region);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    expect(hasLiveSelection(region)).toBe(true);

    startOnce({
      store,
      tab: () => "findings",
      liveRegion: () => region,
      fetchImpl: okFetch({ findings: [{ id: "x" }] }),
    });
    // The fetch resolves but the apply is deferred — the store stays first-load, NOT stale.
    await new Promise((r) => setTimeout(r, 5));
    expect(store.getState().status).toBe("first-load");
    expect(store.getState().data).toBeNull();

    sel.removeAllRanges();
    document.body.removeChild(region);
  });
});
