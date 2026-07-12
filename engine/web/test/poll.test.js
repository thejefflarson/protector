// Unit tests for the poll engine (ADR-0025 / JEF-397): same-origin URL construction, the
// defer-apply-while-text-selection rule (ported from v3), and stale-not-blank on a failed poll.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { snapshotUrl, startPolling, hasLiveSelection, POLL_MS } from "../src/poll.js";
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

// JEF-408 regression: the DEFAULT setIntervalImpl must adapt native `setInterval` (whose signature
// is `(fn, ms)`) to the `(ms, fn)` shape this module calls it with. The pre-fix default passed native
// `setInterval` directly, so `setInterval(POLL_MS, tick)` handed the NUMBER 5000 as the handler — the
// recurring poll never fired (dead poll / blank tab-swaps) AND the browser coerced the number to the
// string "5000" and took the legacy string-handler eval path, which the strict CSP (`script-src
// 'self'`, no unsafe-eval) correctly BLOCKED. Both symptoms have the same root cause: reversed args.
describe("startPolling default interval (JEF-408 regression)", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("re-fires the recurring poll MORE THAN ONCE with the DEFAULT setIntervalImpl", async () => {
    // No setIntervalImpl override — exercise the real default over fake timers. Pre-fix this ticked
    // exactly once (only the initial tick()); the recurring interval was dead.
    const fetchImpl = okFetch({ findings: [] });
    const stop = startPolling({
      store: new Store(),
      tab: () => "findings",
      liveRegion: () => null,
      fetchImpl,
    });
    // Initial tick fires synchronously on start.
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    // Advance three intervals — the recurring poll must fire each time.
    await vi.advanceTimersByTimeAsync(POLL_MS * 3);
    expect(fetchImpl.mock.calls.length).toBeGreaterThan(1);
    expect(fetchImpl.mock.calls.length).toBe(4); // 1 initial + 3 recurring
    stop();
  });

  it("hands native setInterval a FUNCTION handler (never a number/string — no eval)", () => {
    // Spy on the global the default closes over. The reversed-args bug passed POLL_MS (a number) as
    // the handler; coerced to the string "5000", native setInterval evals it — the CSP violation the
    // operator reported. Assert the FIRST arg to native setInterval is a function, not a number/string.
    const setIntervalSpy = vi.spyOn(globalThis, "setInterval");
    const stop = startPolling({
      store: new Store(),
      tab: () => "findings",
      liveRegion: () => null,
      fetchImpl: okFetch({ findings: [] }),
      // No setIntervalImpl override — the default adapter must call native setInterval as (fn, ms).
    });
    expect(setIntervalSpy).toHaveBeenCalledTimes(1);
    const [handler, delay] = setIntervalSpy.mock.calls[0];
    expect(typeof handler).toBe("function"); // never a number/string — no legacy string-eval path
    expect(delay).toBe(POLL_MS);
    stop();
    setIntervalSpy.mockRestore();
  });
});
