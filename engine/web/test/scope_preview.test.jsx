// Scope-preview panel tests (ADR-0021, ADR-0016): the candidate scope is submitted via a
// same-origin fetch (never a poll), the honest-empty-candidate reading, the would-fire /
// held-out-of-scope partition, the collateral-unknown caveat (never collapsed into "no
// collateral"), and that untrusted cut/action text renders inert (no XSS).

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, fireEvent, cleanup, waitFor } from "@testing-library/preact";
import { ScopePreviewPanel } from "../src/scope_preview/view.jsx";

beforeEach(() => {
  cleanup();
});

function jsonResponse(body, ok = true) {
  return Promise.resolve({ ok, json: () => Promise.resolve(body) });
}

function submit(container, { namespaces = "", labels = "" } = {}) {
  const [nsInput, labelInput] = container.querySelectorAll("input");
  fireEvent.input(nsInput, { target: { value: namespaces } });
  fireEvent.input(labelInput, { target: { value: labels } });
  fireEvent.submit(container.querySelector("form"));
}

describe("ScopePreviewPanel", () => {
  it("fetches the candidate scope on submit and never polls on mount", async () => {
    const fetchImpl = vi.fn(() =>
      jsonResponse({
        strip: {},
        "candidate-namespaces": ["app"],
        "candidate-labels": [],
        "candidate-is-empty": false,
        "would-fire": [],
        "held-out-of-scope": [],
      }),
    );
    const { container } = render(<ScopePreviewPanel fetchImpl={fetchImpl} />);
    expect(fetchImpl).not.toHaveBeenCalled();

    submit(container, { namespaces: "app" });
    await waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));
    const [url] = fetchImpl.mock.calls[0];
    expect(url).toBe("/api/scope_preview.json?namespaces=app");
  });

  it("renders the honest empty-candidate reading distinct from a nothing-fires-in-scope result", async () => {
    const fetchImpl = vi.fn(() =>
      jsonResponse({
        "candidate-is-empty": true,
        "would-fire": [],
        "held-out-of-scope": [],
      }),
    );
    const { container } = render(<ScopePreviewPanel fetchImpl={fetchImpl} />);
    submit(container);
    await waitFor(() => expect(container.textContent).toContain("no namespaces or labels entered"));
    expect(container.textContent).toContain("an honest zero");
  });

  it("renders a firing cut's collateral and a held-out-of-scope cut separately", async () => {
    const fetchImpl = vi.fn(() =>
      jsonResponse({
        "candidate-is-empty": false,
        "would-fire": [
          {
            cut: "workload/app/Pod/web -[reaches/Tcp/5432]-> workload/app/Pod/db",
            action: "add a scoped deny NetworkPolicy/AuthorizationPolicy",
            "alive-collateral": ["workload/app/Pod/metrics"],
            "collateral-unknown": false,
          },
        ],
        "held-out-of-scope": [
          {
            cut: "workload/other/Pod/svc -[reaches/Tcp/443]-> workload/ext/Pod/api",
            action: "quarantine the internet-facing entry with a default-deny NetworkPolicy",
          },
        ],
      }),
    );
    const { container } = render(<ScopePreviewPanel fetchImpl={fetchImpl} />);
    submit(container, { namespaces: "app" });
    await waitFor(() => expect(container.textContent).toContain("would sever"));
    expect(container.textContent).toContain("workload/app/Pod/metrics");
    expect(container.textContent).toContain("held");
    expect(container.textContent).toContain("workload/other/Pod/svc");
  });

  it("flags collateral-unknown distinctly, never as an implied-safe empty collateral", async () => {
    const fetchImpl = vi.fn(() =>
      jsonResponse({
        "candidate-is-empty": false,
        "would-fire": [
          {
            cut: "workload/app/Pod/web -[reaches/Tcp/5432]-> workload/app/Pod/db",
            action: "add a scoped deny NetworkPolicy/AuthorizationPolicy",
            "alive-collateral": [],
            "collateral-unknown": true,
          },
        ],
        "held-out-of-scope": [],
      }),
    );
    const { container } = render(<ScopePreviewPanel fetchImpl={fetchImpl} />);
    submit(container, { namespaces: "app" });
    await waitFor(() => expect(container.textContent).toContain("collateral unknown"));
    expect(container.textContent).not.toContain("no live collateral known");
  });

  it("shows an honest error state and renders nothing untrusted as HTML on a non-ok response", async () => {
    const fetchImpl = vi.fn(() => jsonResponse({}, false));
    const { container } = render(<ScopePreviewPanel fetchImpl={fetchImpl} />);
    submit(container, { namespaces: "app" });
    await waitFor(() => expect(container.textContent).toContain("could not compute the preview"));
  });

  it("renders an XSS cut/action string as inert text, never executed", async () => {
    window.__pwned = undefined;
    const xss = '<img src=x onerror="window.__pwned=1">';
    const fetchImpl = vi.fn(() =>
      jsonResponse({
        "candidate-is-empty": false,
        "would-fire": [
          {
            cut: xss,
            action: xss,
            "alive-collateral": [xss],
            "collateral-unknown": false,
          },
        ],
        "held-out-of-scope": [],
      }),
    );
    const { container } = render(<ScopePreviewPanel fetchImpl={fetchImpl} />);
    submit(container, { namespaces: "app" });
    await waitFor(() => expect(container.textContent).toContain(xss));
    expect(container.querySelector("img")).toBeNull();
    expect(window.__pwned).toBeUndefined();
  });
});
