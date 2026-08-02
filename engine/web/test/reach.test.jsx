// The finding detail's adversary-reach annotation (ADR-0040): a value-free "if compromised,
// this workload grants the attacker …" line. PRESENTATION ONLY — this test only asserts it
// renders (auto-escaped, like every other string) and is honestly absent when the engine has
// nothing to annotate; it never touches a verdict or a cut decision.

import { describe, it, expect, beforeEach } from "vitest";
import { render, fireEvent, cleanup } from "@testing-library/preact";
import { FindingsView } from "../src/findings/table.jsx";
import { finding, findingsView } from "./fixtures.js";

beforeEach(() => {
  sessionStorage.clear();
  cleanup();
});

function expand(container, id) {
  fireEvent.click(container.querySelector(`tr.row[data-finding="${id}"]`));
}

describe("finding detail adversary-reach panel", () => {
  it("renders the value-free reach line under its own section", () => {
    const f = finding("reach-1", {
      reach:
        "if compromised, this workload grants the attacker: a service-account-token secret; 2 reachable data stores, 1 reachable RBAC capability, and an internet egress path",
    });
    const { container } = render(<FindingsView view={findingsView([f])} />);
    expand(container, "reach-1");

    const section = container.querySelector(".reach-block");
    expect(section).not.toBeNull();
    expect(section.querySelector(".reach-line").textContent).toBe(
      "if compromised, this workload grants the attacker: a service-account-token secret; 2 reachable data stores, 1 reachable RBAC capability, and an internet egress path",
    );
  });

  it("renders nothing when the engine has no reach annotation for this entry", () => {
    const f = finding("reach-2", { reach: null });
    const { container } = render(<FindingsView view={findingsView([f])} />);
    expand(container, "reach-2");

    expect(container.querySelector(".reach-block")).toBeNull();
  });
});
