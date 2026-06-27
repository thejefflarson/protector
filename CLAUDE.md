# Protector — repository conventions

These rules apply to all work in this repo. Architectural *decisions* live in
`docs/adr/`; this file captures the engineering *conventions* contributors and agents
must follow.

## File size — hard limit

**No source file may exceed 1,000 lines.** This is a hard cap, not a guideline. The
dashboard grew past 7,000 lines and became unreadable and unreviewable; that must not
recur anywhere.

- When a file approaches 1,000 lines, split it into a module directory of focused
  submodules — one cohesive responsibility each — rather than letting it grow.
- **Tests count toward the limit.** Move large `#[cfg(test)]` blocks into their own
  `tests.rs` / `*_tests.rs` files alongside the code they cover.
- Write new code as small, single-purpose modules from the start. Prefer many small
  files over one large one.

## Dashboard structure (the canonical UI pattern)

The server-rendered dashboard follows a React-like split (see ADR-0019):

- `view_model/` shapes engine domain state into plain `Props` (the data layer).
- `components/` are pure `maud` renderers (`Props -> Markup`) and **must not import
  `engine::` domain types** — they receive only their `Props`.
- `page.rs` composes components into pages/fragments; `mod.rs` wires routes and state.

New UI work composes these small components; it does not grow a monolith.

## Invariants (enforced; see docs/adr)

- The engine runs in **shadow** by default — it proposes, it never acts.
- **Zero egress**: the security graph and evidence never leave the cluster.
- Presentation is a **view, never a decision gate** (ADR-0016).
- Untrusted text (CVE / verdict / prompt / advisory) is always escaped at render.

## Workflow

- Branch + PR; never commit directly to `main`. Merge on green CI.
- Rust edition 2024: use `cargo add` for dependencies (don't hand-edit `Cargo.toml`);
  run `cargo fmt`; treat `clippy` warnings as errors; run the full test suite before
  declaring work complete.
