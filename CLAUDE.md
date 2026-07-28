# Protector — repository conventions

These rules apply to all work in this repo. Architectural *decisions* live in
`docs/adr/`; this file captures the engineering *conventions* contributors and agents
must follow.

**North star:** the product's reason for existing is that **the model acts as an incident
responder** — along internet-facing attack paths it decides what is an attack and what to
cut, at the minimum scope; determinism proves + enriches + *feeds* the model, it never
decides the cut. See [`docs/VISION.md`](docs/VISION.md). Work should point toward it (the
downstream/pivot lane is not there yet — tracked from JEF-547).

## File size — hard limit

**No source file may exceed 1,000 lines.** This is a hard cap, not a guideline. A file
that grows unbounded becomes unreadable and unreviewable; that must not recur anywhere.

- When a file approaches 1,000 lines, split it into a module directory of focused
  submodules — one cohesive responsibility each — rather than letting it grow.
- **Tests count toward the limit.** Move large `#[cfg(test)]` blocks into their own
  `tests.rs` / `*_tests.rs` files alongside the code they cover.
- Write new code as small, single-purpose modules from the start. Prefer many small
  files over one large one.

## Invariants (enforced; see docs/adr)

- The engine runs in **shadow** by default — it proposes, it never acts.
- **Zero egress**: the security graph and evidence never leave the cluster.
- Presentation is a **view, never a decision gate** (ADR-0016).
- Untrusted text (CVE / verdict / prompt / advisory) is always escaped at render.

## Configuration — detection on by default; two gates only

Protector's job is detection, and **shadow already makes every detector inert of action**,
so a per-detector on/off flag guards nothing. **Do not add `PROTECTOR_*_ENABLE`-style
toggles** for detection / corroboration / enrichment features — wire them on. If a detector
is noisy, fix its **scope** (add a discriminator), don't add a toggle.

Only two boundaries justify a setting:

- **Enforcement** — `PROTECTOR_MODE` (`audit` = shadow, the default; `enforce` +
  `enforceScope` arms the reversible cuts, ADR-0021). The single shadow-vs-act gate.
- **Egress** — the zero-egress invariant. A flag that guards an *outbound* call is
  legitimate (e.g. `PROTECTOR_REKOR_ENABLE`, `PROTECTOR_ENGINE_NOTIFY_URL`,
  `PROTECTOR_ALLOW_EXTERNAL_*`).

Everything else is a deployment essential (binds, TLS, endpoints, feed mounts) or a tuning
knob with a sane default — not an operator toggle. Prefer a good default over a new setting.

## Workflow

- Branch + PR; never commit directly to `main`. Merge on green CI.
- **Releases follow strict semver**, computed from the conventional-commit subjects since
  the last tag: `feat` → **minor**; `fix`/`perf`/`refactor`/`chore`/`docs`/`ci`/`build` →
  **patch**; `!` or `BREAKING CHANGE` → **major** (pre-1.0: breaking → minor). Do not
  default to a rolling patch bump — this retires the old 0.3.x patch-per-release cadence
  (e.g. the next release carrying any `feat` after v0.3.112 is **v0.4.0**, not v0.3.113).
- Rust edition 2024: use `cargo add` for dependencies (don't hand-edit `Cargo.toml`);
  run `cargo fmt`; treat `clippy` warnings as errors; run the full test suite before
  declaring work complete.
