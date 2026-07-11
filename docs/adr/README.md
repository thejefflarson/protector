# Architecture Decision Records

The consequential decisions behind protector — the *why* behind the code, not
just the *what*. New decisions get a new numbered file; superseded ones stay
(marked `Superseded by NNNN`).

Format: [Michael Nygard's ADR style](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions).
Copy [`0000-template.md`](0000-template.md) to start one.

| # | Decision | Status |
|---|----------|--------|
| [0001](0001-async-mitigation-engine.md) | Async mitigation engine: propose / prove / respond, local-first | Accepted |
| [0002](0002-change-driven-ir-loop.md) | Change-driven incident loop: diff the cluster, prove the delta, manage the debt | Accepted |
| [0003](0003-capability-ports.md) | Capability ports: depend on what a tool answers, not which tool it is | Accepted |
| [0004](0004-graph-representation.md) | Graph representation: in-memory petgraph, rebuilt from observed state | Accepted |
| [0005](0005-attack-objectives.md) | Objectives are ATT&CK outcomes, not just secrets | Accepted |
| [0006](0006-build-vs-adopt.md) | Build the substrate; treat KubeHound/IceKube as catalogue and optional provider | Accepted |
| [0007](0007-live-cuts-via-adminnetworkpolicy.md) | Live network cuts are additive AdminNetworkPolicy Deny rules | Accepted |
| [0009](0009-asymmetric-action-bar.md) | Asymmetric action bar: live evidence acts, latent exposure proposes | Accepted (amended by 0011, 0013, 0016, 0017, 0022; corroboration made tool-agnostic + per-objective by 0014/JEF-305) |
| [0010](0010-flannel-actuator-workload-isolation.md) | Flannel actuator: quarantine the source with a default-deny NetworkPolicy | Accepted (amended by 0022) |
| [0011](0011-positive-judgement.md) | The model corroborates positively; operator access is out of scope, defended in depth | Superseded in part by 0013 |
| [0012](0012-exposure-observed-or-declared.md) | Exposure is observed where possible, declared (annotation) where it can't be — tunnels | Accepted |
| [0013](0013-proof-winnows-model-decides.md) | Proof winnows the search space; the model makes the exploitability call (positive gate + breach-relevance) | Accepted (amended by 0016) |
| [0014](0014-behavioral-telemetry-ebpf.md) | First-party behavioral telemetry via eBPF, behind a tool-agnostic port (potential vs actual) | Accepted (amended by JEF-305: per-objective corroboration landed; the Retire-Falco parity bar = measured decision-path coverage, retire the adapter not the port) |
| [0015](0015-advisory-evidence-egress.md) | Advisory evidence is mounted-snapshot-only (zero egress); structurally extracted + capped for injection safety | Accepted (advisory feed retired per JEF-242; Rekor egress carve-out amended by 0020) |
| [0016](0016-severity-vs-urgency.md) | The breach model: prove chains, enrich them, the model decides and isolates until clear | Accepted (amended by 0017) |
| [0017](0017-isolation-persists-on-the-breach-condition.md) | Isolation persists on the breach condition: chain ∧ enrichment fingerprint (revert keys on `entry_fingerprint`) | Accepted |
| [0018](0018-operator-configured-redacted-breach-notifier.md) | The breach notifier is the one sanctioned outbound path: operator-configured, off by default, redacted by default | Accepted |
| [0019](0019-dashboard-v3-presentation-architecture.md) | Dashboard v3: server-rendered (maud), zero-egress, light-theme presentation — the view_model/component/page split + the honesty invariants | Accepted (amended by JEF-281: finding detail shows all proven paths; presentation *mechanism* superseded in part by 0025 — IA + honesty axes survive) |
| [0020](0020-signature-continuity.md) | Supply-chain trust is signature continuity: observe every image, learn a per-repo TOFU baseline, treat the signed→unsigned / identity-change regression as the signal — not prefix-gated single-identity (amended: JEF-280 baseline-relative downgrade; JEF-275 build-provenance as a second continuity axis) | Accepted |
| [0021](0021-two-setting-operating-posture.md) | Two-setting operating posture: `mode` (audit default / enforce) + one `enforceScope` arms all three enforcement surfaces (signature + mesh webhooks + engine live cut), fail-closed webhook selector and actuation RBAC derived from it — no per-surface toggle, no wildcard | Accepted |
| [0022](0022-quarantine-the-entry-is-the-default-containment.md) | Quarantine the internet-facing entry is the default containment (entry-only, additive/reversible default-deny); the surgical edge-cut is the refinement used only when it suffices | Accepted |
| [0023](0023-delta-aware-adjudication.md) | Delta-aware adjudication: the full cluster state is the context, the change is the question | Accepted |
| [0024](0024-no-redundant-by-construction-predicates.md) | Corroboration shapes must be load-bearing when merged, not deferred-dead — a predicate whose result is already fixed by an existing arm lands when it bites, not ahead of it | Accepted |
| [0025](0025-dashboard-v4-preact-client-render.md) | Dashboard v4: a bundled Preact client reconciling from same-origin read-only JSON — supersedes 0019's maud server-render *mechanism* (its IA + honesty axes survive); view_model/props retained as the serde JSON contract, bundle built-from-source + gitignored, honesty stays server-derived | Accepted |

See also [`../VISION.md`](../VISION.md) for the longer-form narrative this ADR realizes.
