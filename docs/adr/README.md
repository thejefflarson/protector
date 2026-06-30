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
| [0009](0009-asymmetric-action-bar.md) | Asymmetric action bar: live evidence acts, latent exposure proposes | Accepted (amended by 0011, 0013, 0016, 0017) |
| [0010](0010-flannel-actuator-workload-isolation.md) | Flannel actuator: quarantine the source with a default-deny NetworkPolicy | Accepted |
| [0011](0011-positive-judgement.md) | The model corroborates positively; operator access is out of scope, defended in depth | Superseded in part by 0013 |
| [0012](0012-exposure-observed-or-declared.md) | Exposure is observed where possible, declared (annotation) where it can't be — tunnels | Accepted |
| [0013](0013-proof-winnows-model-decides.md) | Proof winnows the search space; the model makes the exploitability call (positive gate + breach-relevance) | Accepted (amended by 0016) |
| [0014](0014-behavioral-telemetry-ebpf.md) | First-party behavioral telemetry via eBPF, behind a tool-agnostic port (potential vs actual) | Accepted |
| [0015](0015-advisory-evidence-egress.md) | Advisory evidence is mounted-snapshot-only (zero egress); structurally extracted + capped for injection safety | Accepted |
| [0016](0016-severity-vs-urgency.md) | The breach model: prove chains, enrich them, the model decides and isolates until clear | Accepted (amended by 0017) |
| [0017](0017-isolation-persists-on-the-breach-condition.md) | Isolation persists on the breach condition: chain ∧ enrichment fingerprint (revert keys on `entry_fingerprint`) | Accepted |
| [0018](0018-operator-configured-redacted-breach-notifier.md) | The breach notifier is the one sanctioned outbound path: operator-configured, off by default, redacted by default | Accepted |
| [0019](0019-dashboard-v3-presentation-architecture.md) | Dashboard v3: server-rendered (maud), zero-egress, light-theme presentation — the view_model/component/page split + the honesty invariants | Accepted |
| [0020](0020-signature-continuity.md) | Supply-chain trust is signature continuity: observe every image, learn a per-repo TOFU baseline, treat the signed→unsigned / identity-change regression as the signal — not prefix-gated single-identity | Accepted |

See also [`../VISION.md`](../VISION.md) for the longer-form narrative this ADR realizes.
