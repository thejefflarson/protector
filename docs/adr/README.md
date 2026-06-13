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
| [0008](0008-model-adjudicates-never-authorizes.md) | The model adjudicates (one-way veto); it never authorizes, and never exploits | Accepted (amended by 0011) |
| [0009](0009-asymmetric-action-bar.md) | Asymmetric action bar: live evidence acts, latent exposure proposes | Accepted (amended by 0011) |
| [0010](0010-flannel-actuator-workload-isolation.md) | Flannel actuator: quarantine the source with a default-deny NetworkPolicy | Accepted |
| [0011](0011-positive-judgement.md) | The model corroborates positively; operator access is out of scope, defended in depth | Proposed |
| [0012](0012-exposure-observed-or-declared.md) | Exposure is observed where possible, declared (annotation) where it can't be — tunnels | Accepted |

See also [`../VISION.md`](../VISION.md) for the longer-form narrative this ADR realizes.
