# 0004. Graph representation: in-memory petgraph, rebuilt from observed state

- Status: Accepted
- Date: 2026-06-11

## Context

[ADR-0002](0002-change-driven-ir-loop.md) made the cluster security graph core
infrastructure and decided it tracks *observed* state fed by watch streams.
[ADR-0003](0003-capability-ports.md) fixed the graph **vocabulary** (typed nodes
and edges, each edge carrying provenance; originally also a proof-grade/hypothesis-grade
tag, removed in JEF-365 — see that ADR's amendment) as the stable contract adapters map
into. What neither settled is the concrete question: **what do we store the graph in,
and does it persist?**

The forces are unusually one-sided here, which is why this is a short ADR:

- **Scale is tiny.** Dozens to low-hundreds of nodes, a small edge set — the
  bound ADR-0001 accepted deliberately. Query-engine sophistication and storage
  throughput buy nothing at this size.
- **The graph is derivable, not authoritative.** Because detection tracks observed
  state from `list`+`watch`, the graph can always be reconstructed from the live
  cluster on startup or after a watch gap. The cluster is the source of truth; the
  graph is a projection of it.
- **The proof layer's queries are explicit walks.** `is_reachable(A,B)` is a
  predicate-filtered BFS over reachability edges; `can_i(S,V,R)` is a privilege
  walk; the counterfactual cut, for an already-*proven* path, is just "enumerate
  the edges on that path and test whether any other proven path survives." None of
  this needs a query language to be correct — and a hand-walk is maximally
  auditable, which is exactly what "only deterministic proof moves privilege"
  wants.
- **The codebase favors a small dependency surface.** `metrics.rs` hand-rolls
  Prometheus output specifically to avoid pulling a stack and to keep `cargo
  audit` small. An embedded or external graph DB is a large commitment against
  that grain, for durability and query power we just established we do not need.

## Decision

We will hold the graph **in memory, in [`petgraph`](https://docs.rs/petgraph)**,
reconstructed on startup from `kube`'s `list`+`watch` and mutated incrementally as
watch events arrive. **No graph database, and no persistence for the graph
itself.** Specifically:

- A `petgraph::stable_graph::StableGraph` — stable node/edge indices survive the
  incremental add/remove churn that deltas produce.
- Strongly-typed node and edge enums implementing the ADR-0003 vocabulary. Every
  edge carries its **provenance** (which adapter asserted it) and is a **deterministic
  observation by construction** — no hypothesis-grade edges exist, so any edge is
  eligible to move privilege. (The original design tagged each edge proof-grade vs
  hypothesis-grade; JEF-365 removed the tag once nothing constructed a hypothesis-grade
  edge — see ADR-0003's amendment.)
- Reachability and privilege as **explicit predicate-filtered walks**, not a query
  language. The counterfactual cut enumerates edges on a proven path; we do not
  need general max-flow at this scale (`petgraph::algo::ford_fulkerson` is there if
  a denser graph ever changes that).
- On a missed-watch / resync gap, **rebuild from a fresh `list`** rather than
  trusting accumulated state — a stale graph produces wrong cuts, so freshness
  beats continuity.

**Two boundaries this decision does _not_ cover, deliberately:**

- **The mitigation ledger persists; the graph does not.** Active mitigations and
  findings (ADR-0002 Q5) outlive a restart and are *not* reconstructable from
  cluster state alone (their justification and retirement predicate are engine
  knowledge). They need durable storage — likely as **CRDs** (kubectl-visible,
  RBAC-controlled, watchable, persisted in etcd) rather than a sidecar database —
  but that is a separate decision deferred to its own ADR.
- **Declarative proof rules are a possible evolution, not the starting point.** If
  the rule set outgrows hand-walks, [`ascent`](https://docs.rs/ascent) (Datalog as
  a compile-time Rust macro, no runtime service) composes on top of the same
  `petgraph` substrate. We start with hand-walks for auditability and reach for
  `ascent` only if complexity demands it.

## Consequences

Easier:

- Zero new stateful infrastructure; the graph is a process-local data structure.
- No stale-persistence hazard — the worst case is a rebuild from the API, which is
  cheap at this scale and always yields the true current state.
- Proof queries are plain Rust over a typed graph: inspectable, testable with
  fabricated graphs, and trivially fast.
- One well-trusted pure-Rust crate, in keeping with the project's dependency
  discipline.

Harder / accepted downsides:

- **Rebuild cost on every restart / resync.** Acceptable at this scale; would not
  be at large scale — but large scale is already out of scope.
- **No history.** The in-memory graph is "now"; temporal questions ("when did this
  edge appear?") aren't answerable from it. The delta stream and the ledger carry
  what history we need; full time-travel would require a different substrate, and
  we are not buying it.
- **Hand-walked queries are code, not declarations.** A new *kind* of reachability
  question is a new walk to write and test. That is the cost of not adopting a
  query engine, and it is the right cost until the rules prove unwieldy.
