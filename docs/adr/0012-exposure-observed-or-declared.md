# 0012. Exposure is observed where possible, declared where it can't be

- Status: Accepted
- Date: 2026-06-13

## Context

`Exposure::Internet` on an entry workload is load-bearing: it is the entry side of
the action bar and the gate for a *foothold* (internet-exposed ∧ exploited-in-wild/
critical CVE ∧ reachable — the log4j case, ADR-0011). If a genuinely internet-facing
workload is not marked `Internet`, the foothold never forms and the headline
auto-response never fires on it.

The [`ExposureAdapter`](../../engine/src/engine/adapter/exposure.rs) infers exposure from the
Services that select a pod: `LoadBalancer`/`NodePort`/`externalIPs` ⇒ `Internet`,
any other selecting Service ⇒ `ClusterExposed`, none ⇒ `Internal`. That is correct
for clusters that expose via the Service type — but **many clusters don't**.

A common pattern is an **outbound tunnel** (e.g. a Cloudflare/ngrok-style
`cloudflared tunnel`): the hostname→service routing lives **off-cluster** at the
tunnel provider, and the in-cluster target is a plain **`ClusterIP`** Service. So:

- there is **no in-cluster object** carrying the ingress map — the tunnel's config
  is remote, not a ConfigMap the engine can read; and
- every internet-facing workload resolves to `ClusterExposed`, not `Internet`.

Net effect before this ADR: the engine sees **~zero internet-exposed workloads** in
such a cluster, so the foothold/log4j path — proven in the e2e with a stand-in
`LoadBalancer` — is inert against the real attack surface.

We considered an adapter that reads the tunnel ingress map in-cluster. It is
infeasible: such tunnels hold no in-cluster ingress config to observe.

## Decision

Exposure is **observed where the engine can see it, and declared where it can't.**

1. **Observed (unchanged):** Service type — `LoadBalancer`/`NodePort`/`externalIPs`
   ⇒ `Internet`; other selecting Service ⇒ `ClusterExposed`.
2. **Declared:** an annotation, `protector.jeffl.es/exposure: internet`, on the
   fronted **Service** or the **pod**, forces `Internet`. This is the honest seam
   for exposure that is real but out-of-cluster — a Cloudflare tunnel, an external
   LB, or an Ingress/Gateway the engine doesn't model. The operator (or the
   workload's chart) declares what the engine cannot observe.

The annotation *wins* (it's an override for the case inference gets wrong), and a
missing/other value changes nothing. The source of truth for which Services to
annotate is wherever your off-cluster routing is defined (the tunnel/ingress config).

This keeps the capability-port discipline (ADR-0003): exposure is still a *fact* the
graph carries; we've added a second, declarative provider for it alongside the
Service-type observer, rather than teaching the rules about tunnels.

## Consequences

Easier:

- The foothold/log4j path actually fires on the cluster's real internet surface,
  once the tunnel-fronted Services carry the annotation.
- No dependency on external IaC state or the tunnel provider's API at runtime; the
  engine stays a pure observer of cluster state plus a declared fact.

Harder / accepted downsides:

- **Exposure is only as correct as the annotations.** A public Service that nobody
  annotates is invisible to the foothold gate — a missed detection (fail-safe
  direction: under-acts, never over-acts). Keeping annotations in sync with your
  routing config is an operational responsibility; drift = blind spots.
- **It's a manual declaration**, not inference. That is inherent: the routing lives
  off-cluster, so there is nothing to infer from.
- Ingress/Gateway-API exposure is likewise unmodeled and uses the same annotation
  until/unless a dedicated observer is added.

## Rollout

Annotate each tunnel-/ingress-fronted Service that is actually internet-reachable
with `protector.jeffl.es/exposure: internet`. Until then, the engine treats those
workloads as cluster-only, and footholds on them will not promote.
