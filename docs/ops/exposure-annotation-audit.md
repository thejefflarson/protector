# Exposure model audit — deployed cluster (post route-transitive exposure)

Audit run after the Ingress exposure observer (ADR-0038) landed, to check for
annotation drift and decide whether a Gateway-API/`HTTPRoute` observer is warranted.
Snapshot date: 2026-08-01.

## How the deployed cluster's internet edge actually works

**The edge is off-cluster cloudflared tunnels, not in-cluster L7 routing.** The `public`
namespace runs `tunnel-*-tunnel-token-*` (cloudflared) pods fronting the internet-facing
services (argocd, k8s, linkerd, murmurify-oprf, murmurify-relay, …). Internet exposure is
therefore declared, not observed in-cluster — the correct mechanism per
[ADR-0012](../adr/0012-exposure-observed-or-declared.md): 12 Services carry
`protector.jeffl.es/exposure=internet` —

    analytics/{murmurify-aggregator, murmurify-oprf, murmurify-relay, murmurify-sdk, murmurify-server}
    argocd/argocd-server
    protector/{protector-dashboard, protector-mcp}
    public/{persephone, portal, resume}
    watcher/watcher-server

## Findings

1. **No k8s `Ingress` objects exist** (`kubectl get ingress -A` → none; default IngressClass
   is `traefik`). So the Ingress observer (ADR-0038) is **inert on this cluster** — correctly:
   there is no in-cluster route object to promote from, and the observer's fail direction is
   under-promote. With the graceful-degradation preflight (a forbidden/absent Ingress API →
   log-once, skip), it is safely inert even before the fork RBAC hand-port lands.

2. **Annotations: keep all 12 — no drift, no orphans.** Because the edge is off-cluster
   (cloudflared) and there are no Ingresses, nothing in-cluster now covers these Services;
   the annotation remains the sole, load-bearing exposure declaration for each. Removing any
   would un-expose that Service to protector. **Guidance: keep every annotation above as-is.**

3. **Gateway API CRDs ARE installed, but a Gateway/`HTTPRoute` observer is NOT warranted.**
   The CRDs exist (`gateways`, `httproutes`, `grpcroutes`, `gatewayclasses`,
   `referencegrants`), but the only `HTTPRoute`s are **internal** postgres-operator routes
   (`*-patroni-control`/`-metrics`/`-probes` in `analytics`/`watcher`), and there are **no
   `Gateway` objects** and no external hostnames. A naive HTTPRoute observer would risk
   **over-promoting internal DB backends** to internet entries — the exact hazard ADR-0038's
   controller-anchoring guards against. **Decision: do not build a Gateway/HTTPRoute observer
   for this cluster.** If one is ever built (for a different cluster), it must anchor on an
   internet-exposed `Gateway` (of which this cluster has none), mirroring the Ingress
   observer's live-address anchor.

## Follow-ups

- **Fork RBAC hand-port (low priority).** ADR-0038's Ingress observer needs
  `networking.k8s.io: [ingresses, ingressclasses]` get/list/watch, added to the in-repo
  chart but not the deployed **fork** (`../cluster/charts/protector`, image-tag auto-bump
  only). Since this cluster has no Ingresses and the observer graceful-degrades, deploying
  without the hand-port is safe (the observer stays inert). Port it only if/when in-cluster
  Ingress routing is introduced here.
- **No Gateway-observer ticket filed** — not warranted (finding 3).

## Conclusion

The route-transitive Ingress observer (ADR-0038) is a correct, general capability (it helps
any cluster that uses in-cluster Ingress), and it ships safely inert here. The deployed
cluster's off-cluster cloudflared edge is correctly modeled by the ADR-0012 annotation set,
which should be kept intact. No further exposure-observer work is warranted for this cluster.
