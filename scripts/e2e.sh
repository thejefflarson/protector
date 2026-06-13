#!/usr/bin/env bash
#
# End-to-end integration test for the mitigation engine, on a real k3d cluster.
#
# k3d *is* k3s, so a default k3d cluster has the SAME CNI stack as the Pis
# (flannel + the embedded kube-router NetworkPolicy controller). That makes it
# the right place to exercise the engine's cluster-facing glue that unit tests
# can't reach — the watch/reflector streams, the kube actuator's apply/delete,
# the Falco ingest HTTP path — and to drive the `networkpolicy` isolation
# actuator exactly as it behaves in prod. (Cilium/Calico is only needed for the
# ANP actuator, which this test does not cover.)
#
# The scenario proves the whole asymmetric action bar (ADR-0009) and the Q5
# self-revert invariant end-to-end:
#
#   web (internet-exposed) ──reaches──▶ store ──can-read──▶ secret/session-key
#
#   A. shadow      — the chain proves STRUCTURALLY (no vuln, no corroboration).
#   B. corroborate — a simulated falcosidekick alert on `web` flips it to
#                    "live — auto-eligible", but nothing is applied (shadow).
#   C. hard mode   — enable=network: the engine applies a default-deny
#                    NetworkPolicy quarantining `web`.
#   D. self-revert — remove the durable allow (store-ingress); the chain stops
#                    being provable, so the engine DELETES its NetworkPolicy.
#
# Requirements: docker, k3d, kubectl, helm, jq, curl.
# Usage:        scripts/e2e.sh
# Env knobs:    CHART_PATH (default ../cluster/charts/protector)
#               IMAGE      (default protector:e2e — built from this repo)
#               CLUSTER    (default protector-e2e)
#               KEEP=1     leave the cluster up on exit for debugging
#
set -euo pipefail

CLUSTER="${CLUSTER:-protector-e2e}"
IMAGE="${IMAGE:-protector:e2e}"
CHART_PATH="${CHART_PATH:-$(cd "$(dirname "$0")/../../cluster/charts/protector" 2>/dev/null && pwd || true)}"
NS=protector
APP_NS=app
ENTRY="workload/${APP_NS}/Pod/web"
OBJECTIVE="secret/${APP_NS}/session-key"
CM_VERSION="${CM_VERSION:-v1.16.2}"

# --- output helpers -----------------------------------------------------------
RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; OFF=$'\033[0m'
log()  { echo "${YELLOW}==>${OFF} $*"; }
pass() { echo "${GREEN}PASS${OFF} $*"; }
fail() { echo "${RED}FAIL${OFF} $*" >&2; exit 1; }
step() { echo; echo "${DIM}────────────────────────────────────────────────────────${OFF}"; log "$*"; }

# --- preflight ----------------------------------------------------------------
for tool in docker k3d kubectl helm jq curl; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing required tool: $tool"
done
[ -n "$CHART_PATH" ] && [ -d "$CHART_PATH" ] || fail "chart not found; set CHART_PATH (got '${CHART_PATH}')"
log "chart: $CHART_PATH"

# --- teardown -----------------------------------------------------------------
PF_PIDS=()
cleanup() {
  for p in "${PF_PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  if [ "${KEEP:-0}" = "1" ]; then
    log "KEEP=1 — leaving cluster '$CLUSTER' up (delete with: k3d cluster delete $CLUSTER)"
  else
    log "tearing down cluster '$CLUSTER'"
    k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# --- generic poll -------------------------------------------------------------
# wait_until "<description>" <timeout-seconds> <predicate-fn> [args...]
wait_until() {
  local desc="$1" timeout="$2"; shift 2
  local deadline=$((SECONDS + timeout))
  until "$@"; do
    if (( SECONDS >= deadline )); then
      echo "${RED}timed out after ${timeout}s waiting for: ${desc}${OFF}" >&2
      return 1
    fi
    sleep 3
  done
}

# --- port-forwards (re-established after the pod is replaced on upgrade) -------
pf_reset() {
  for p in "${PF_PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  PF_PIDS=()
  kubectl -n "$NS" port-forward deploy/protector 8080:8080 >/dev/null 2>&1 & PF_PIDS+=($!)
  kubectl -n "$NS" port-forward deploy/protector 9999:9999 >/dev/null 2>&1 & PF_PIDS+=($!)
  # give the forwards a moment to bind
  wait_until "dashboard port-forward" 30 curl -fsS -o /dev/null localhost:8080/findings
}

# --- predicates ---------------------------------------------------------------
# A finding for the web→secret chain with the given disposition exists.
finding_is() {
  local disposition="$1"
  curl -fsS localhost:8080/findings 2>/dev/null \
    | jq -e --arg e "$ENTRY" --arg o "$OBJECTIVE" --arg d "$disposition" \
        '[.[] | select(.entry==$e and .objective==$o and .disposition==$d)] | length > 0' \
        >/dev/null 2>&1
}

post_falco() {
  curl -fsS -XPOST localhost:9999/ -H 'content-type: application/json' -d '{
    "rule": "Terminal shell in container",
    "priority": "Notice",
    "output_fields": { "k8s.ns.name": "app", "k8s.pod.name": "web" }
  }' >/dev/null
}

# The engine's managed isolation NetworkPolicy in the app namespace.
managed_np_name() {
  kubectl -n "$APP_NS" get networkpolicy \
    -l app.kubernetes.io/managed-by=protector -o name 2>/dev/null | head -n1
}
managed_np_present() { [ -n "$(managed_np_name)" ]; }
managed_np_absent()  { [ -z "$(managed_np_name)" ]; }

# ==============================================================================
step "1/8  Create k3d cluster (flannel + kube-router, like prod)"
k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
k3d cluster create "$CLUSTER" --wait --timeout 180s
kubectl config use-context "k3d-$CLUSTER" >/dev/null

step "2/8  Build + import the protector image"
docker build -t "$IMAGE" "$(dirname "$0")/.."
k3d image import "$IMAGE" -c "$CLUSTER"

step "3/8  Install cert-manager ($CM_VERSION) — the pod won't start without its serving cert"
kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CM_VERSION}/cert-manager.yaml"
kubectl wait --for=condition=Available -n cert-manager deploy --all --timeout=180s

step "4/8  Deploy protector in SHADOW mode (engine on, no actions, no actuation RBAC)"
helm install protector "$CHART_PATH" \
  --namespace "$NS" --create-namespace \
  --set replicaCount=1 \
  --set image.repository="${IMAGE%:*}" --set image.tag="${IMAGE#*:}" --set image.pullPolicy=Never \
  --set imagePullSecrets=null \
  --set signature.enforceNamespaces="" --set signature.enforceLabels="" \
  --set engine.enable="" --set engine.actuationRBAC=false \
  --wait --timeout 240s
kubectl -n "$NS" rollout status deploy/protector --timeout=120s
pf_reset

step "5/8  Create the attack path: exposed web ─reaches→ store ─can-read→ secret"
kubectl create ns "$APP_NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$APP_NS" create secret generic session-key --from-literal=k=x \
  --dry-run=client -o yaml | kubectl apply -f -
# `store` mounts the secret (envFrom) -> can-read edge store→secret.
kubectl -n "$APP_NS" run store --image=nginx:alpine --labels=role=store \
  --overrides='{"spec":{"containers":[{"name":"store","image":"nginx:alpine","envFrom":[{"secretRef":{"name":"session-key"}}]}]}}'
# `web` is the entry; LoadBalancer Service -> Exposure::Internet.
kubectl -n "$APP_NS" run web --image=nginx:alpine --labels=role=web
kubectl -n "$APP_NS" expose pod web --type=LoadBalancer --port=80 --name=web
# The durable allow that creates the reaches edge web→store. Removing THIS is the
# real fix (step 8); the engine's quarantine is the compensating control.
kubectl -n "$APP_NS" apply -f - <<'YAML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: store-ingress
spec:
  podSelector:
    matchLabels: { role: store }
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels: { role: web }
YAML
kubectl -n "$APP_NS" wait --for=condition=Ready pod/web pod/store --timeout=120s

step "6/8  SHADOW: chain proves structurally, then corroboration flips it auto-eligible — but NOTHING is applied"
wait_until "structural chain web→session-key" 90 finding_is "structural — proposed"
pass "structural chain proven (no foothold, no corroboration)"

post_falco
wait_until "chain flips to live — auto-eligible after Falco alert" 60 finding_is "live — auto-eligible"
pass "corroboration alone meets the asymmetric action bar (no vuln required)"

managed_np_absent || fail "shadow mode applied a NetworkPolicy — propose-only was violated"
pass "shadow mode applied nothing (propose-only honored)"

step "7/8  HARD MODE: enable=network + actuation RBAC; engine quarantines web"
helm upgrade protector "$CHART_PATH" --namespace "$NS" --reuse-values \
  --set engine.enable=network --set engine.actuationRBAC=true \
  --wait --timeout 180s
kubectl -n "$NS" rollout status deploy/protector --timeout=120s
pf_reset
# The pod was replaced, so its runtime-evidence store reset — re-send the alert.
post_falco
wait_until "engine applies a managed isolation NetworkPolicy" 120 managed_np_present
np="$(managed_np_name)"
selector="$(kubectl -n "$APP_NS" get "$np" -o jsonpath='{.spec.podSelector.matchLabels.role}')"
[ "$selector" = "web" ] || fail "managed NetworkPolicy selects role='$selector', expected 'web'"
pass "engine applied $np quarantining role=web"

step "8/8  SELF-REVERT: remove the durable allow; the chain is no longer provable, so the engine reverts"
kubectl -n "$APP_NS" delete networkpolicy store-ingress
wait_until "engine deletes its managed NetworkPolicy" 120 managed_np_absent
pass "engine reverted its compensating control once the chain stopped being proven (Q5 invariant)"

echo
echo "${GREEN}e2e: all phases passed${OFF} — watch loop, graph build, Falco ingest, isolation actuator, and self-revert all verified against a real API server on the prod CNI."
