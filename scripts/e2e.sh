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

# Isolate the kubeconfig to a throwaway file so a caller's multi-path KUBECONFIG
# (which makes k3d refuse to write/select the context) can't break the run.
export KUBECONFIG="$(mktemp -t protector-e2e-kubeconfig)"

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
  rm -f "$KUBECONFIG" 2>/dev/null || true
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
step "1/12  Create k3d cluster (flannel + kube-router, like prod)"
k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
k3d cluster create "$CLUSTER" --wait --timeout 180s
kubectl config use-context "k3d-$CLUSTER" >/dev/null

step "2/12  Build + import the protector image"
docker build -t "$IMAGE" "$(dirname "$0")/.."
k3d image import "$IMAGE" -c "$CLUSTER"

step "3/12  Install cert-manager ($CM_VERSION) — the pod won't start without its serving cert"
kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CM_VERSION}/cert-manager.yaml"
kubectl wait --for=condition=Available -n cert-manager deploy --all --timeout=180s

step "4/12  Deploy protector in SHADOW mode (engine on, no actions, no actuation RBAC)"
helm install protector "$CHART_PATH" \
  --namespace "$NS" --create-namespace \
  --set replicaCount=1 \
  --set image.repository="${IMAGE%:*}" --set image.tag="${IMAGE#*:}" --set image.pullPolicy=Never \
  --set imagePullSecrets=null \
  --set signature.enforceNamespaces="" --set signature.enforceLabels="" \
  --set engine.enable="" --set engine.actuationRBAC=false \
  --set engine.model.endpoint= \
  --wait --timeout 240s
kubectl -n "$NS" rollout status deploy/protector --timeout=120s
pf_reset

step "5/12  Create the attack path: exposed web ─reaches→ store ─can-read→ secret"
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

step "6/12  SHADOW: chain proves structurally, then corroboration flips it auto-eligible — but NOTHING is applied"
wait_until "structural chain web→session-key" 90 finding_is "structural — propose"
pass "structural chain proven (no foothold, no corroboration)"

post_falco
wait_until "chain flips to auto-eligible after Falco alert" 60 finding_is "auto-eligible"
pass "corroboration on an internet-facing entry meets the asymmetric action bar (no vuln required)"

managed_np_absent || fail "shadow mode applied a NetworkPolicy — propose-only was violated"
pass "shadow mode applied nothing (propose-only honored)"

step "7/12  HARD MODE: enable=network + actuation RBAC; engine quarantines web"
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

step "8/12  SELF-REVERT: remove the durable allow; the chain is no longer provable, so the engine reverts"
kubectl -n "$APP_NS" delete networkpolicy store-ingress
wait_until "engine deletes its managed NetworkPolicy" 120 managed_np_absent
pass "engine reverted its compensating control once the chain stopped being proven (Q5 invariant)"

step "9/10  LOG4J: a proven foothold (exposed + critical CVE) auto-promotes — NO model, NO Falco"
# Minimal trivy VulnerabilityReport CRD (open schema) so the engine's Vulnerability
# port has something to list. (trivy-operator itself isn't needed for the test.)
kubectl apply -f - <<'YAML'
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: vulnerabilityreports.aquasecurity.github.io
spec:
  group: aquasecurity.github.io
  scope: Namespaced
  names: { plural: vulnerabilityreports, singular: vulnerabilityreport, kind: VulnerabilityReport, shortNames: [vulns] }
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          x-kubernetes-preserve-unknown-fields: true
YAML
kubectl wait --for=condition=Established crd/vulnerabilityreports.aquasecurity.github.io --timeout=60s
# A CRITICAL log4shell finding on web's image. The report uses a fully-qualified
# ref (index.docker.io/library/nginx:alpine); the pod used the short `nginx:alpine`.
# Canonical image keying (fix [15]) makes them the SAME Image node, so the CVE
# attaches — otherwise the foothold would never form.
kubectl -n "$APP_NS" apply -f - <<'YAML'
apiVersion: aquasecurity.github.io/v1alpha1
kind: VulnerabilityReport
metadata: { name: web-nginx, namespace: app }
report:
  registry: { server: index.docker.io }
  artifact: { repository: library/nginx, tag: alpine }
  vulnerabilities:
    - { vulnerabilityID: CVE-2021-44228, severity: CRITICAL }
YAML
# Recreate the reaches edge (step 10 deleted it) so web → store → secret is provable.
kubectl -n "$APP_NS" apply -f - <<'YAML'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: store-ingress, namespace: app }
spec:
  podSelector: { matchLabels: { role: store } }
  policyTypes: [Ingress]
  ingress:
    - from: [{ podSelector: { matchLabels: { role: web } } }]
YAML
# Hard mode + judgement, with NO model endpoint: NullAdjudicator confirms (never
# refutes), so the deterministic foothold governs. No Falco event is sent.
helm upgrade protector "$CHART_PATH" --namespace "$NS" --reuse-values \
  --set 'engine.enable=network\,judgement' \
  --set engine.model.endpoint= \
  --wait --timeout 180s
kubectl -n "$NS" rollout status deploy/protector --timeout=120s
pf_reset
wait_until "engine promotes the log4shell foothold and quarantines web" 150 managed_np_present
pass "log4j foothold auto-promoted to a cut — no runtime signal, no model (ADR-0011)"
finding_foothold() {
  curl -fsS localhost:8080/findings 2>/dev/null \
    | jq -e --arg e "$ENTRY" --arg o "$OBJECTIVE" \
        '[.[] | select(.entry==$e and .objective==$o and .foothold==true and .promoted==true
                       and .corroborated==false and .breach_relevant==true
                       and .disposition=="auto-eligible")] | length > 0' \
        >/dev/null 2>&1
}
wait_until "dashboard classifies log4j as a promoted foothold" 30 finding_foothold
pass "dashboard shows log4j foothold auto-eligible (exposed + critical CVE, promoted, model-free)"

step "10/10  SELF-REVERT: remove the durable allow; the chain is no longer provable, engine reverts"
kubectl -n "$APP_NS" delete networkpolicy store-ingress
wait_until "engine reverts the foothold cut" 120 managed_np_absent
pass "engine reverted the foothold control once the chain stopped being proven"

echo
echo "${GREEN}e2e: all phases passed${OFF} — watch loop, graph build, Falco ingest, the runtime-corroborated and deterministic-foothold (log4j) action paths, the isolation actuator, and self-revert all verified against a real API server on the prod CNI."
