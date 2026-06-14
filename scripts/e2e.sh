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
#                    "auto-eligible", but nothing is applied (shadow).
#   C. hard mode   — enable=network: the engine applies a default-deny
#                    NetworkPolicy quarantining `web`.
#   D. self-revert — remove the durable allow (store-ingress); the chain stops
#                    being provable, so the engine DELETES its NetworkPolicy.
#
# Then the core thesis — proofs WINNOW, the model DECIDES:
#   E. log4j present, NO model — a critical CVE is proven reachable, but presence
#      is not proof of exploitability, so the engine only PROPOSES (no auto-cut).
#   F. log4j + model — the model examines the proven path, judges it EXPLOITABLE,
#      and ONLY THEN does the engine cut. The determination is the model's, not a
#      rule's. (Skipped if no Ollama is reachable; see PROTECTOR_E2E_MODEL.)
#   G. self-revert — the model-driven cut reverts when the chain stops proving.
#
# Requirements: docker, k3d, kubectl, helm, jq, curl. A reachable Ollama for E/F.
# Usage:        scripts/e2e.sh
# Env knobs:    CHART_PATH (default ../cluster/charts/protector)
#               IMAGE      (default protector:e2e — built from this repo)
#               CLUSTER    (default protector-e2e)
#               PROTECTOR_E2E_MODEL / _NAME / _PROBE — the model-decides endpoint
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
# The model that makes the exploitability determination (ADR-0013). k3d pods reach
# the host's Ollama via host.docker.internal (Docker Desktop resolves it inside
# pods; host.k3d.internal only works in the node containers, not pods). Override
# PROTECTOR_E2E_MODEL for a different endpoint (e.g. a Linux bridge gateway IP).
MODEL_NAME="${PROTECTOR_E2E_MODEL_NAME:-ibm/granite4:3b-h}"
MODEL_ENDPOINT="${PROTECTOR_E2E_MODEL:-http://host.docker.internal:11434/v1/chat/completions}"
# Host-side probe (host.k3d.internal is pod-only, so the host checks localhost):
# is an Ollama endpoint actually serving the model? The model phase only runs if
# so (otherwise it's skipped, not failed).
MODEL_PROBE_URL="${PROTECTOR_E2E_MODEL_PROBE:-http://localhost:11434/api/tags}"
model_available() {
  curl -fsS --max-time 5 "$MODEL_PROBE_URL" 2>/dev/null | grep -q "$MODEL_NAME"
}

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
step "1/11  Create k3d cluster (flannel + kube-router, like prod)"
k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
k3d cluster create "$CLUSTER" --wait --timeout 180s
kubectl config use-context "k3d-$CLUSTER" >/dev/null

step "2/11  Build + import the protector image"
docker build -t "$IMAGE" "$(dirname "$0")/.."
k3d image import "$IMAGE" -c "$CLUSTER"

step "3/11  Install cert-manager ($CM_VERSION) — the pod won't start without its serving cert"
kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CM_VERSION}/cert-manager.yaml"
kubectl wait --for=condition=Available -n cert-manager deploy --all --timeout=180s

step "4/11  Deploy protector in SHADOW mode (engine on, no actions, no actuation RBAC)"
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

step "5/11  Create the attack path: exposed web ─reaches→ store ─can-read→ secret"
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

step "6/11  SHADOW: chain proves structurally, then corroboration flips it auto-eligible — but NOTHING is applied"
wait_until "structural chain web→session-key" 90 finding_is "structural — propose"
pass "structural chain proven (no foothold, no corroboration)"

post_falco
wait_until "chain flips to auto-eligible after Falco alert" 60 finding_is "auto-eligible"
pass "corroboration on an internet-facing entry meets the asymmetric action bar (no vuln required)"

managed_np_absent || fail "shadow mode applied a NetworkPolicy — propose-only was violated"
pass "shadow mode applied nothing (propose-only honored)"

step "7/11  HARD MODE: enable=network + actuation RBAC; engine quarantines web"
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

step "8/11  SELF-REVERT: remove the durable allow; the chain is no longer provable, so the engine reverts"
kubectl -n "$APP_NS" delete networkpolicy store-ingress
wait_until "engine deletes its managed NetworkPolicy" 120 managed_np_absent
pass "engine reverted its compensating control once the chain stopped being proven (Q5 invariant)"

step "9/11  LOG4J PRESENT, NO MODEL: a critical CVE on the exposed image is PROVEN reachable — but presence ≠ exploitability, so with no analyst to judge it, the engine only PROPOSES (no auto-cut)"
# Minimal trivy VulnerabilityReport CRD (open schema) so the engine's Vulnerability
# port has something to list. (trivy-operator itself isn't needed for the test —
# we inject the report a real scan would produce.)
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
# Hard mode + judgement, but NO model endpoint. The proof winnows the candidate;
# without an analyst to make the exploitability call, the engine must NOT auto-cut
# on mere CVE presence — the foothold stays a propose-only latent finding.
#
# The helm upgrade replaces the pod, resetting its in-memory runtime store — so the
# Falco corroboration from steps 6-7 is cleared. We recreate the `reaches` edge only
# AFTER the fresh, uncorroborated pod is up, so the chain it proves carries ONLY the
# CVE foothold (no lingering runtime signal that would auto-cut via the veto lane).
helm upgrade protector "$CHART_PATH" --namespace "$NS" --reuse-values \
  --set 'engine.enable=network\,judgement' \
  --set engine.model.endpoint= \
  --wait --timeout 180s
kubectl -n "$NS" rollout status deploy/protector --timeout=120s
pf_reset
# Recreate the reaches edge (step 8 deleted it) so web → store → secret is provable.
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
wait_until "log4j foothold proven but propose-only (no model to judge it)" 150 \
  finding_is "latent foothold — propose"
pass "CVE present + exposed, but with no model the engine PROPOSES — it does not cut"
# Give the reconcile a few cycles; assert it never cuts on mere presence.
sleep 10
managed_np_absent || fail "engine auto-cut on mere CVE presence with no model — the positive-gate is violated"
pass "no NetworkPolicy applied: the model, not a rule, must decide to cut"

if model_available; then
  step "10/11  LOG4J + MODEL: the model examines the proven path, judges log4shell EXPLOITABLE, and the engine cuts — the determination is the model's"
  log "model: $MODEL_NAME @ $MODEL_ENDPOINT"
  # Warm the model so the engine's first judge call doesn't pay the cold-load cost
  # against its 30s HTTP timeout (a freshly-restarted engine judges once per pass).
  log "warming the model (one inference to load it into memory)…"
  curl -fsS --max-time 90 "${MODEL_PROBE_URL%/api/tags}/v1/chat/completions" \
    -H 'content-type: application/json' \
    -d "$(jq -n --arg m "$MODEL_NAME" '{model:$m,messages:[{role:"user",content:"ready? reply ok"}],stream:false}')" \
    >/dev/null 2>&1 || true
  helm upgrade protector "$CHART_PATH" --namespace "$NS" --reuse-values \
    --set engine.model.endpoint="$MODEL_ENDPOINT" \
    --set engine.model.name="$MODEL_NAME" \
    --wait --timeout 180s
  kubectl -n "$NS" rollout status deploy/protector --timeout=120s
  pf_reset
  wait_until "model promotes the exploitable log4shell foothold → engine quarantines web" 180 managed_np_present
  pass "the MODEL decided to cut — its 'exploitable' verdict promoted the foothold (ADR-0011)"
  finding_foothold() {
    curl -fsS localhost:8080/findings 2>/dev/null \
      | jq -e --arg e "$ENTRY" --arg o "$OBJECTIVE" \
          '[.[] | select(.entry==$e and .objective==$o and .foothold==true and .promoted==true
                         and .corroborated==false and .breach_relevant==true
                         and .disposition=="auto-eligible")] | length > 0' \
          >/dev/null 2>&1
  }
  wait_until "dashboard shows the model-promoted foothold" 30 finding_foothold
  pass "dashboard: foothold auto-eligible because the model judged it exploitable"
  # Surface the model's actual verdict + reasoning from the engine logs.
  log "model verdict (from engine logs):"
  kubectl -n "$NS" logs deploy/protector --tail=400 2>/dev/null \
    | grep -i 'adjudicated entry' | tail -2 || true

  step "11/11  SELF-REVERT: remove the durable allow; the chain is no longer provable, engine reverts the model-driven cut"
  kubectl -n "$APP_NS" delete networkpolicy store-ingress
  wait_until "engine reverts the model-driven foothold cut" 120 managed_np_absent
  pass "engine reverted the model-driven control once the chain stopped being proven"
else
  log "${YELLOW}SKIP 10-11/11${OFF}: no model at $MODEL_PROBE_URL serving $MODEL_NAME — start Ollama and re-run to exercise the model-decides path"
fi

echo
echo "${GREEN}e2e: all phases passed${OFF} — watch loop, graph build, Falco ingest, the runtime-corroborated path, the proof-winnows→model-decides foothold path (presence is propose-only; the model's 'exploitable' verdict is what cuts), the isolation actuator, and self-revert all verified against a real API server on the prod CNI."
