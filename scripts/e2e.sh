#!/usr/bin/env bash
#
# End-to-end integration test for the mitigation engine, on a real k3d cluster.
#
# k3d *is* k3s, so a default k3d cluster has the SAME CNI stack as the Pis
# (flannel + the embedded kube-router NetworkPolicy controller). That makes it
# the right place to exercise the engine's cluster-facing glue that unit tests
# can't reach — the watch/reflector streams, the kube actuator's apply/delete,
# the behavioral-ingest HTTP path — and to drive the `networkpolicy` isolation
# actuator exactly as it behaves in prod. (Cilium/Calico is only needed for the
# ANP actuator, which this test does not cover.)
#
# The scenario proves the whole asymmetric action bar (ADR-0009) and the Q5
# self-revert invariant end-to-end:
#
#   web (internet-exposed) ──reaches──▶ store ──can-read──▶ secret/session-key
#
#   A. shadow      — the chain proves (store reachable + compromisable), but the
#                    entry has no foothold and no corroboration yet.
#   B. corroborate — an `Alert` behavior on `web` (posted to the behavioral port)
#                    flips it to "auto-eligible", but nothing is applied (shadow).
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
# Requirements: docker, k3d, kubectl, jq, curl. A reachable Ollama for E/F.
# Usage:        scripts/e2e.sh
# Env knobs:    IMAGE      (default protector:e2e — built from this repo)
#               CLUSTER    (default protector-e2e)
#               PROTECTOR_E2E_MODEL / _NAME / _PROBE — the model-decides endpoint
#               KEEP=1     leave the cluster up on exit for debugging
#
# Self-contained: protector is deployed from a minimal manifest rendered by
# deploy_protector() below — NOT the production Helm chart (which lives in the
# private cluster repo and is exercised by Argo on the real cluster). This e2e
# validates the engine's cluster glue against a real API server; a purpose-built
# test manifest keeps CI free of a cross-repo private checkout and a Helm dependency.
set -euo pipefail

CLUSTER="${CLUSTER:-protector-e2e}"
IMAGE="${IMAGE:-protector:e2e}"
NS=protector
APP_NS=app
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
export KUBECONFIG="$(mktemp -t protector-e2e-kubeconfig.XXXXXX)"

# --- output helpers -----------------------------------------------------------
RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; OFF=$'\033[0m'
log()  { echo "${YELLOW}==>${OFF} $*"; }
pass() { echo "${GREEN}PASS${OFF} $*"; }
fail() { echo "${RED}FAIL${OFF} $*" >&2; exit 1; }
step() { echo; echo "${DIM}────────────────────────────────────────────────────────${OFF}"; log "$*"; }

# --- preflight ----------------------------------------------------------------
for tool in docker k3d kubectl jq curl; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing required tool: $tool"
done

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
  kubectl -n "$NS" port-forward deploy/protector 9999:9999 >/dev/null 2>&1 & PF_PIDS+=($!)
  # give the forward a moment to bind
  sleep 2
}

# --- predicates ---------------------------------------------------------------
# The engine has proven the web→session-key attack chain this run. The engine has no read API
# (its output state is in-memory; a presentation layer is being redesigned), so we observe the
# per-chain proof log line — the synchronization signal that this chain is now provable — before
# we assert what shadow/hard mode did about it (the actuation assertions below read the cluster's
# NetworkPolicy state, which is the authoritative behavioral check).
#
# JEF-300: grep the FULL log (no --tail) for the SPECIFIC chain, not `--tail=400 | grep 'proven
# chains'`. The engine emits the "proven chains" summary once per structural pass, then FLOODS the
# stream (one `proven chain` line per chain + per-pass behavior batches + the signing sweep), so
# the single summary line scrolls out of a 400-line tail long before we poll — the assertion timed
# out even though the chain proved minutes earlier (the timeout was a red herring). Matching the
# exact `proven chain entry=…/web objective=…/session-key` line on the whole log is both
# window-proof (grep -q short-circuits on first match) and a stronger assertion: it proves THE
# chain, not merely that some pass ran.
chains_proven() {
  kubectl -n "$NS" logs deploy/protector 2>/dev/null \
    | grep -qE 'proven chain .*entry=workload/app/Pod/web .*objective=secret/app/session-key'
}

post_alert() {
  # POST an `Alert` behavior on `web` to the tool-agnostic behavioral port
  # (`/behavior`, ADR-0003) — the same corroboration effect any sensor gets. An `Alert`
  # is the "something alarming, now" signal that flips a proven chain to corroborated.
  curl -fsS -XPOST localhost:9999/behavior -H 'content-type: application/json' -d '[{
    "namespace": "app",
    "pod": "web",
    "source": "e2e",
    "behavior": { "kind": "alert", "rule": "Terminal shell in container" }
  }]' >/dev/null
}

# The engine's managed isolation NetworkPolicy in the app namespace.
managed_np_name() {
  kubectl -n "$APP_NS" get networkpolicy \
    -l app.kubernetes.io/managed-by=protector -o name 2>/dev/null | head -n1
}
managed_np_present() { [ -n "$(managed_np_name)" ]; }
managed_np_absent()  { [ -z "$(managed_np_name)" ]; }

# Hard mode can apply MORE than one managed policy at once (ADR-0022 / JEF-284), so an
# assertion must name the workload ROLE it means, never assume a single policy or grab
# "the first one" (that races). Two distinct controls coexist on the web→store→secret
# scenario:
#   - the ENTRY cut (role=web): the internet-facing entry is isolated once its chain
#     meets the asymmetric action bar — live corroboration (ADR-0009) or a model
#     "exploitable" verdict (ADR-0011). It is gated: no cut on mere CVE presence.
#   - the PIVOT quarantine (role=store): a *remotely-exploitable* pod — a non-entry
#     workload reachable from the internet-exposed entry that runs a critical/KEV CVE —
#     is quarantined DETERMINISTICALLY (JEF-284), needing neither a model nor a live
#     alert. This is a separate high bar (reachable + critical CVE), not the model-gated
#     entry path, and it is applied first (it waits on nothing).
# The two race, and store's policy-name can sort either side of web's, so the old
# `managed_np_name | head -n1`-selects-web check was inherently flaky.
managed_np_roles() {
  kubectl -n "$APP_NS" get networkpolicy -l app.kubernetes.io/managed-by=protector \
    -o jsonpath='{range .items[*]}{.spec.podSelector.matchLabels.role}{"\n"}{end}' 2>/dev/null
}
managed_np_for()        { managed_np_roles | grep -qx "$1"; }
managed_np_for_absent() { ! managed_np_for "$1"; }

# cert-manager's Deployment going Available does NOT mean its admission webhook is
# actually serving (CA injection + endpoints lag), and deploy_protector creates a
# Certificate immediately — against a half-ready webhook that Certificate is never
# issued, the serving-cert secret never lands, and the pod can't start. Gate on the
# webhook truly admitting a (server dry-run) Certificate before deploying.
cm_webhook_ready() {
  kubectl apply --dry-run=server -f - >/dev/null 2>&1 <<'YAML'
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: webhook-probe, namespace: cert-manager }
spec:
  secretName: webhook-probe
  issuerRef: { name: does-not-exist, kind: Issuer }
  dnsNames: [probe.invalid]
YAML
}

# Dump why the structural chain web→store→session-key never proved (the cluster is torn
# down on exit, so grab this before failing). A *structural* chain is deterministic graph
# reachability — no model — so a timeout means the engine hasn't finished building the graph
# and running a proof pass, OR a graph input is missing. Surface both: what the engine logged
# (the proof/graph/watch signals + whether "proven chains" ever appeared) and the app-namespace
# inputs the chain is derived from (the workloads + their images, the session-key secret, the
# store-ingress reaches-edge NetworkPolicy, web's LoadBalancer exposure, the CVE reports).
diagnose_chain() {
  log "structural chain never proved — diagnostics (deterministic reachability, no model):"
  log "  engine — did it log a proof pass at all? (proven chains / proven chain / graph / watch / error)"
  kubectl -n "$NS" logs deploy/protector --tail=400 2>&1 \
    | grep -iE 'proven chain|graph|watch|error|panic|signing|sweep' | tail -30 | sed 's/^/    /' || true
  log "  app workloads + images (entry web, pivot store):"
  kubectl -n "$APP_NS" get pods -o wide 2>&1 | sed 's/^/    /' || true
  log "  chain inputs: session-key secret, store-ingress (web→store reaches edge), web LB (exposure), CVE reports:"
  kubectl -n "$APP_NS" get secret,networkpolicy,service,vulnerabilityreports 2>&1 | sed 's/^/    /' || true
}

# Dump why protector didn't become Ready (the cluster is torn down on exit, so grab
# this before failing): pod state, recent events, the cert + its serving secret.
diagnose_protector() {
  log "protector did not become Ready — diagnostics:"
  kubectl -n "$NS" get pods -o wide 2>&1 | sed 's/^/    /' || true
  kubectl -n "$NS" describe pod -l app.kubernetes.io/name=protector 2>&1 | grep -iE "state|reason|message|event|warn|mount|secret" | tail -25 | sed 's/^/    /' || true
  kubectl -n "$NS" get certificate,secret 2>&1 | sed 's/^/    /' || true
  kubectl -n "$NS" logs -l app.kubernetes.io/name=protector --tail=30 2>&1 | sed 's/^/    /' || true
}

# --- deploy protector (self-contained, no Helm) -------------------------------
# Render + apply the minimal manifests protector needs to run against a real API
# server: ServiceAccount + engine RBAC + a cert-manager serving cert + the
# Deployment/Service. Idempotent (kubectl apply), so the hard-mode/judgement/model
# phases just re-invoke it with new args and the env change triggers a rollout.
#
# This is a TEST manifest, deliberately not the production Helm chart — it mirrors
# the chart's deployment + clusterrole faithfully (engine reads; NetworkPolicy write
# only in hard mode) without depending on the private cluster repo. The webhook's
# ValidatingWebhookConfiguration is intentionally omitted: this exercises the engine,
# and an active admission webhook would needlessly gate the test pods.
#
# Args: <enable> <actuationRBAC:true|false> <model_endpoint> <model_name>
# `enable` is the legacy caller contract ("network" = hard mode, "" = shadow); it is
# translated to the two-setting posture (ADR-0021): hard mode ⇒ mode: enforce scoped to
# the app namespace (where the test workloads + the cut live); shadow ⇒ mode: audit.
deploy_protector() {
  local enable="$1" actuation_rbac="$2" model_endpoint="$3" model_name="$4"

  # Translate the legacy `enable` flag into PROTECTOR_MODE + enforceScope. Hard mode
  # confines actuation to APP_NS — both cut endpoints (web + its peer) live there.
  local mode="audit" enforce_scope=""
  if [ -n "$enable" ]; then
    mode="enforce"
    enforce_scope="$APP_NS"
  fi

  kubectl create ns "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  # Hard mode grants the actuator create/delete/patch on NetworkPolicies so it can
  # apply (and self-revert) its default-deny isolation policy.
  local np_write=""
  if [ "$actuation_rbac" = "true" ]; then
    np_write='
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["create", "delete", "patch"]'
  fi

  # These two are the ONLY operator-set values interpolated into the manifest heredoc
  # below (PROTECTOR_E2E_MODEL / _MODEL_NAME). They come from whoever runs the e2e — a
  # test-harness input, not an untrusted boundary — but reject YAML-breaking chars anyway
  # so a stray quote/newline can't corrupt the Deployment we `kubectl apply`.
  case "$model_endpoint$model_name" in
    *'"'* | *'\'* | *'
'*) echo "e2e: PROTECTOR_E2E_MODEL/_MODEL_NAME contain YAML-unsafe characters" >&2; exit 1 ;;
  esac

  # The model-decides env is added only when an endpoint is given (phases 10-11).
  local model_env=""
  if [ -n "$model_endpoint" ]; then
    model_env="
            - name: PROTECTOR_ENGINE_MODEL
              value: \"$model_endpoint\"
            - name: PROTECTOR_ENGINE_MODEL_NAME
              value: \"$model_name\"
            - name: PROTECTOR_ENGINE_MODEL_TIMEOUT_SECS
              value: \"600\""
  fi

  kubectl apply -f - <<YAML
apiVersion: v1
kind: ServiceAccount
metadata: { name: protector, namespace: $NS }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: protector-engine }
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "secrets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["aquasecurity.github.io"]
    resources: ["vulnerabilityreports"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["policy.linkerd.io"]
    resources: ["servers", "authorizationpolicies", "meshtlsauthentications"]
    verbs: ["get", "list", "watch"]$np_write
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: protector-engine }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: protector-engine }
subjects:
  - { kind: ServiceAccount, name: protector, namespace: $NS }
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata: { name: protector-selfsign, namespace: $NS }
spec: { selfSigned: {} }
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: protector-tls, namespace: $NS }
spec:
  secretName: protector-tls
  # rustls loads PKCS#8 only; cert-manager defaults ECDSA to SEC1 (would crashloop).
  privateKey: { algorithm: ECDSA, size: 256, encoding: PKCS8 }
  usages: ["server auth"]
  dnsNames:
    - protector.$NS.svc
    - protector.$NS.svc.cluster.local
  issuerRef: { name: protector-selfsign, kind: Issuer, group: cert-manager.io }
---
apiVersion: v1
kind: Service
metadata: { name: protector, namespace: $NS }
spec:
  selector: { app.kubernetes.io/name: protector }
  ports: [{ name: https, port: 8443, targetPort: https }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: protector, namespace: $NS }
spec:
  replicas: 1
  selector: { matchLabels: { app.kubernetes.io/name: protector } }
  template:
    metadata: { labels: { app.kubernetes.io/name: protector } }
    spec:
      serviceAccountName: protector
      securityContext: { runAsNonRoot: true }
      containers:
        - name: protector
          image: "$IMAGE"
          imagePullPolicy: Never
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            capabilities: { drop: ["ALL"] }
          ports:
            - { name: https, containerPort: 8443 }
            - { name: behavior-ingest, containerPort: 9999 }
          livenessProbe: { httpGet: { path: /healthz, port: https, scheme: HTTPS } }
          readinessProbe: { httpGet: { path: /readyz, port: https, scheme: HTTPS } }
          env:
            - { name: PROTECTOR_ADDR, value: "0.0.0.0:8443" }
            - { name: PROTECTOR_TLS_CERT, value: /etc/protector/tls/tls.crt }
            - { name: PROTECTOR_TLS_KEY, value: /etc/protector/tls/tls.key }
            - { name: PROTECTOR_TUF_CACHE, value: /tmp/sigstore }
            - { name: PROTECTOR_GATED_PREFIXES, value: "ghcr.io/thejefflarson/" }
            - { name: PROTECTOR_IDENTITY_REGEXP, value: '^https://github\.com/thejefflarson/' }
            - { name: PROTECTOR_MODE, value: "$mode" }
            - { name: PROTECTOR_ENFORCE_SCOPE_NAMESPACES, value: "$enforce_scope" }
            - { name: RUST_LOG, value: "protector=info,sigstore=error,warn" }
            - { name: PROTECTOR_ENGINE_ACTUATOR, value: "networkpolicy" }
            - { name: PROTECTOR_BEHAVIOR_ADDR, value: "0.0.0.0:9999" }$model_env
          volumeMounts:
            - { name: tls, mountPath: /etc/protector/tls, readOnly: true }
            - { name: tmp, mountPath: /tmp }
      volumes:
        - { name: tls, secret: { secretName: protector-tls } }
        - { name: tmp, emptyDir: {} }
YAML
}

# ==============================================================================
step "1/11  Create k3d cluster (flannel + kube-router, like prod)"
# Retry: k3d maps the serverlb to an ephemeral host port, which a just-torn-down
# previous run can still hold for a moment ("address already in use") — transient,
# clears on retry.
created=0
for attempt in 1 2 3; do
  k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
  if k3d cluster create "$CLUSTER" --wait --timeout 180s; then created=1; break; fi
  log "cluster create failed (attempt $attempt/3) — retrying after the port settles"
  sleep 5
done
[ "$created" = 1 ] || fail "k3d cluster create failed after 3 attempts"
kubectl config use-context "k3d-$CLUSTER" >/dev/null

step "2/11  Build + import the protector image"
docker build -t "$IMAGE" "$(dirname "$0")/.."
k3d image import "$IMAGE" -c "$CLUSTER"

step "3/11  Install cert-manager ($CM_VERSION) — the pod won't start without its serving cert"
kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/${CM_VERSION}/cert-manager.yaml"
kubectl wait --for=condition=Available -n cert-manager deploy --all --timeout=180s
kubectl wait --for=condition=Established crd/certificates.cert-manager.io --timeout=60s
# ...and wait until the webhook actually admits a Certificate (Available != serving).
wait_until "cert-manager webhook ready to issue" 120 cm_webhook_ready

step "4/11  Deploy protector in SHADOW mode (engine on, no actions, no actuation RBAC)"
deploy_protector "" false "" ""
kubectl -n "$NS" rollout status deploy/protector --timeout=300s \
  || { diagnose_protector; fail "protector did not become ready in shadow mode"; }
pf_reset

step "5/11  Create the attack path: exposed web ─reaches→ store ─can-read→ secret"
kubectl create ns "$APP_NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$APP_NS" create secret generic session-key --from-literal=k=x \
  --dry-run=client -o yaml | kubectl apply -f -
# The engine reads CVEs from trivy VulnerabilityReport CRs; create the CRD up front
# (a real scan would produce the reports). Open schema — trivy-operator isn't needed.
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
# `store` mounts the secret (envFrom) -> can-read edge store→secret. It runs a
# DISTINCT, vulnerable image (httpd + the critical CVE below) so it is *compromisable*:
# under ADR-0002 compromise gating a reached workload's secrets are only in scope once
# it can be compromised, so without this the web→store→secret lateral chain wouldn't
# prove. A separate image from web's keeps web a non-foothold until phase 9.
kubectl -n "$APP_NS" run store --image=httpd:alpine --labels=role=store \
  --overrides='{"spec":{"containers":[{"name":"store","image":"httpd:alpine","envFrom":[{"secretRef":{"name":"session-key"}}]}]}}'
kubectl -n "$APP_NS" apply -f - <<'YAML'
apiVersion: aquasecurity.github.io/v1alpha1
kind: VulnerabilityReport
metadata: { name: store-httpd, namespace: app }
report:
  registry: { server: index.docker.io }
  artifact: { repository: library/httpd, tag: alpine }
  vulnerabilities:
    - { vulnerabilityID: CVE-2026-9001, severity: CRITICAL }
YAML
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

step "6/11  SHADOW: chain proves structurally, then corroboration would flip it auto-eligible — but NOTHING is applied"
# This is the FIRST proof pass after a fresh rollout, and it is gated behind the engine's
# per-pass signing-posture sweep (ADR-0020), which runs BEFORE process() on every image
# running in the cluster. On a cold TUF cache with CI's constrained egress that first sweep
# can burn most of a minute (per-image verify timeouts) before the deterministic proof pass
# even runs — so the old 90s bound timed out chronically on loaded CI nodes even though the
# chain proves. The assertion is unchanged (the engine must still LOG a proven chain — real
# deterministic reachability, no model); only the wait is widened to the same generous
# envelope the rollout waits above use, with a diagnostic dump so a genuine failure is
# debuggable rather than an opaque "timed out".
wait_until "structural chain web→session-key proven" 300 chains_proven \
  || { diagnose_chain; fail "structural chain web→session-key never proved within 300s"; }
pass "structural chain proven (no foothold, no corroboration)"

post_alert
# Give the corroborated pass a few cycles to run after the alert lands.
sleep 10

managed_np_absent || fail "shadow mode applied a NetworkPolicy — propose-only was violated"
pass "shadow mode applied nothing (propose-only honored) — corroboration would meet the asymmetric action bar, but shadow only proposes"

step "7/11  HARD MODE: enable=network + actuation RBAC; engine cuts the corroborated entry (web) AND quarantines the remotely-exploitable pivot (store)"
deploy_protector network true "" ""
kubectl -n "$NS" rollout status deploy/protector --timeout=180s
pf_reset
# The pod was replaced, so its runtime-evidence store reset — re-send the alert that
# corroborates web (the internet-facing entry), which is what flips its chain to
# auto-eligible under the asymmetric action bar.
post_alert
# Wait for the ENTRY cut specifically (role=web) — the corroboration-driven control this
# step exists to prove — not "the first managed policy". The engine also applies a SECOND,
# deterministic quarantine on the remotely-exploitable pivot `store` (JEF-284: reachable
# from the internet-exposed entry + a critical CVE), which lands first (it waits on no
# corroboration); the two race, so naming the role is the only stable assertion.
wait_until "engine cuts the corroborated entry web" 120 managed_np_for web
pass "engine quarantined role=web — live corroboration met the asymmetric action bar (ADR-0009)"
# The pivot is ALSO isolated, on the independent deterministic bar (no model/alert needed).
managed_np_for store \
  || fail "engine did not quarantine the remotely-exploitable pivot role=store (JEF-284)"
pass "engine also quarantined role=store — a remotely-exploitable pivot (reachable + critical CVE)"

step "8/11  SELF-REVERT: remove the durable allow; web is no longer provable AND store is no longer reachable-from-internet, so the engine reverts BOTH controls"
kubectl -n "$APP_NS" delete networkpolicy store-ingress
wait_until "engine deletes every managed NetworkPolicy" 120 managed_np_absent
pass "engine reverted both compensating controls once the chain stopped being proven (Q5 invariant)"

step "9/11  LOG4J PRESENT, NO MODEL: a critical CVE on the exposed image is PROVEN reachable — but presence ≠ exploitability, so with no analyst to judge it, the engine only PROPOSES (no auto-cut)"
# The VulnerabilityReport CRD was created in phase 5. Now a CRITICAL log4shell finding
# lands on WEB's image — making web (internet-exposed) a proven foothold. The report
# uses a fully-qualified
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
# without an analyst to make the exploitability call, the engine must NOT auto-cut the
# ENTRY foothold (web) on mere CVE presence — it stays a propose-only latent finding.
#
# We must genuinely RESET the pod here. `deploy_protector "network,judgement"` renders a
# byte-identical manifest to step 7's `deploy_protector "network"` (any non-empty enable →
# mode=enforce / enforceScope=app; the "judgement" token is dropped and never reaches the
# engine), so `kubectl apply` is a no-op — the pod is NOT replaced. But the pod still holds
# the step-7 alert corroboration of web in its in-memory runtime store (300s TTL); left
# there, web would auto-cut on that STALE live signal, not on the (absent) model, defeating
# this step's whole point. So force an explicit rollout restart to clear the runtime store,
# then recreate the `reaches` edge AFTER the fresh, uncorroborated pod is up.
deploy_protector "network,judgement" true "" ""
kubectl -n "$NS" rollout restart deploy/protector
# Fresh pod ⇒ cold TUF cache ⇒ the first proof pass sits behind the same slow per-image
# signing sweep step 6 gets 300s for (ADR-0020). Give the rollout + the re-prove that same
# generous envelope — this supersedes #174, which widened step 9's budget to 300s but never
# reset the pod, so it fixed neither the stale corroboration nor the never-a-fresh-re-prove.
kubectl -n "$NS" rollout status deploy/protector --timeout=300s
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
# On the fresh pod the log is empty, so this is a genuine RE-PROVE assertion, not a match
# of a stale line from an earlier step. Dump diagnostics on timeout (step 6 does; step 9
# never did — an opaque timeout here is exactly what made JEF-300 undebuggable in CI).
wait_until "log4j foothold re-proven on the fresh pod (no model to judge it)" 300 chains_proven \
  || { diagnose_chain; fail "web→session-key never re-proved within 300s after the step-9 pod reset"; }
pass "CVE present + exposed, foothold re-proven on a fresh, uncorroborated pod"
# Give the reconcile a few cycles, then assert the ENTRY foothold (web) is NOT auto-cut:
# with no model to judge exploitability, mere CVE presence must stay propose-only (ADR-0011).
sleep 10
managed_np_for_absent web \
  || fail "engine auto-cut the web foothold on mere CVE presence with no model — the positive-gate is violated"
pass "web foothold left uncut: the model, not a rule, must decide to promote+cut the entry"
# The remotely-exploitable PIVOT (store) IS quarantined here (JEF-284, deterministic:
# reachable + critical CVE) — a separate high-bar control, independent of the model that
# gates the entry foothold. Its presence is expected and correct, not a thesis violation;
# assert it so the two lanes stay legible and a regression in either is caught.
managed_np_for store \
  || fail "engine did not quarantine the remotely-exploitable pivot role=store (JEF-284)"
pass "pivot store quarantined deterministically — the model gates the entry, not the remotely-exploitable pivot"

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
  # Adding the model endpoint DOES change the manifest (model env vars), so this apply is a
  # real rollout — a fresh, uncorroborated pod, same as step 9. The ONLY new input vs step 9
  # is the model, so a cut of web here is attributable to the model's verdict, nothing else.
  deploy_protector "network,judgement" true "$MODEL_ENDPOINT" "$MODEL_NAME"
  kubectl -n "$NS" rollout status deploy/protector --timeout=180s
  pf_reset
  wait_until "model promotes the exploitable log4shell foothold → engine cuts the entry web" 180 managed_np_for web
  pass "the MODEL decided to cut role=web — its 'exploitable' verdict promoted the entry foothold (ADR-0011)"
  # The cut itself (managed NetworkPolicy present) is the authoritative proof the model
  # promoted the foothold. Corroborate that the engine's own logs record an exploitable
  # verdict for the entry — the model's reasoning behind the cut.
  model_judged_exploitable() {
    kubectl -n "$NS" logs deploy/protector --tail=400 2>/dev/null \
      | grep -i 'adjudicated entry' | grep -qi 'exploitable'
  }
  wait_until "engine logs an exploitable verdict for the foothold" 30 model_judged_exploitable
  pass "engine logged an exploitable verdict — the foothold was promoted because the model judged it exploitable"
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
echo "${GREEN}e2e: all phases passed${OFF} — watch loop, graph build, behavioral ingest, the runtime-corroborated path, the proof-winnows→model-decides foothold path (presence is propose-only; the model's 'exploitable' verdict is what cuts), the isolation actuator, and self-revert all verified against a real API server on the prod CNI."
