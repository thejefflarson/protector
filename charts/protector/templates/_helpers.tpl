{{/* Expand the name of the chart. */}}
{{- define "protector.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fully qualified app name. */}}
{{- define "protector.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "protector.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "protector.labels" -}}
helm.sh/chart: {{ include "protector.chart" . }}
{{ include "protector.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "protector.selectorLabels" -}}
app.kubernetes.io/name: {{ include "protector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
The eBPF agent (ADR-0014) is a distinct workload from the engine, so it gets its
own `app.kubernetes.io/name` — otherwise `kubectl ... -l app.kubernetes.io/name=protector`
selects both and grabs an agent pod when you meant the engine. part-of ties it back
to the release. Selector labels are immutable, so changing them needs a DaemonSet recreate.
*/}}
{{- define "protector.agentSelectorLabels" -}}
app.kubernetes.io/name: {{ include "protector.name" . }}-agent
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "protector.agentLabels" -}}
helm.sh/chart: {{ include "protector.chart" . }}
{{ include "protector.agentSelectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: agent
app.kubernetes.io/part-of: {{ include "protector.name" . }}
{{- end }}

{{- define "protector.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "protector.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the feed-sync workload (CronJob + its dedicated ServiceAccount / Role /
RoleBinding). The feed-sync job is the ONLY component with network egress (JEF-228):
it fetches the public KEV + advisory feeds and upserts the two ConfigMaps the engine
mounts. Its RBAC is scoped to get/update/patch on exactly those two named ConfigMaps —
least privilege — and it never reads or transmits any cluster data outward. The engine
stays zero-egress (ADR-0015): it only mounts the resulting snapshots.
*/}}
{{- define "protector.feedSyncName" -}}
{{- printf "%s-feed-sync" (include "protector.fullname" .) }}
{{- end }}

{{/*
Effective KEV ConfigMap the engine mounts. An explicit engine.kev.configMapName always
wins (the manual-mount path is untouched). Otherwise, when feed-sync is ON (default),
auto-wire the engine to the ConfigMap the job upserts (feedSync.kevConfigMapName) so a
stock install actually feeds the engine. Empty (no auto-wire) only when feed-sync is OFF
and no explicit name is given — the air-gapped/manual path. KEV always has a default
source (feedSync.kevUrl), so it auto-wires whenever feed-sync is enabled.
*/}}
{{- define "protector.kevConfigMapName" -}}
{{- if .Values.engine.kev.configMapName -}}
{{- .Values.engine.kev.configMapName -}}
{{- else if .Values.feedSync.enabled -}}
{{- .Values.feedSync.kevConfigMapName -}}
{{- end -}}
{{- end }}

{{/*
Effective advisory ConfigMap the engine mounts. As with KEV, an explicit
engine.advisory.configMapName always wins. Advisory has NO default source, so it only
auto-wires when feed-sync is ON *and* an advisory source URL is configured
(feedSync.advisoryUrl non-empty) — matching the job, which only upserts the advisory
ConfigMap when advisoryUrl is set. Empty otherwise (no advisory enrichment).
*/}}
{{- define "protector.advisoryConfigMapName" -}}
{{- if .Values.engine.advisory.configMapName -}}
{{- .Values.engine.advisory.configMapName -}}
{{- else if and .Values.feedSync.enabled .Values.feedSync.advisoryUrl -}}
{{- .Values.feedSync.advisoryConfigMapName -}}
{{- end -}}
{{- end }}

{{/* Name of the cert-manager serving Certificate (and its Secret). */}}
{{- define "protector.servingCertName" -}}
{{- printf "%s-tls" (include "protector.fullname" .) }}
{{- end }}

{{/*
Name of the Secret holding the ingest bearer token (Fix A). Prefers a user-supplied
existingSecret; otherwise the chart-provisioned "<release>-ingest-auth".
*/}}
{{- define "protector.ingestSecretName" -}}
{{- if .Values.ingestAuth.existingSecret }}
{{- .Values.ingestAuth.existingSecret }}
{{- else }}
{{- printf "%s-ingest-auth" (include "protector.fullname" .) }}
{{- end }}
{{- end }}
