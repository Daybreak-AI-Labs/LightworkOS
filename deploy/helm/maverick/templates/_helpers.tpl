{{- define "maverick.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "maverick.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "maverick.labels" -}}
app.kubernetes.io/name: {{ include "maverick.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{- define "maverick.selectorLabels" -}}
app.kubernetes.io/name: {{ include "maverick.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "maverick.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{- define "maverick.secretName" -}}
{{- default (printf "%s-secrets" (include "maverick.fullname" .)) .Values.secret.name -}}
{{- end -}}

{{/*
The dashboard/serve process still owns durable file-backed control-plane state
outside the world model (flow releases/runs, A2A task claims, audit/learning
ledgers, and tenant-local policy files). Postgres makes the world model safe to
share, but it does not make those stores replica-safe. Refuse a topology that
could split approval/idempotency authority across pods. Scale remote workers
separately until every control-plane store has a shared transactional backend.
*/}}
{{- define "maverick.validate" -}}
{{- if not .Values.persistence.enabled -}}
{{- fail "persistence.enabled must be true: approval records, external-operation reconciliation, flow versions, audit and credential state remain local even with Postgres." -}}
{{- end -}}
{{- if ne .Values.persistence.mountPath "/home/maverick/.maverick" -}}
{{- fail "persistence.mountPath must be /home/maverick/.maverick so every durable control-plane store uses the mounted state volume." -}}
{{- end -}}
{{- if hasKey .Values.env "MAVERICK_HOME" -}}
{{- if ne (toString .Values.env.MAVERICK_HOME) .Values.persistence.mountPath -}}
{{- fail "env.MAVERICK_HOME must match persistence.mountPath." -}}
{{- end -}}
{{- end -}}
{{- if gt (int .Values.replicaCount) 1 -}}
{{- fail "replicaCount > 1 is not supported for the Lightwork control plane: Postgres centralizes the world model, but flows, A2A idempotency, audit, and learning state remain tenant-local. Run one dashboard/serve replica and scale remote workers separately." -}}
{{- end -}}
{{- if .Values.autoscaling.enabled -}}
{{- fail "autoscaling.enabled is not supported for the Lightwork control plane until all durable flow/A2A/audit/learning stores are shared transactionally. Run one dashboard/serve replica and scale remote workers separately." -}}
{{- end -}}
{{- end -}}
