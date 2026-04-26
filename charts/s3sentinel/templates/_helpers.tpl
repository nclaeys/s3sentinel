{{/*
Expand the name of the chart.
*/}}
{{- define "s3sentinel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "s3sentinel.fullname" -}}
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

{{/*
Create chart label.
*/}}
{{- define "s3sentinel.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "s3sentinel.labels" -}}
helm.sh/chart: {{ include "s3sentinel.chart" . }}
{{ include "s3sentinel.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "s3sentinel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "s3sentinel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "s3sentinel.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "s3sentinel.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the secret holding backend credentials.
*/}}
{{- define "s3sentinel.backendSecretName" -}}
{{- if .Values.backend.existingSecret }}
{{- .Values.backend.existingSecret }}
{{- else }}
{{- include "s3sentinel.fullname" . }}-backend
{{- end }}
{{- end }}

{{/*
Name of the secret holding STS token secret.
*/}}
{{- define "s3sentinel.stsSecretName" -}}
{{- if .Values.sts.existingSecret }}
{{- .Values.sts.existingSecret }}
{{- else }}
{{- include "s3sentinel.fullname" . }}-sts
{{- end }}
{{- end }}

{{/*
Whether STS is enabled.
*/}}
{{- define "s3sentinel.stsEnabled" -}}
{{- if or .Values.sts.tokenSecret .Values.sts.existingSecret }}true{{- end }}
{{- end }}
