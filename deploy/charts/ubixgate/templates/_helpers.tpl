{{/* Chart name, overridable. */}}
{{- define "ubixgate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "ubixgate.fullname" -}}
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

{{- define "ubixgate.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ubixgate.labels" -}}
helm.sh/chart: {{ include "ubixgate.chart" . }}
{{ include "ubixgate.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "ubixgate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ubixgate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* ServiceAccount name to use. */}}
{{- define "ubixgate.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "ubixgate.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Image reference; the tag defaults to the chart's appVersion. */}}
{{- define "ubixgate.image" -}}
{{- $repo := required "image.repository is required: no official image is published yet, so build the Dockerfile and push it to your registry" .Values.image.repository -}}
{{- printf "%s:%s" $repo (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}

{{/* The config file as rendered into the ConfigMap; listen always follows containerPort. */}}
{{- define "ubixgate.configYAML" -}}
{{- if not .Values.config.public_url -}}
{{- fail "config.public_url is required (the full MCP endpoint URL and token audience), or set existingConfigMap" -}}
{{- end -}}
{{- $cfg := merge (dict "listen" (printf ":%v" .Values.containerPort)) (deepCopy .Values.config) -}}
{{- toYaml $cfg -}}
{{- end -}}

{{- define "ubixgate.configMapName" -}}
{{- default (include "ubixgate.fullname" .) .Values.existingConfigMap -}}
{{- end -}}

{{/* Ingress host and MCP path: explicit values, else taken from config.public_url. */}}
{{- define "ubixgate.ingressHost" -}}
{{- if .Values.ingress.host -}}
{{- .Values.ingress.host -}}
{{- else if .Values.config.public_url -}}
{{- (urlParse .Values.config.public_url).hostname -}}
{{- end -}}
{{- end -}}

{{- define "ubixgate.ingressPath" -}}
{{- if .Values.ingress.path -}}
{{- .Values.ingress.path -}}
{{- else if .Values.config.public_url -}}
{{- (urlParse .Values.config.public_url).path | default "/" -}}
{{- end -}}
{{- end -}}
