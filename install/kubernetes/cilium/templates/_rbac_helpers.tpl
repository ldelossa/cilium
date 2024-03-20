{{- define "container.rbac.name" -}}
{{- "rbac" -}}
{{- end }}

{{- define "container.rbac" -}}
{{- if not .Values.hubble.tls.enabled }}
{{- fail "Hubble RBAC requires Hubble TLS (.Values.hubble.tls.enabled=true)" }}
{{- end }}
name: {{ include "container.rbac.name" . }}
image: {{ include "cilium.image" .Values.hubble.rbac.image | quote }}
imagePullPolicy: {{ .Values.hubble.rbac.pullPolicy }}
terminationMessagePolicy: FallbackToLogsOnError
securityContext:
  {{- toYaml .Values.hubble.rbac.securityContext | nindent 4 }}
resources:
  {{- toYaml .Values.hubble.rbac.resources | nindent 4 }}
command:
  - /usr/bin/hubble-rbac
args:
  - --logging-level={{ .Values.hubble.rbac.loggingLevel }}
  - --hubble-policy-mode=config
  - --hubble-policy-file=/etc/hubble-rbac/policy/{{ .Values.hubble.rbac.policy.configMap.key }}
  - --hubble-policy-log-roles={{ .Values.hubble.rbac.policy.logRoles }}
  - --hubble-listen-address=0.0.0.0:{{ .Values.hubble.rbac.listenPort }}
  - --hubble-local-server={{ include "hubble-relay.config.listenAddress" . }}
  - --hubble-auth=oidc
  - --hubble-oidc-url={{ .Values.hubble.rbac.auth.oidc.issuerUrl | required "hubble.rbac.auth.oidc.issuerUrl is required" }}
  - --hubble-oidc-client-id={{ .Values.hubble.rbac.auth.oidc.clientID | required "hubble.rbac.auth.oidc.clientID is required" }}
  - --hubble-tls-cert=/etc/hubble-rbac/tls/server.crt
  - --hubble-tls-key=/etc/hubble-rbac/tls/server.key
  {{- if .Values.hubble.rbac.auth.oidc.ca.configMap.name }}
  - --hubble-oidc-ca=/etc/hubble-rbac/tls/oidc/hubble-oidc-provider-ca.pem
  {{- end }}
ports:
  - name: grpc-rbac
    containerPort: {{ .Values.hubble.rbac.listenPort }}
volumeMounts:
  {{- if eq .Values.hubble.rbac.policy.mode "configMap" }}
  - name: hubble-rbac-policy
    mountPath: /etc/hubble-rbac/policy
    readOnly: true
  {{- end }}
  - mountPath: /etc/hubble-rbac/tls
    name: tls
    readOnly: true
  {{- if .Values.hubble.rbac.auth.oidc.ca.configMap.name }}
  - mountPath: /etc/hubble-rbac/tls/oidc
    name: hubble-rbac-tls-oidc
    readOnly: true
  {{- end }}
readinessProbe:
  {{- include "container.rbac.probe" . | nindent 4 }}
{{- end -}}

{{- define "container.rbac.probe" -}}
exec:
  command:
  - /usr/bin/grpc_health_probe
  - -addr=localhost:{{ .Values.hubble.rbac.listenPort }}
  - -tls
  - -tls-no-verify
{{- end }}
