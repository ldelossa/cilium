{{/*
Enterprise-only cilium-config entries
*/}}
{{- define "enterprise.cilium-config" }}
# Configuration options to enable overlapping PodCIDR support for clustermesh
{{- /* We additionally fallback to the specific setting used in v1.13-ce for backward compatibility */}}
enable-cluster-aware-addressing: {{ .Values.enterprise.clustermesh.enableOverlappingPodCIDRSupport | default .Values.clustermesh.enableOverlappingPodCIDRSupport | default "false" | quote }}
enable-inter-cluster-snat: {{ .Values.enterprise.clustermesh.enableOverlappingPodCIDRSupport | default .Values.clustermesh.enableOverlappingPodCIDRSupport | default "false" | quote }}
# SRv6 Locator Pool support
srv6-locator-pool-enabled:  {{ .Values.enterprise.srv6.locatorPoolEnabled | default .Values.enterprise.srv6.locatorPoolEnabled | default "false" | quote }}
{{- end }}
