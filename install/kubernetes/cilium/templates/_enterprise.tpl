{{/*
Enterprise-only cilium-config entries
*/}}
{{- define "enterprise.cilium-config" }}

# Configuration options to enable overlapping PodCIDR support for clustermesh
{{- /* We additionally fallback to the specific setting used in v1.13-ce for backward compatibility */}}
enable-cluster-aware-addressing: {{ .Values.enterprise.clustermesh.enableOverlappingPodCIDRSupport | default .Values.clustermesh.enableOverlappingPodCIDRSupport | default "false" | quote }}
enable-inter-cluster-snat: {{ .Values.enterprise.clustermesh.enableOverlappingPodCIDRSupport | default .Values.clustermesh.enableOverlappingPodCIDRSupport | default "false" | quote }}

# Configuration options to enable SRv6 support
enable-srv6:               {{ .Values.enterprise.srv6.enabled            | default "false"   | quote }}
srv6-encap-mode:           {{ .Values.enterprise.srv6.encapMode          | default "reduced" | quote }}
srv6-locator-pool-enabled: {{ .Values.enterprise.srv6.locatorPoolEnabled | default "false"   | quote }}

{{- if .Values.enterprise.bgpControlPlane.enabled }}
enable-enterprise-bgp-control-plane: "true"
enable-bgp-control-plane: "true"
bgp-secrets-namespace: {{ .Values.enterprise.bgpControlPlane.secretsNamespace.name | quote }}
# Service health-checking integration in BGP control plane
enable-bgp-svc-health-checking: {{ .Values.enterprise.bgpControlPlane.enableServiceHealthChecking | default "false" | quote }}
{{- end }}

# BFD subsystem
enable-bfd: {{ .Values.enterprise.bfd.enabled | default "false" | quote }}

# Configuration options to enable multicast support
multicast-enabled: {{ .Values.enterprise.multicast.enabled | default "false" | quote }}

{{- if .Values.enterprise.ciliummesh.enabled }}
enable-cilium-mesh: "true"
{{- end }}
{{- if .Values.enterprise.egressGatewayHA.enabled }}
enable-ipv4-egress-gateway-ha: "true"
{{- end }}
{{- if hasKey .Values.enterprise.egressGatewayHA "reconciliationTriggerInterval" }}
egress-gateway-ha-reconciliation-trigger-interval: {{ .Values.enterprise.egressGatewayHA.reconciliationTriggerInterval | quote }}
{{- end }}
{{- if .Values.enterprise.egressGatewayHA.maxPolicyEntries }}
egress-gateway-ha-policy-map-max: {{ .Values.enterprise.egressGatewayHA.maxPolicyEntries }}
{{- end }}
{{- if hasKey .Values.enterprise.egressGatewayHA "healthcheckTimeout" }}
egress-gateway-ha-healthcheck-timeout: {{ .Values.enterprise.egressGatewayHA.healthcheckTimeout | quote }}
{{- else if hasKey .Values.egressGateway "healthcheckTimeout" }}
egress-gateway-ha-healthcheck-timeout: {{ .Values.egressGateway.healthcheckTimeout | quote }}
{{- end }}

{{- if .Values.enterprise.clustermesh.mixedRoutingMode.enabled }}
fallback-routing-mode: tunnel
{{- end }}

# Allows Cilium to enable features marked as alpha.
feature-gates: {{ .Values.enterprise.featureGates | join "," | quote }}

{{- if .Values.enterprise.multiNetwork.enabled }}
# Multi-network support
enable-multi-network: {{ .Values.enterprise.multiNetwork.enabled | quote }}
{{- if hasKey .Values.enterprise.multiNetwork "autoDirectNodeRoutes" }}
multi-network-auto-direct-node-routes: {{ .Values.enterprise.multiNetwork.autoDirectNodeRoutes | quote }}
{{- end }}
{{- if hasKey .Values.enterprise.multiNetwork "autoCreateDefaultPodNetwork" }}
auto-create-default-pod-network: {{ .Values.enterprise.multiNetwork.autoCreateDefaultPodNetwork | quote }}
{{- end }}
{{- end }}

{{- if or (not .Values.extraConfig) (not (hasKey .Values.extraConfig "export-file-path"))}}
    # If user did not provide any extraConfig or didn't provide export-file-path, use the default value
    {{- $defaultExportFilePath := "/var/run/cilium/hubble/hubble.log"}}
    {{- if semverCompare ">=1.16" (default "1.16" .Values.upgradeCompatibility)}}
        {{- $defaultExportFilePath = "" }}
    {{- end }}
export-file-path: {{ $defaultExportFilePath | quote }}
  {{- end }}

enable-phantom-services: {{ .Values.enterprise.clustermesh.phantomServices.enabled | quote}}

{{- end }}
