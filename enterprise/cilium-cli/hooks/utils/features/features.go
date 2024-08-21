//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package features

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/sysdump"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/versioncheck"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	enterpriseDefaults "github.com/isovalent/cilium/enterprise/cilium-cli/defaults"
)

const (
	CiliumDNSProxyHA features.Feature = "cilium-dnsproxy-ha"

	EgressGatewayHA features.Feature = "enable-ipv4-egress-gateway-ha"

	SRv6            features.Feature = "enable-srv6"
	SRv6LocatorPool features.Feature = "srv6-locator-pool-enabled"

	Multicast features.Feature = "multicast"

	EnterpriseBGPControlPlane features.Feature = "enable-enterprise-bgp-control-plane"
	BFD                       features.Feature = "enable-bfd"

	// RemoteClusterTunnel: the routing mode configured in the remote cluster.
	RemoteClusterTunnel features.Feature = "remote-cluster-tunnel"
	// FallbackRoutingMode: whether a (and which) fallback routing mode is configured.
	FallbackRoutingMode features.Feature = "fallback-routing-mode"
	// MixedRoutingMode: whether local and remote clusters have different routing modes.
	MixedRoutingMode features.Feature = "mixed-routing-mode"
)

func Detect(ctx context.Context, ct *check.ConnectivityTest) error {
	err := extractFromConfigMap(ctx, ct)
	if err != nil {
		return err
	}

	err = extractFromRemoteConfigMap(ctx, ct)
	if err != nil {
		return err
	}

	// Only check whether the cilium-dnsproxy DaemonSet is deployed if the feature is enabled in
	// the ConfigMap.
	if ct.Features[CiliumDNSProxyHA].Enabled {
		err = extractExternalDNSProxyFeature(ctx, ct)
		if err != nil {
			return fmt.Errorf("failed to extract feature %s: %w", CiliumDNSProxyHA, err)
		}
	}

	return nil
}

func extractExternalDNSProxyFeature(ctx context.Context, ct *check.ConnectivityTest) error {
	for _, client := range ct.Clients() {
		// cilium-dnsproxy pods are labelled with `k8s-app=ciliumdns-proxy`, let's filter on it.
		ciliumDNSProxyLabelSelector := fmt.Sprintf("k8s-app=%s", enterpriseDefaults.ExternalCiliumDNSProxyName)
		pods, err := client.ListPods(ctx, ct.Params().CiliumNamespace, metav1.ListOptions{LabelSelector: ciliumDNSProxyLabelSelector})
		if err != nil {
			return fmt.Errorf("unable to list %s pods: %w", enterpriseDefaults.ExternalCiliumDNSProxyName, err)
		}

		if len(pods.Items) == 0 {
			ct.Features[CiliumDNSProxyHA] = features.Status{Enabled: false}
			return nil
		}
	}

	return nil
}

func extractFromConfigMap(ctx context.Context, ct *check.ConnectivityTest) error {
	cm, err := ct.K8sClient().GetConfigMap(ctx, ct.Params().CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}
	if cm.Data == nil {
		return fmt.Errorf("ConfigMap %q does not contain any configuration", defaults.ConfigMapName)
	}

	ct.Features[EgressGatewayHA] = features.Status{
		Enabled: cm.Data["enable-ipv4-egress-gateway-ha"] == "true" ||
			// in Cilium v1.14-ce we auto opt into egress gateway HA in case the OSS feature is enabled, for backward compatibility with 1.13-ce
			(versioncheck.MustCompile(">=1.14.0 <1.15.0")(ct.CiliumVersion) && cm.Data["enable-ipv4-egress-gateway"] == "true"),
	}

	ct.Features[CiliumDNSProxyHA] = features.Status{
		Enabled: cm.Data["external-dns-proxy"] == "true",
	}

	ct.Features[FallbackRoutingMode] = features.Status{
		Enabled: cm.Data["fallback-routing-mode"] != "",
		Mode:    cm.Data["fallback-routing-mode"],
	}

	ct.Features[Multicast] = features.Status{
		Enabled: cm.Data["multicast-enabled"] == "true",
	}

	ct.Features[EnterpriseBGPControlPlane] = features.Status{
		Enabled: cm.Data[string(EnterpriseBGPControlPlane)] == "true",
	}

	ct.Features[BFD] = features.Status{
		Enabled: cm.Data[string(BFD)] == "true",
	}

	return nil
}

func extractFromRemoteConfigMap(ctx context.Context, ct *check.ConnectivityTest) error {
	if ct.Params().MultiCluster == "" {
		ct.Features[MixedRoutingMode] = features.Status{Enabled: false}
		return nil
	}

	cm, err := ct.Clients()[1].GetConfigMap(ctx, ct.Params().CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve remote ConfigMap %q: %w", defaults.ConfigMapName, err)
	}
	if cm.Data == nil {
		return fmt.Errorf("remote ConfigMap %q does not contain any configuration", defaults.ConfigMapName)
	}

	ct.Features[RemoteClusterTunnel] = features.ExtractTunnelFeatureFromVersionedConfigMap(ct.CiliumVersion, cm)
	ct.Features[MixedRoutingMode] = features.Status{Enabled: ct.Features[features.Tunnel].Enabled != ct.Features[RemoteClusterTunnel].Enabled}
	return nil
}

func ExtractFromSysdumpCollector(collector *sysdump.Collector) error {
	cm := collector.CiliumConfigMap

	collector.FeatureSet[SRv6] = features.Status{
		Enabled: cm != nil && cm.Data[string(SRv6)] == "true",
	}

	collector.FeatureSet[SRv6LocatorPool] = features.Status{
		Enabled: cm != nil && cm.Data[string(SRv6LocatorPool)] == "true",
	}

	collector.FeatureSet[EnterpriseBGPControlPlane] = features.Status{
		Enabled: cm != nil && cm.Data[string(EnterpriseBGPControlPlane)] == "true",
	}

	collector.FeatureSet[BFD] = features.Status{
		Enabled: cm != nil && cm.Data[string(BFD)] == "true",
	}

	return nil
}
