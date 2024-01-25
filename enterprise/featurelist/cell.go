//nolint:goheader
// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package featurelist

import (
	"runtime"
	"strings"

	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/enterprise/pkg/features"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/datapath/types"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/option"

	"github.com/cilium/hive/cell"
)

const (
	namespacePolicy        = "Policy"
	namespaceDatapath      = "Datapath"
	namespaceCNI           = "CNI"
	namespaceEgressGateway = "EgressGateway"
	namespaceEncryption    = "Encryption"
	namespaceBGP           = "BGP"
	namespaceIPAM          = "IPAM"
	namespaceIngress       = "K8sIngress"
)

// EnterpriseFeatures provides a declaration of features (both OSS and Enterprise) as they
// are currently supported in Cilium for CE customers.
// Note: This may differ from maturity of features in open source Cilium.
//
// See feature maturity matrix here:
//
//	https://docs.google.com/spreadsheets/d/1OjcFPEG9J2pJDaIsIyIXyrEBy2wT-PUiMM3PbzpoO40/
//
// This feature list will generally use *option.DaemonConfig as the configuration type for
// features.
// They are maintained here so that we can mindfully apply feature specs for existing OSS features
// (or enterprise features that use the same configuration type) as a component of Cilium Enterprise
// integration.
//
// In general, if possible, we should define features in the same module as the feature implementation.
var Cell = cell.Module(
	"enterprise-featurelist",
	"Enterprise Feature List",

	// Datapath features are features that are related to Ciliums network datapath.
	cell.Module(
		"datapath-featurelist",
		"Datapath Feature List",
		// Datapath IP Modes
		features.FeatureWithConfigT(features.Spec{
			ID:          namespaceDatapath + "IPModeDualStack",
			Name:        "Dual-stack IPv4/IPv6 Mode",
			Description: "Enable dual-stack IPv4/IPv6 datapath, enabled by having both ipv4-enabled and ipv6-enabled set to true",
			Stage:       features.Beta,
		}, features.WithIsEnabledFn(func(conf *option.DaemonConfig) (bool, error) {
			return conf.IsDualStack(), nil
		})),
		features.FeatureWithConfigT(features.Spec{
			ID:          namespaceDatapath + "IPModeIPv4",
			Name:        "IPv4 Only IP Mode",
			Description: "IPv4 only datapath, enabled by having ipv4-enabled set to true and ipv6-enabled set to false",
			Stage:       features.Stable,
		}, features.WithIsEnabledFn(func(conf *option.DaemonConfig) (bool, error) {
			return conf.IPv4Enabled() && !conf.IPv6Enabled(), nil
		})),
		features.FeatureWithConfigT(features.Spec{
			ID:          namespaceDatapath + "IPModeIPv6",
			Name:        "IPv6 Only IP Mode",
			Description: "IPv6 only datapath, enabled by having ipv6-enabled set to true and ipv4-enabled set to false",
			Stage:       features.Beta,
		}, features.WithIsEnabledFn(func(conf *option.DaemonConfig) (bool, error) {
			return conf.IPv6Enabled() && !conf.IPv4Enabled(), nil
		})),

		// Host Firewall
		features.FeatureWithConfigT(features.Spec{
			ID:          namespaceDatapath + "HostFirewall",
			Name:        "Host Firewall",
			Description: "Enable host firewall functionality",
			Stage:       features.Limited,
		}, features.WithIsEnabledFn(func(conf *option.DaemonConfig) (bool, error) {
			return conf.EnableHostFirewall, nil
		})),

		// Bandwidth Manager
		features.FeatureWithConfigT(features.Spec{
			ID:          namespaceDatapath + "BandwidthManager",
			Name:        "Bandwidth Manager",
			Description: "Enable bandwidth manager functionality",
			Stage:       features.Beta,
		}, features.WithIsEnabledFn(func(conf types.BandwidthConfig) (bool, error) {
			return conf.EnableBandwidthManager, nil
		})),

		features.FeatureWithConfigT(features.Spec{
			ID:          namespaceDatapath + "DatapathMode" + "VETH",
			Name:        "VETH Datapath Mode",
			Description: "VETH datapath mode, enabled by having datapath-mode set to veth.",
			Stage:       features.Stable,
		}, features.WithIsEnabledFn(func(conf *option.DaemonConfig) (bool, error) {
			return conf.DatapathMode == datapathOption.DatapathModeVeth, nil
		})),

		features.FeatureWithConfigT(features.Spec{
			ID:          namespaceDatapath + "DatapathMode" + "LBOnly",
			Name:        "LB Only Datapath Mode",
			Description: "LB Only datapath mode, enabled by having datapath-mode set to lbonly.",
			Stage:       features.Stable,
		}, features.WithIsEnabledFn(func(conf *option.DaemonConfig) (bool, error) {
			return conf.DatapathMode == datapathOption.DatapathModeLBOnly, nil
		})),
	),

	cell.Module(
		"egress-gateway-featurelist",
		"Egress Gateway Feature List",

		features.FeatureWithConfigT(features.Spec{
			ID:          namespaceEgressGateway + "IPv4",
			Name:        "Egress Gateway IPv4",
			Description: "Egress Gateway running in IPv4 mode, enabled by having egress-gateway-ipv4 set to true.",
			Stage:       features.Limited,
		}, features.WithIsEnabledFn(func(conf *option.DaemonConfig) (bool, error) {
			return conf.EnableIPv4EgressGateway, nil
		})),

		features.FeatureWithConfigT(features.Spec{
			ID:          namespaceEgressGateway + "HA",
			Name:        "Egress Gateway High Availability",
			Description: "Egress Gateway High Availability, enabled by having egress-gateway-ha set to true",
			Stage:       features.Limited,
		}, features.WithIsEnabledFn(func(conf *option.DaemonConfig) (bool, error) {
			return conf.EnableIPv4EgressGatewayHA, nil
		})),
	),

	cell.Module(
		"encryption-featurelist",
		"Encryption Feature List",

		features.FeatureWithConfigT(features.Spec{
			ID:          namespaceEncryption + "IPSec",
			Name:        "IPSec Encryption",
			Description: "Transparent IPSec encryption for all traffic between Cilium endpoints",
			Stage:       features.Limited,
		}, features.WithIsEnabledFn(func(conf *option.DaemonConfig) (bool, error) {
			return conf.EnableIPSec, nil
		})),

		features.FeatureWithConfigT(features.Spec{
			ID:          namespaceEncryption + "Wireguard",
			Name:        "Wireguard Encryption",
			Description: "Transparent Wireguard encryption for all traffic between Cilium endpoints",
			Stage:       features.Limited,
		}, features.WithIsEnabledFn(func(conf *option.DaemonConfig) (bool, error) {
			return conf.EnableWireguard, nil
		})),
	),

	cell.Module(
		"cni-featurelist",
		"CNI Feature List",
		features.FeatureWithConfigT(features.Spec{
			ID:   namespaceCNI + "ChainingMode",
			Name: "CNI Chaining Mode",
			Description: "CNI Chaining Mode allows Cilium to chain with multiple CNI plugins.\n" +
				"This feature includes all CNI chaining modes, including aws-vpc-cni, Calico and Flannel.\n" +
				"Note: CNI Chaining mode is considered disabled if the chaining mode is set to 'none'.",
			Stage: features.Limited,
		}, features.WithIsEnabledFn(
			func(cm cni.CNIConfigManager) (bool, error) {
				return cm.GetChainingMode() != "none", nil
			},
		)),
	),

	cell.Module(
		"misc-featurelist",
		"Miscellaneous Feature List",

		// Machine Architecture
		features.FeatureWithConfigT(features.Spec{
			ID:          "ArchARM64",
			Name:        "ARM64 Architecture",
			Description: "ARM64 architecture support",
			Stage:       features.Alpha,
		}, features.WithIsEnabledFn(func(_ features.None) (bool, error) {
			return strings.HasPrefix(runtime.GOARCH, "arm"), nil
		})),
	),

	cell.Module(
		"policy",
		"Policy Feature List",
		features.FeatureWithConfigT(features.Spec{
			ID:          namespacePolicy + "LocalRedirect",
			Name:        "Local Redirect Policy",
			Description: "Enables local traffic redirection policy functionality.",
			Stage:       features.Limited,
		}, features.WithIsEnabledFn(func(conf *option.DaemonConfig) (bool, error) {
			return conf.EnableLocalRedirectPolicy, nil
		})),
	),

	cell.Module(
		"ipam-featurelist",
		"IPAM Feature List",
		features.FeatureWithConfigT(features.Spec{
			ID:          namespaceIPAM + "ClusterPool",
			Name:        "Cluster Pool IPAM",
			Description: "Cluster Pool IPAM allows Cilium to allocate IP addresses from a pool of addresses",
			Stage:       features.Stable,
		}, features.WithIsEnabledFn(func(conf *option.DaemonConfig) (bool, error) {
			return conf.IPAMMode() == ipamOption.IPAMClusterPool, nil
		})),
		features.FeatureWithConfigT(features.Spec{
			ID:          namespaceIPAM + "MultiPool",
			Name:        "Multi Pool IPAM",
			Description: "Multi Pool IPAM allows Cilium to allocate IP addresses from multiple pools of addresses",
			Stage:       features.Beta,
		}, features.WithIsEnabledFn(func(conf *option.DaemonConfig) (bool, error) {
			return conf.IPAMMode() == ipamOption.IPAMMultiPool, nil
		})),
		features.FeatureWithConfigT(features.Spec{
			ID:          namespaceIPAM + "Azure",
			Name:        "Azure IPAM",
			Description: "Azure based IPAM",
			Stage:       features.Limited,
		}, features.WithIsEnabledFn(func(conf *option.DaemonConfig) (bool, error) {
			return conf.IPAMMode() == ipamOption.IPAMAzure, nil
		})),
	),

	cell.Module(
		"bgp-featurelist",
		"BGP Feature List",
		features.FeatureWithConfigT(features.Spec{
			ID:          "BGPControlPlane",
			Name:        "Enterprise BGP Control Plane",
			Description: "Enables the BGP control plane for Cilium Enterprise",
			Stage:       features.Limited,
		}, features.WithIsEnabledFn(func(conf *option.DaemonConfig) (bool, error) {
			return conf.BGPControlPlaneEnabled(), nil
		})),
	),
)
