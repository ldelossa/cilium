// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/datapath/linux/route"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

// groupConfig is the internal representation of an egress group, describing
// which nodes should act as egress gateway for a given policy
type groupConfig struct {
	nodeSelector    api.EndpointSelector
	iface           string
	egressIP        net.IP
	maxGatewayNodes int
}

// gatewayConfig is the gateway configuration derived at runtime from a policy.
//
// Some of these fields are derived from the running system as the policy may
// specify only the egress IP (and so we need to figure out which interface has
// that IP assigned to) or the interface (and in this case we need to find the
// first IPv4 assigned to that).
type gatewayConfig struct {
	// ifaceName is the name of the interface used to SNAT traffic
	ifaceName string
	// ifaceIndex is the index of the interface used to SNAT traffic
	ifaceIndex int
	// egressIP is the IP used to SNAT traffic
	egressIP net.IPNet

	// activeGatewayIPs is a slice of node IPs that are actively working as
	// egress gateways
	activeGatewayIPs []net.IP

	// healthyGatewayIPs is the entire pool of healthy nodes that can act as
	// egress gateway for the given policy.
	// Not all of them may be actively acting as gateway since with the
	// maxGatewayNodes policy directive we can select a subset of them
	healthyGatewayIPs []net.IP

	// localNodeConfiguredAsGateway tells if the local node belongs to the
	// pool of egress gateway node for this config.
	// This information is used to decide if it is necessary to install ENI
	// IP rules/routes
	localNodeConfiguredAsGateway bool
}

// PolicyConfig is the internal representation of Cilium Egress NAT Policy.
type PolicyConfig struct {
	// id is the parsed config name and namespace
	id types.NamespacedName

	endpointSelectors []api.EndpointSelector
	dstCIDRs          []*net.IPNet
	egressIP          net.IP
	groupConfigs      []groupConfig

	gatewayConfig gatewayConfig
}

// PolicyID includes policy name and namespace
type policyID = types.NamespacedName

// selectsEndpoint determines if the given endpoint is selected by the policy
// config based on matching labels of config and endpoint.
func (config *PolicyConfig) selectsEndpoint(endpointInfo *endpointMetadata) bool {
	labelsToMatch := k8sLabels.Set(endpointInfo.labels)
	for _, selector := range config.endpointSelectors {
		if selector.Matches(labelsToMatch) {
			return true
		}
	}
	return false
}

func (config *groupConfig) selectsNodeAsGateway(node nodeTypes.Node) bool {
	return config.nodeSelector.Matches(k8sLabels.Set(node.Labels))
}

func (config *PolicyConfig) regenerateGatewayConfig(manager *Manager) {
	if config.egressIP != nil {
		config.gatewayConfig = gatewayConfig{
			activeGatewayIPs:  []net.IP{config.egressIP},
			healthyGatewayIPs: []net.IP{config.egressIP},
			egressIP:          net.IPNet{IP: config.egressIP, Mask: net.CIDRMask(32, 32)},
		}

		return
	}

	gwc := gatewayConfig{
		egressIP: net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 0)},
	}

	for _, gc := range config.groupConfigs {
		// we need a per-group slice to properly honor the maxGatewayNodes
		// directive
		groupGatewayIPs := []net.IP{}

		for _, node := range manager.nodes {
			if !gc.selectsNodeAsGateway(node) {
				continue
			}

			if manager.nodeIsHealthy(node.Name) {
				gwc.healthyGatewayIPs = append(gwc.healthyGatewayIPs, node.GetK8sNodeIP())

				if gc.maxGatewayNodes == 0 || len(groupGatewayIPs) < gc.maxGatewayNodes {
					groupGatewayIPs = append(groupGatewayIPs, node.GetK8sNodeIP())
				}
			}

			if node.IsLocal() {
				err := gwc.deriveFromGroupConfig(&gc)
				if err != nil {
					logger := log.WithFields(logrus.Fields{
						logfields.CiliumEgressGatewayPolicyName: config.id,
						logfields.Interface:                     gc.iface,
						logfields.EgressIP:                      gc.egressIP,
					})

					logger.WithError(err).Error("Failed to derive policy gateway configuration")
				}
			}
		}

		gwc.activeGatewayIPs = append(gwc.activeGatewayIPs, groupGatewayIPs...)
	}

	config.gatewayConfig = gwc
}

// deriveFromGroupConfig retrieves all the missing gateway configuration data
// (such as egress IP or interface) given a policy group config
func (gwc *gatewayConfig) deriveFromGroupConfig(gc *groupConfig) error {
	var err error

	gwc.localNodeConfiguredAsGateway = false

	switch {
	case gc.iface != "":
		// If the group config specifies an interface, use the first IPv4 assigned to that
		// interface as egress IP
		gwc.egressIP, gwc.ifaceIndex, err = getIfaceFirstIPv4Address(gc.iface)
		if err != nil {
			return fmt.Errorf("failed to retrieve IPv4 address for egress interface: %w", err)
		}
	case gc.egressIP != nil && !gc.egressIP.Equal(net.IPv4zero):
		// If the group config specifies an egress IP, use the interface with that IP as egress
		// interface
		gwc.egressIP.IP = gc.egressIP
		gwc.ifaceName, gwc.ifaceIndex, gwc.egressIP.Mask, err = getIfaceWithIPv4Address(gc.egressIP)
		if err != nil {
			return fmt.Errorf("failed to retrieve interface with egress IP: %w", err)
		}
	default:
		// If the group config doesn't specify any egress IP or interface, us
		// the interface with the IPv4 default route
		iface, err := route.NodeDeviceWithDefaultRoute(true, false)
		if err != nil {
			return fmt.Errorf("failed to find interface with default route: %w", err)
		}

		gwc.ifaceName = iface.Attrs().Name
		gwc.egressIP, gwc.ifaceIndex, err = getIfaceFirstIPv4Address(gwc.ifaceName)
		if err != nil {
			return fmt.Errorf("failed to retrieve IPv4 address for egress interface: %w", err)
		}
	}

	gwc.localNodeConfiguredAsGateway = true

	return nil
}

func (config *PolicyConfig) forEachEndpointAndDestination(epDataStore map[endpointID]*endpointMetadata,
	f func(net.IP, *net.IPNet, *gatewayConfig)) {

	for _, endpoint := range epDataStore {
		if !config.selectsEndpoint(endpoint) {
			continue
		}

		for _, endpointIP := range endpoint.ips {
			for _, dstCIDR := range config.dstCIDRs {
				f(endpointIP, dstCIDR, &config.gatewayConfig)
			}
		}
	}
}

func (config *PolicyConfig) matches(epDataStore map[endpointID]*endpointMetadata,
	f func(net.IP, *net.IPNet, *gatewayConfig) bool) bool {

	for _, endpoint := range epDataStore {
		if !config.selectsEndpoint(endpoint) {
			continue
		}

		for _, endpointIP := range endpoint.ips {
			for _, dstCIDR := range config.dstCIDRs {
				if f(endpointIP, dstCIDR, &config.gatewayConfig) {
					return true
				}
			}
		}
	}

	return false
}

// ParseCENP takes a CiliumEgressNATPolicy CR and converts to PolicyConfig, the
// internal representation of the egress nat policy
func ParseCENP(cenp *v2alpha1.CiliumEgressNATPolicy) (*PolicyConfig, error) {
	var endpointSelectorList []api.EndpointSelector
	var dstCidrList []*net.IPNet

	allowAllNamespacesRequirement := slim_metav1.LabelSelectorRequirement{
		Key:      k8sConst.PodNamespaceLabel,
		Operator: slim_metav1.LabelSelectorOpExists,
	}
	name := cenp.ObjectMeta.Name

	if name == "" {
		return nil, fmt.Errorf("CiliumEgressNATPolicy must have a name")
	}

	egressIP := net.ParseIP(cenp.Spec.EgressSourceIP).To4()

	gc := []groupConfig{}
	for _, gcSpec := range cenp.Spec.EgressGroups {
		if gcSpec.Interface != "" && gcSpec.EgressIP != "" {
			return nil, fmt.Errorf("CiliumEgressNATPolicy's group configuration can't specify both an interface and an egress IP")
		}

		egressIP := net.ParseIP(gcSpec.EgressIP)

		gc = append(gc, groupConfig{
			nodeSelector:    api.NewESFromK8sLabelSelector("", gcSpec.NodeSelector),
			iface:           gcSpec.Interface,
			egressIP:        egressIP,
			maxGatewayNodes: gcSpec.MaxGatewayNodes,
		})
	}

	switch {
	case egressIP != nil && len(gc) != 0:
		return nil, fmt.Errorf("CiliumEgressNATPolicy cannot have both EgressSourceIP and EgressGroups set")
	case egressIP == nil && len(gc) == 0:
		return nil, fmt.Errorf("CiliumEgressNATPolicy needs either EgressSourceIP or EgressGroups set")
	}

	for _, cidrString := range cenp.Spec.DestinationCIDRs {
		_, cidr, err := net.ParseCIDR(string(cidrString))
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{logfields.CiliumEgressNATPolicyName: name}).Warn("Error parsing cidr.")
			return nil, err
		}
		dstCidrList = append(dstCidrList, cidr)
	}

	for _, egressRule := range cenp.Spec.Egress {
		if egressRule.NamespaceSelector != nil {
			prefixedNsSelector := egressRule.NamespaceSelector
			matchLabels := map[string]string{}
			// We use our own special label prefix for namespace metadata,
			// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
			for k, v := range egressRule.NamespaceSelector.MatchLabels {
				matchLabels[policy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v
			}

			prefixedNsSelector.MatchLabels = matchLabels

			// We use our own special label prefix for namespace metadata,
			// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
			for i, lsr := range egressRule.NamespaceSelector.MatchExpressions {
				lsr.Key = policy.JoinPath(k8sConst.PodNamespaceMetaLabels, lsr.Key)
				prefixedNsSelector.MatchExpressions[i] = lsr
			}

			// Empty namespace selector selects all namespaces (i.e., a namespace
			// label exists).
			if len(egressRule.NamespaceSelector.MatchLabels) == 0 && len(egressRule.NamespaceSelector.MatchExpressions) == 0 {
				prefixedNsSelector.MatchExpressions = []slim_metav1.LabelSelectorRequirement{allowAllNamespacesRequirement}
			}

			endpointSelectorList = append(
				endpointSelectorList,
				api.NewESFromK8sLabelSelector("", prefixedNsSelector, egressRule.PodSelector))
		} else if egressRule.PodSelector != nil {
			endpointSelectorList = append(
				endpointSelectorList,
				api.NewESFromK8sLabelSelector("", egressRule.PodSelector))
		} else {
			return nil, fmt.Errorf("CiliumEgressNATPolicy cannot have both nil namespace selector and nil pod selector")
		}
	}

	return &PolicyConfig{
		endpointSelectors: endpointSelectorList,
		dstCIDRs:          dstCidrList,
		egressIP:          egressIP,
		groupConfigs:      gc,
		id: types.NamespacedName{
			Name: name,
		},
	}, nil
}

// ParseCENPConfigID takes a CiliumEgressNATPolicy CR and returns only the config id
func ParseCENPConfigID(cenp *v2alpha1.CiliumEgressNATPolicy) types.NamespacedName {
	return policyID{
		Name: cenp.Name,
	}
}

// ParseCEGP takes a CiliumEgressGatewayPolicy CR and converts to PolicyConfig,
// the internal representation of the egress gateway policy
func ParseCEGP(cegp *v2.CiliumEgressGatewayPolicy) (*PolicyConfig, error) {
	var endpointSelectorList []api.EndpointSelector
	var dstCidrList []*net.IPNet

	allowAllNamespacesRequirement := slim_metav1.LabelSelectorRequirement{
		Key:      k8sConst.PodNamespaceLabel,
		Operator: slim_metav1.LabelSelectorOpExists,
	}

	name := cegp.ObjectMeta.Name
	if name == "" {
		return nil, fmt.Errorf("CiliumEgressGatewayPolicy must have a name")
	}

	gc := []groupConfig{}
	for _, gcSpec := range cegp.Spec.EgressGroups {
		if gcSpec.Interface != "" && gcSpec.EgressIP != "" {
			return nil, fmt.Errorf("CiliumEgressGatewayPolicy's group configuration can't specify both an interface and an egress IP")
		}

		egressIP := net.ParseIP(gcSpec.EgressIP)

		gc = append(gc, groupConfig{
			nodeSelector:    api.NewESFromK8sLabelSelector("", gcSpec.NodeSelector),
			iface:           gcSpec.Interface,
			egressIP:        egressIP,
			maxGatewayNodes: gcSpec.MaxGatewayNodes,
		})
	}

	for _, cidrString := range cegp.Spec.DestinationCIDRs {
		_, cidr, err := net.ParseCIDR(string(cidrString))
		if err != nil {
			log.WithError(err).WithFields(logrus.Fields{logfields.CiliumEgressGatewayPolicyName: name}).Warn("Error parsing cidr.")
			return nil, err
		}
		dstCidrList = append(dstCidrList, cidr)
	}

	for _, egressRule := range cegp.Spec.Selectors {
		if egressRule.NamespaceSelector != nil {
			prefixedNsSelector := egressRule.NamespaceSelector
			matchLabels := map[string]string{}
			// We use our own special label prefix for namespace metadata,
			// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
			for k, v := range egressRule.NamespaceSelector.MatchLabels {
				matchLabels[policy.JoinPath(k8sConst.PodNamespaceMetaLabels, k)] = v
			}

			prefixedNsSelector.MatchLabels = matchLabels

			// We use our own special label prefix for namespace metadata,
			// thus we need to prefix that prefix to all NamespaceSelector.MatchLabels
			for i, lsr := range egressRule.NamespaceSelector.MatchExpressions {
				lsr.Key = policy.JoinPath(k8sConst.PodNamespaceMetaLabels, lsr.Key)
				prefixedNsSelector.MatchExpressions[i] = lsr
			}

			// Empty namespace selector selects all namespaces (i.e., a namespace
			// label exists).
			if len(egressRule.NamespaceSelector.MatchLabels) == 0 && len(egressRule.NamespaceSelector.MatchExpressions) == 0 {
				prefixedNsSelector.MatchExpressions = []slim_metav1.LabelSelectorRequirement{allowAllNamespacesRequirement}
			}

			endpointSelectorList = append(
				endpointSelectorList,
				api.NewESFromK8sLabelSelector("", prefixedNsSelector, egressRule.PodSelector))
		} else if egressRule.PodSelector != nil {
			endpointSelectorList = append(
				endpointSelectorList,
				api.NewESFromK8sLabelSelector("", egressRule.PodSelector))
		} else {
			return nil, fmt.Errorf("CiliumEgressGatewayPolicy cannot have both nil namespace selector and nil pod selector")
		}
	}

	return &PolicyConfig{
		endpointSelectors: endpointSelectorList,
		dstCIDRs:          dstCidrList,
		groupConfigs:      gc,
		id: types.NamespacedName{
			Name: name,
		},
	}, nil
}

// ParseCEGPConfigID takes a CiliumEgressGatewayPolicy CR and returns only the config id
func ParseCEGPConfigID(cegp *v2.CiliumEgressGatewayPolicy) types.NamespacedName {
	return policyID{
		Name: cegp.Name,
	}
}
