//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/ip"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
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
	egressIP        netip.Addr
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
	// egressIP is the IP used to SNAT traffic
	egressIP netip.Addr

	// activeGatewayIPs is a slice of node IPs that are actively working as
	// egress gateways
	activeGatewayIPs []netip.Addr

	// healthyGatewayIPs is the entire pool of healthy nodes that can act as
	// egress gateway for the given policy.
	// Not all of them may be actively acting as gateway since with the
	// maxGatewayNodes policy directive we can select a subset of them
	healthyGatewayIPs []netip.Addr

	// localNodeConfiguredAsGateway tells if the local node belongs to the
	// pool of egress gateway node for this config.
	// This information is used to make sure the node does not get selected
	// multiple times by different egress groups
	localNodeConfiguredAsGateway bool
}

type groupStatus struct {
	activeGatewayIPs     []netip.Addr
	activeGatewayIPsByAZ map[string][]netip.Addr
	healthyGatewayIPs    []netip.Addr
}

type azAffinityMode int

const (
	azAffinityDisabled azAffinityMode = iota
	azAffinityLocalOnly
	azAffinityLocalOnlyFirst
	azAffinityLocalPriority
)

func azAffinityModeFromString(azAffinity string) (azAffinityMode, error) {
	switch azAffinity {
	case "disabled", "":
		return azAffinityDisabled, nil
	case "localOnly":
		return azAffinityLocalOnly, nil
	case "localOnlyFirst":
		return azAffinityLocalOnlyFirst, nil
	case "localPriority":
		return azAffinityLocalPriority, nil
	default:
		return 0, fmt.Errorf("invalid azAffinity value \"%s\"", azAffinity)
	}
}

func (m azAffinityMode) toString() string {
	switch m {
	case azAffinityDisabled:
		return "disabled"
	case azAffinityLocalOnly:
		return "localOnly"
	case azAffinityLocalOnlyFirst:
		return "localOnlyFirst"
	case azAffinityLocalPriority:
		return "localPriority"
	default:
		return ""
	}
}

func (m azAffinityMode) enabled() bool {
	return m != azAffinityDisabled
}

// PolicyConfig is the internal representation of IsovalentEgressGatewayPolicy.
type PolicyConfig struct {
	// id is the parsed config name and namespace
	id types.NamespacedName

	apiVersion string
	generation int64

	endpointSelectors []api.EndpointSelector
	dstCIDRs          []netip.Prefix
	excludedCIDRs     []netip.Prefix

	azAffinity azAffinityMode

	groupConfigs            []groupConfig
	groupStatusesGeneration int64
	groupStatuses           []groupStatus

	matchedEndpoints map[endpointID]*endpointMetadata
	gatewayConfig    gatewayConfig
}

// PolicyID includes policy name and namespace
type policyID = types.NamespacedName

// matchesEndpointLabels determines if the given endpoint is a match for the
// policy config based on matching labels.
func (config *PolicyConfig) matchesEndpointLabels(endpointInfo *endpointMetadata) bool {
	labelsToMatch := k8sLabels.Set(endpointInfo.labels)
	for _, selector := range config.endpointSelectors {
		if selector.Matches(labelsToMatch) {
			return true
		}
	}
	return false
}

// updateMatchedEndpointIDs update the policy's cache of matched endpoint IDs
func (config *PolicyConfig) updateMatchedEndpointIDs(epDataStore map[endpointID]*endpointMetadata) {
	config.matchedEndpoints = make(map[endpointID]*endpointMetadata)

	for _, endpoint := range epDataStore {
		if config.matchesEndpointLabels(endpoint) {
			config.matchedEndpoints[endpoint.id] = endpoint
		}
	}
}

func (config *groupConfig) selectsNodeAsGateway(node nodeTypes.Node) bool {
	return config.nodeSelector.Matches(k8sLabels.Set(node.Labels))
}

func getIEGPForStatusUpdate(iegp *Policy, groupStatuses []v1.IsovalentEgressGatewayPolicyGroupStatus) *Policy {
	return &Policy{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       iegp.Kind,
			APIVersion: iegp.APIVersion,
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name:            iegp.GetName(),
			Namespace:       iegp.GetNamespace(),
			ResourceVersion: iegp.GetResourceVersion(),
			UID:             iegp.GetUID(),
			Labels:          iegp.GetLabels(),
			Annotations:     iegp.GetAnnotations(),
		},
		// The Spec isn't needed in production code, as this update object will be passed into an UpdateStatus client-go
		// method, that will promptly ignore the spec. However, it's needed in tests because the fake k8s client
		// implements UpdateStatus in a simplistic way, and overwrites the stored spec with the one on this object.
		// This results in us storing a blank spec, and breaking the test.
		Spec: iegp.Spec,
		Status: v1.IsovalentEgressGatewayPolicyStatus{
			ObservedGeneration: iegp.GetGeneration(),
			GroupStatuses:      groupStatuses,
		},
	}
}

func (gc *groupConfig) computeGroupStatus(operatorManager *OperatorManager, config *PolicyConfig) v1.IsovalentEgressGatewayPolicyGroupStatus {
	activeGatewayIPs := []string{}
	healthyGatewayIPs := []string{}

	activeGatewayIPsByAZ := map[string][]string{}
	healthyGatewayIPsByAZ := map[string][]string{}

	for _, node := range operatorManager.nodes {
		// if the group config doesn't match the node, ignore it and go to the next one
		if !gc.selectsNodeAsGateway(node) {
			continue
		}

		// if AZ affinity is enabled for the egress group, track the node's AZ.
		//
		// This will be used later on to ensure that even AZs with no healthy gateway nodes can get non
		// local gateways asigned to (and because of this tracking needs to happen before ignoring an
		// unhealthy node)
		if config.azAffinity.enabled() {
			if nodeAZ, ok := node.Labels[core_v1.LabelTopologyZone]; ok {
				// as the healthyGatewayIPsByAZ map is used also to keep track of all the available AZs,
				// always create an empty entry if it doesn't exist yet.
				// In this way we can ensure all AZs will have a key in the map
				if _, ok = healthyGatewayIPsByAZ[nodeAZ]; !ok {
					healthyGatewayIPsByAZ[nodeAZ] = []string{}
				}
			}
		}

		// if the node is not healthy, ignore it and move to the next one
		if !operatorManager.nodeIsHealthy(node.Name) {
			continue
		}

		nodeIP := node.GetK8sNodeIP().String()

		// add the node to the list of active and healthy gateway IPs.
		// These lists are global (i.e. they do not take into account the AZ of the node)
		healthyGatewayIPs = append(healthyGatewayIPs, nodeIP)
		activeGatewayIPs = append(activeGatewayIPs, nodeIP)

		// if AZ affinity is enabled, add the node IP also to the list of healthy gateway IPs
		if config.azAffinity.enabled() {
			if nodeAZ, ok := node.Labels[core_v1.LabelTopologyZone]; ok {
				healthyGatewayIPsByAZ[nodeAZ] = append(healthyGatewayIPsByAZ[nodeAZ], nodeIP)
			} else {
				log.WithField(logfields.NodeName, node.Name).
					Errorf("AZ affinity is enabled but node is missing %s label. Node will be ignored", core_v1.LabelTopologyZone)
			}
		}
	}

	// if AZ affinity is enabled, do a first pass to build the per-AZ list of active gateway IPs:
	// initially the list of active gateways for a given AZ will be identical to the list of healthy gateways,
	// then based on the selected AZ affinity mode and maxGatewayNodes settings, other nodes from different AZs can
	// be added or already present nodes can be removed
	if config.azAffinity.enabled() {
		for az, healthyGatewayIPs := range healthyGatewayIPsByAZ {
			activeGatewayIPsByAZ[az] = slices.Clone(healthyGatewayIPs)
		}
	}

	// nonLocalActiveGatewayIPs is a helper that returns, given a particular AZ, a slice of non local gateways for
	// that AZ.
	//
	// The slice is sorted by nodes' AZs, in lexicographical ordering, and starts from AZ next to the one passed to the function.
	// In this way each AZ will have its own ordering of non local gateways, allowing different AZs to fallback to
	// different set of non local gateways
	nonLocalActiveGatewayIPs := func(az string) []string {
		// sort the AZs lexicographically
		sortedAZs := maps.Keys(healthyGatewayIPsByAZ)
		sort.Strings(sortedAZs)

		// shift the list so that it starts after the given AZ.
		//
		// For example [a, b, c, d] with local AZ "c" would result in [d, a, b]
		if i, ok := slices.BinarySearch(sortedAZs, az); ok {
			// first shift the list so that it starts with the given AZ.
			//
			// [a, b, c, d] -> [c, d, a, b]
			sortedAZs = append(sortedAZs[i:], sortedAZs[:i]...)

			// then delete the given AZ (first one in the list)
			//
			// [c, d, a, b] -> [d, a, b]
			sortedAZs = sortedAZs[1:]
		}

		// then build a list of non local gateway IPs following the ordering of the sorted list of AZs
		gwIPs := []string{}
		for _, az := range sortedAZs {
			gwIPs = append(gwIPs, healthyGatewayIPsByAZ[az]...)
		}

		return gwIPs
	}

	// next do a second pass to populate the per-AZ list of active gateways
	switch config.azAffinity {
	case azAffinityLocalOnly:
		// for local only affinity there's nothing left to do

	case azAffinityLocalOnlyFirst:
		for az := range activeGatewayIPsByAZ {
			// only if there are no local gateways, pick the ones from the other AZs
			if len(activeGatewayIPsByAZ[az]) == 0 {
				activeGatewayIPsByAZ[az] = nonLocalActiveGatewayIPs(az)
			}
		}

	case azAffinityLocalPriority:
		for az := range activeGatewayIPsByAZ {
			// always append non local gateways to the local ones
			activeGatewayIPsByAZ[az] = append(activeGatewayIPsByAZ[az],
				nonLocalActiveGatewayIPs(az)...)
		}
	}

	// if set, limit the number of gateways to maxGatewayNodes
	if gc.maxGatewayNodes != 0 {
		if len(activeGatewayIPs) > gc.maxGatewayNodes {
			activeGatewayIPs = activeGatewayIPs[:gc.maxGatewayNodes]
		}

		if config.azAffinity.enabled() {
			for az := range activeGatewayIPsByAZ {
				if len(activeGatewayIPsByAZ[az]) > gc.maxGatewayNodes {
					activeGatewayIPsByAZ[az] = activeGatewayIPsByAZ[az][:gc.maxGatewayNodes]
				}
			}
		}
	}

	return v1.IsovalentEgressGatewayPolicyGroupStatus{
		ActiveGatewayIPs:     activeGatewayIPs,
		ActiveGatewayIPsByAZ: activeGatewayIPsByAZ,
		HealthyGatewayIPs:    healthyGatewayIPs,
	}
}

// updateGroupStatuses updates the list of active and healthy gateway IPs in the
// IEGP k8s resource for the receiver PolicyConfig
func (config *PolicyConfig) updateGroupStatuses(operatorManager *OperatorManager) error {
	groupStatuses := []v1.IsovalentEgressGatewayPolicyGroupStatus{}
	for _, gc := range config.groupConfigs {
		groupStatuses = append(groupStatuses,
			gc.computeGroupStatus(operatorManager, config))
	}

	// After building the list of active and healthy gateway IPs, update the
	// status of the corresponding IEGP k8s resource
	iegp, ok := operatorManager.policyCache[config.id]
	if !ok {
		log.WithFields(logrus.Fields{
			logfields.IsovalentEgressGatewayPolicyName: config.id.Name,
		}).Error("Cannot find cached policy, group statuses will not be updated")

		return nil
	}

	newIEGP := getIEGPForStatusUpdate(operatorManager.policyCache[config.id], groupStatuses)

	// if the IEGP's status is already up to date, that is:
	// - ObservedGeneration is already equal to the IEGP Generation
	// - GroupStatuses are already in sync with the computed ones
	// then skip updating the status to avoid emitting an update event for the policy
	if config.generation == config.groupStatusesGeneration &&
		cmp.Equal(iegp.Status.GroupStatuses, newIEGP.Status.GroupStatuses, cmpopts.EquateEmpty()) {
		return nil
	}

	logger := log.WithField(logfields.IsovalentEgressGatewayPolicyName, config.id.Name)
	logger.Debugf("Updating policy status: %+v", newIEGP.Status)

	updatedIEGP, err := operatorManager.clientset.IsovalentV1().IsovalentEgressGatewayPolicies().
		UpdateStatus(context.TODO(), newIEGP, meta_v1.UpdateOptions{})
	if err != nil {
		logger.WithField(logfields.K8sGeneration, newIEGP.Status.ObservedGeneration).
			WithError(err).
			Warn("Cannot update IsovalentEgressGatewayPolicy status, retrying")

		return err
	}
	// Now we've updated the IsovalentEgressGatewayPolicy, we need to update our local cache. The UpdateStatus
	// method on the Kubernetes client object helpfully returned the updated iegp. So we can just write that back to
	// the cache. By definition, if that call did not error, it's the most up-to-date version of the object.
	updatedPolicyConfig, err := ParseIEGP(updatedIEGP)
	if err != nil {
		// This is a super-strange case where we've written an updated object that we then cannot parse.
		logger.WithField(logfields.K8sGeneration, updatedIEGP.Status.ObservedGeneration).
			WithError(err).
			Warn("Failed to parse IsovalentEgressGatewayPolicy after update")
		return err
	}
	operatorManager.policyCache[config.id] = updatedIEGP
	operatorManager.policyConfigs[config.id] = updatedPolicyConfig

	return nil
}

func (config *PolicyConfig) regenerateGatewayConfig(manager *Manager) {
	config.gatewayConfig = gatewayConfig{
		egressIP:          netip.IPv4Unspecified(),
		activeGatewayIPs:  []netip.Addr{},
		healthyGatewayIPs: []netip.Addr{},
	}

	if len(config.groupStatuses) == 0 {
		return
	}

	localNode, err := manager.localNodeStore.Get(context.TODO())
	if err != nil {
		log.Error("Failed to get local node store")
		return
	}

	localNodeK8sAddr, ok := ip.AddrFromIP(localNode.GetK8sNodeIP())
	if !ok {
		log.Error("Failed to parse local node IP")
		return
	}

	gwc := &config.gatewayConfig
	for groupIndex, gc := range config.groupConfigs {
		groupStatus := &config.groupStatuses[groupIndex]

		gwc.activeGatewayIPs = append(gwc.activeGatewayIPs, groupStatus.activeGatewayIPs...)
		gwc.healthyGatewayIPs = append(gwc.healthyGatewayIPs, groupStatus.healthyGatewayIPs...)

		// We use the local node IP to determine if the current node
		// matches the list of active gateway IPs
		if slices.Contains(groupStatus.activeGatewayIPs, localNodeK8sAddr) {
			logger := log.WithFields(logrus.Fields{
				logfields.IsovalentEgressGatewayPolicyName: config.id,
				logfields.Interface:                        gc.iface,
				logfields.EgressIP:                         gc.egressIP,
			})

			// If localNodeConfiguredAsGateway is already set it means that another
			// egress group for the same policy has already selected it as gateway. In
			// this case don't regenerate a new gatewayConfig and emit a warning
			if gwc.localNodeConfiguredAsGateway {
				logger.Warning("Local node selected by multiple egress gateway groups from the same policy")
				continue
			}

			if err := gwc.deriveFromGroupConfig(&gc); err != nil {
				logger.WithError(err).Error("Failed to derive policy gateway configuration")
			}
		}
	}
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
		gwc.ifaceName = gc.iface
		gwc.egressIP, err = getIfaceFirstIPv4Address(gc.iface)
		if err != nil {
			return fmt.Errorf("failed to retrieve IPv4 address for egress interface: %w", err)
		}
	case gc.egressIP.IsValid():
		// If the group config specifies an egress IP, use the interface with that IP as egress
		// interface
		gwc.egressIP = gc.egressIP
		gwc.ifaceName, err = getIfaceWithIPv4Address(gc.egressIP)
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
		gwc.egressIP, err = getIfaceFirstIPv4Address(gwc.ifaceName)
		if err != nil {
			return fmt.Errorf("failed to retrieve IPv4 address for egress interface: %w", err)
		}
	}

	gwc.localNodeConfiguredAsGateway = true

	return nil
}

// forEachEndpointAndCIDR iterates through each combination of endpoints and
// destination/excluded CIDRs of the receiver policy, and for each of them it
// calls the f callback function passing the given endpoint and CIDR, together
// with a boolean value indicating if the CIDR belongs to the excluded ones and
// the gatewayConfig of the receiver policy
func (config *PolicyConfig) forEachEndpointAndCIDR(f func(*endpointMetadata, netip.Prefix, bool, *gatewayConfig)) {
	for _, endpoint := range config.matchedEndpoints {
		isExcludedCIDR := false
		for _, dstCIDR := range config.dstCIDRs {
			f(endpoint, dstCIDR, isExcludedCIDR, &config.gatewayConfig)
		}

		isExcludedCIDR = true
		for _, excludedCIDR := range config.excludedCIDRs {
			f(endpoint, excludedCIDR, isExcludedCIDR, &config.gatewayConfig)
		}
	}
}

// matches returns true if at least one of the combinations of (source, destination, egressIP, gatewayIP)
// from the policy configuration matches the callback f
//
// The callback f takes as arguments:
// - the given endpoint
// - the destination CIDR
// - a boolean value indicating if the CIDR belongs to the excluded ones
// - the gatewayConfig of the  policy
func (config *PolicyConfig) matches(f func(*endpointMetadata, netip.Prefix, bool, *gatewayConfig) bool) bool {
	for _, ep := range config.matchedEndpoints {
		isExcludedCIDR := false
		for _, dstCIDR := range config.dstCIDRs {
			if f(ep, dstCIDR, isExcludedCIDR, &config.gatewayConfig) {
				return true
			}
		}

		isExcludedCIDR = true
		for _, excludedCIDR := range config.excludedCIDRs {
			if f(ep, excludedCIDR, isExcludedCIDR, &config.gatewayConfig) {
				return true
			}
		}
	}

	return false
}

// ParseIEGP takes a IsovalentEgressGatewayPolicy CR and converts to PolicyConfig,
// the internal representation of the egress gateway policy
func ParseIEGP(iegp *v1.IsovalentEgressGatewayPolicy) (*PolicyConfig, error) {
	var endpointSelectorList []api.EndpointSelector
	var dstCidrList []netip.Prefix
	var excludedCIDRs []netip.Prefix

	allowAllNamespacesRequirement := slim_metav1.LabelSelectorRequirement{
		Key:      k8sConst.PodNamespaceLabel,
		Operator: slim_metav1.LabelSelectorOpExists,
	}

	name := iegp.ObjectMeta.Name
	if name == "" {
		return nil, fmt.Errorf("must have a name")
	}

	destinationCIDRs := iegp.Spec.DestinationCIDRs
	if destinationCIDRs == nil {
		return nil, fmt.Errorf("destinationCIDRs can't be empty")
	}

	egressGroups := iegp.Spec.EgressGroups
	if egressGroups == nil {
		return nil, fmt.Errorf("egressGroups can't be empty")
	}

	gcs := []groupConfig{}
	for _, gcSpec := range egressGroups {
		if gcSpec.Interface != "" && gcSpec.EgressIP != "" {
			return nil, fmt.Errorf("group configuration can't specify both an interface and an egress IP")
		}

		// EgressIP is not a required field.
		egressIP, _ := netip.ParseAddr(gcSpec.EgressIP)

		gcs = append(gcs, groupConfig{
			nodeSelector:    api.NewESFromK8sLabelSelector("", gcSpec.NodeSelector),
			iface:           gcSpec.Interface,
			egressIP:        egressIP,
			maxGatewayNodes: gcSpec.MaxGatewayNodes,
		})
	}

	for _, cidrString := range destinationCIDRs {
		cidr, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			return nil, fmt.Errorf("failed to parse destination CIDR %s: %s", cidrString, err)
		}
		dstCidrList = append(dstCidrList, cidr)
	}

	for _, cidrString := range iegp.Spec.ExcludedCIDRs {
		cidr, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			return nil, fmt.Errorf("failed to parse excluded CIDR %s: %s", cidr, err)
		}
		excludedCIDRs = append(excludedCIDRs, cidr)
	}

	for _, egressRule := range iegp.Spec.Selectors {
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
			return nil, fmt.Errorf("cannot have both nil namespace selector and nil pod selector")
		}
	}

	azAffinity, err := azAffinityModeFromString(iegp.Spec.AZAffinity)
	if err != nil {
		return nil, err
	}

	if azAffinity == azAffinityLocalPriority {
		for _, gc := range gcs {
			if gc.maxGatewayNodes == 0 {
				return nil, fmt.Errorf("cannot have localPriority AZ affinity mode without maxGatewayNodes set")
			}
		}
	}

	gs := []groupStatus{}

	for _, policyGroupStatus := range iegp.Status.GroupStatuses {
		activeGatewayIPs := []netip.Addr{}
		activeGatewayIPsByAZ := map[string][]netip.Addr{}
		healthyGatewayIPs := []netip.Addr{}

		for _, gwIP := range policyGroupStatus.ActiveGatewayIPs {
			activeGatewayIP, err := netip.ParseAddr(gwIP)
			if err != nil {
				log.WithError(err).Error("Cannot parse active gateway IP")
				continue
			}

			activeGatewayIPs = append(activeGatewayIPs, activeGatewayIP)
		}

		for az, gwIPs := range policyGroupStatus.ActiveGatewayIPsByAZ {
			for _, gwIP := range gwIPs {
				ip, err := netip.ParseAddr(gwIP)
				if err != nil {
					log.WithError(err).Error("Cannot parse AZ active gateway IP")
					continue
				}

				activeGatewayIPsByAZ[az] = append(activeGatewayIPsByAZ[az], ip)
			}
		}

		for _, gwIP := range policyGroupStatus.HealthyGatewayIPs {
			healthyGatewayIP, err := netip.ParseAddr(gwIP)
			if err != nil {
				log.WithError(err).Error("Cannot parse healthy gateway IP")
				continue
			}

			healthyGatewayIPs = append(healthyGatewayIPs, healthyGatewayIP)
		}

		gs = append(gs, groupStatus{
			activeGatewayIPs,
			activeGatewayIPsByAZ,
			healthyGatewayIPs,
		})
	}

	return &PolicyConfig{
		endpointSelectors:       endpointSelectorList,
		dstCIDRs:                dstCidrList,
		excludedCIDRs:           excludedCIDRs,
		matchedEndpoints:        make(map[endpointID]*endpointMetadata),
		azAffinity:              azAffinity,
		groupConfigs:            gcs,
		groupStatusesGeneration: iegp.Status.ObservedGeneration,
		groupStatuses:           gs,
		id: types.NamespacedName{
			Name: name,
		},
		apiVersion: "isovalent.com/v1",
		generation: iegp.GetGeneration(),
	}, nil
}

// ParseIEGPConfigID takes a IsovalentEgressGatewayPolicy CR and returns only the config id
func ParseIEGPConfigID(iegp *v1.IsovalentEgressGatewayPolicy) types.NamespacedName {
	return policyID{
		Name: iegp.Name,
	}
}
