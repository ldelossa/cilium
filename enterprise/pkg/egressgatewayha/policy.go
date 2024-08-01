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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sort"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/exp/maps"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/enterprise/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/linux/netdevice"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// egress gateway IPAM condition types to be set in IEGP status after allocation attempts
	egwIPAMRequestSatisfied = "isovalent.com/IPAMRequestSatisfied"

	egwIPAMInvalidCIDR         = "isovalent.com/InvalidCIDR"
	egwIPAMUnsupportedEgressIP = "isovalent.com/UnsupportedEgressIP"
	egwIPAMPoolExhausted       = "isovalent.com/PoolExhausted"
	egwIPAMPoolConflicting     = "isovalent.com/PoolConflict"
)

// groupConfig is the internal representation of an egress group, describing
// which nodes should act as egress gateway for a given policy
type groupConfig struct {
	nodeSelector    api.EndpointSelector
	iface           string
	egressIP        netip.Addr
	maxGatewayNodes int
}

// azActiveGatewayIPs is a list of active gateway IPs for a particular AZ.
// In addition to the list of IPs, localNodeConfiguredAsGateway specifies if the
// local node is configured as a gateway for the AZ.
type azActiveGatewayIPs struct {
	// list of active gateway IPs for a given AZ
	gatewayIPs []netip.Addr

	// with AZ affinity enabled, within an egress group, the same node can be
	// be configured as gateway for some endpoints, while being not enabled
	// for others.
	//
	// We track this information to determine correctly the egress IP to
	// use for a given endpoint.
	localNodeConfiguredAsGateway bool
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

	// activeGatewayIPsByAZ maps AZs to a slice of node IPs that are
	// actively working as egress gateway for that AZ
	activeGatewayIPsByAZ map[string]azActiveGatewayIPs

	// healthyGatewayIPs is the entire pool of healthy nodes that can act as
	// egress gateway for the given policy.
	// Not all of them may be actively acting as gateway since with the
	// maxGatewayNodes policy directive we can select a subset of them
	healthyGatewayIPs []netip.Addr

	// azAffinity configures the AZ affinity mode for the policy
	azAffinity azAffinityMode

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
	egressIPByGatewayIP  map[netip.Addr]netip.Addr
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
	id                types.NamespacedName
	uid               types.UID
	creationTimestamp time.Time

	apiVersion string
	generation int64
	labels     map[string]string

	endpointSelectors []api.EndpointSelector
	dstCIDRs          []netip.Prefix
	excludedCIDRs     []netip.Prefix
	egressCIDRs       []netip.Prefix

	azAffinity azAffinityMode

	groupConfigs            []groupConfig
	groupStatusesGeneration int64
	groupStatuses           []groupStatus

	matchedEndpoints map[endpointID]*endpointMetadata
	gatewayConfig    gatewayConfig
}

// PolicyID includes policy name and namespace
type policyID = types.NamespacedName

type gwEgressIPConfig struct {
	addr  netip.Addr
	iface string
}

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

func getIEGPForStatusUpdate(iegp *Policy, groupStatuses []groupStatus, conditions []meta_v1.Condition) *Policy {
	iegpGroupStatuses := make([]v1.IsovalentEgressGatewayPolicyGroupStatus, 0, len(groupStatuses))
	for _, gs := range groupStatuses {
		iegpGroupStatuses = append(iegpGroupStatuses, v1.IsovalentEgressGatewayPolicyGroupStatus{
			ActiveGatewayIPs:     toStringSlice(gs.activeGatewayIPs),
			ActiveGatewayIPsByAZ: toStringMapStringSlice(gs.activeGatewayIPsByAZ),
			HealthyGatewayIPs:    toStringSlice(gs.healthyGatewayIPs),
			EgressIPByGatewayIP:  toStringMap(gs.egressIPByGatewayIP),
		})
	}

	policy := &Policy{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       iegp.Kind,
			APIVersion: iegp.APIVersion,
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name:              iegp.GetName(),
			Namespace:         iegp.GetNamespace(),
			ResourceVersion:   iegp.GetResourceVersion(),
			UID:               iegp.GetUID(),
			CreationTimestamp: iegp.GetCreationTimestamp(),
			Labels:            iegp.GetLabels(),
			Annotations:       iegp.GetAnnotations(),
			// The Generation isn't needed in production code, as UpdateStatus ignores the generation.
			// See the comment for the Spec bellow.
			Generation: iegp.GetGeneration(),
		},
		// The Spec isn't needed in production code, as this update object will be passed into an UpdateStatus client-go
		// method, that will promptly ignore the spec. However, it's needed in tests because the fake k8s client
		// implements UpdateStatus in a simplistic way, and overwrites the stored spec with the one on this object.
		// This results in us storing a blank spec, and breaking the test.
		Spec: iegp.Spec,
		Status: v1.IsovalentEgressGatewayPolicyStatus{
			ObservedGeneration: iegp.GetGeneration(),
			GroupStatuses:      iegpGroupStatuses,
		},
	}

	for _, cond := range conditions {
		meta.SetStatusCondition(&policy.Status.Conditions, cond)
	}

	return policy
}

func (gc *groupConfig) computeGroupStatus(operatorManager *OperatorManager, config *PolicyConfig, status *groupStatus) (groupStatus, error) {
	healthyGatewayIPs := []netip.Addr{}

	activeGatewayIPsByAZ := make(map[string][]netip.Addr)
	healthyGatewayIPsByAZ := make(map[string][]netip.Addr)

	for _, node := range operatorManager.nodes {
		// if AZ affinity is enabled for the egress group, track the node's AZ.
		//
		// This will be used later on to ensure that even AZs with no gateway nodes selected by the policy
		// or no healthy gateway nodes can get non-local gateways assigned to
		// (and because of this tracking needs to happen before ignoring a non-gateway node and unhealthy node)
		if config.azAffinity.enabled() {
			if nodeAZ, ok := node.Labels[core_v1.LabelTopologyZone]; ok {
				// as the healthyGatewayIPsByAZ map is used also to keep track of all the available AZs,
				// always create an empty entry if it doesn't exist yet.
				// In this way we can ensure all AZs will have a key in the map
				if _, ok = healthyGatewayIPsByAZ[nodeAZ]; !ok {
					healthyGatewayIPsByAZ[nodeAZ] = []netip.Addr{}
				}
			}
		}

		// if the group config doesn't match the node, ignore it and go to the next one
		if !gc.selectsNodeAsGateway(node) {
			continue
		}

		// if the node is not healthy, ignore it and move to the next one
		if !operatorManager.nodeIsHealthy(node.Name) {
			continue
		}

		nodeIP, ok := netipx.FromStdIP(node.GetK8sNodeIP())
		if !ok {
			return groupStatus{}, fmt.Errorf("unable to convert node IP %s", node.GetK8sNodeIP())
		}

		// add the node to the list of healthy gateway IPs.
		// This list is global (i.e. it doesn't take into account the AZ of the node)
		healthyGatewayIPs = append(healthyGatewayIPs, nodeIP)

		// if AZ affinity is enabled, add the node IP also to the list of healthy gateway IPs
		if config.azAffinity.enabled() {
			if nodeAZ, ok := node.Labels[core_v1.LabelTopologyZone]; ok {
				healthyGatewayIPsByAZ[nodeAZ] = append(healthyGatewayIPsByAZ[nodeAZ], nodeIP)
			} else {
				log.WithField(logfields.NodeName, node.Name).
					Warnf("AZ affinity is enabled but node is missing %s label. Node will be ignored", core_v1.LabelTopologyZone)
			}
		}
	}

	// if AZ affinity is enabled,
	// Choose maxGateway items from the list of per AZ healthy GWs  with random probability.
	// If the selected active GW list is not enough, choose from the non-local active GW list later
	// according to the azAffinity config.
	if config.azAffinity.enabled() {
		for az, healthyGatewayIPs := range healthyGatewayIPsByAZ {
			var currentLocalActiveGWs []netip.Addr
			if status != nil {
				currentLocalActiveGWs = gc.selectCurrentLocalActiveGWs(operatorManager, az, status.activeGatewayIPsByAZ[az])
			}
			activeGWs, err := selectActiveGWs(az, gc.maxGatewayNodes, currentLocalActiveGWs, healthyGatewayIPs)
			if err != nil {
				return groupStatus{}, err
			}
			activeGatewayIPsByAZ[az] = activeGWs
		}
	}

	// nonLocalActiveGatewayIPs is a helper that returns, given a particular AZ, a slice of non local gateways for
	// that AZ.
	//
	// This function selects active non-local GWs from a list of healthy non-local GWs with random probability
	// using a target zone name as a seed to make the result deterministic.
	nonLocalActiveGatewayIPs := func(targetAz string, maxGW int, currentActiveNonLocalGWs []netip.Addr) ([]netip.Addr, error) {
		// sort the AZs lexicographically
		sortedAZs := maps.Keys(healthyGatewayIPsByAZ)
		sort.Strings(sortedAZs)

		var healthyNonLocalGWs []netip.Addr
		for _, az := range sortedAZs {
			if az != targetAz {
				healthyNonLocalGWs = append(healthyNonLocalGWs, healthyGatewayIPsByAZ[az]...)
			}
		}

		activeGWs, err := selectActiveGWs(targetAz, maxGW, currentActiveNonLocalGWs, healthyNonLocalGWs)
		if err != nil {
			return nil, err
		}

		return activeGWs, nil
	}

	// next do a second pass to populate the per-AZ list of active gateways
	switch config.azAffinity {
	case azAffinityLocalOnly:
		// for local only affinity there's nothing left to do

	case azAffinityLocalOnlyFirst:
		for az := range activeGatewayIPsByAZ {
			// only if there are no local gateways, pick the ones from the other AZs
			if len(activeGatewayIPsByAZ[az]) == 0 {
				var currentNonLocalActiveGWs []netip.Addr
				if status != nil {
					currentNonLocalActiveGWs = gc.selectCurrentNonLocalActiveGWs(operatorManager, az, status.activeGatewayIPsByAZ[az])
				}
				nonLocalActiveGWs, err := nonLocalActiveGatewayIPs(az, gc.maxGatewayNodes, currentNonLocalActiveGWs)
				if err != nil {
					return groupStatus{}, err
				}
				activeGatewayIPsByAZ[az] = nonLocalActiveGWs
			}
		}

	case azAffinityLocalPriority:
		for az := range activeGatewayIPsByAZ {
			if gc.maxGatewayNodes != 0 && len(activeGatewayIPsByAZ[az]) < gc.maxGatewayNodes {
				var currentNonLocalActiveGWs []netip.Addr
				if status != nil {
					currentNonLocalActiveGWs = gc.selectCurrentNonLocalActiveGWs(operatorManager, az, status.activeGatewayIPsByAZ[az])
				}
				nonLocalActiveGWs, err := nonLocalActiveGatewayIPs(az, gc.maxGatewayNodes-len(activeGatewayIPsByAZ[az]), currentNonLocalActiveGWs)
				if err != nil {
					return groupStatus{}, err
				}

				activeGatewayIPsByAZ[az] = append(activeGatewayIPsByAZ[az], nonLocalActiveGWs...)
			}
		}
	}

	// Selects the active GWs from a list of the healthy GWs with random probability
	// using a uid as a seed to make the result deterministic. The result is used for the
	// non AZ affinity case.
	//
	// If the active GWs have already been selected, we exclude all the unhealthy and non gateway nodes,
	// and back-fill the currently selected group of active gateways, until maxGateways is reached.
	var currentActiveGWs []netip.Addr
	if status != nil {
		currentActiveGWs = gc.excludeUnhealthyAndStaleGWs(operatorManager, status.activeGatewayIPs)
	}
	activeGatewayIPs, err := selectActiveGWs(string(config.uid), gc.maxGatewayNodes, currentActiveGWs, healthyGatewayIPs)
	if err != nil {
		return groupStatus{}, err
	}

	return groupStatus{
		activeGatewayIPs:     activeGatewayIPs,
		activeGatewayIPsByAZ: activeGatewayIPsByAZ,
		healthyGatewayIPs:    healthyGatewayIPs,
	}, nil
}

// selectCurrentLocalActiveGWs selects the current local active GWs.
// It excludes unhealthy and non-gateway nodes
func (gc *groupConfig) selectCurrentLocalActiveGWs(operatorManager *OperatorManager, az string, currentActiveGWs []netip.Addr) []netip.Addr {
	return gc.selectActiveGWsIf(operatorManager, az, currentActiveGWs, func(nodeAZ, targetAZ string) bool {
		return nodeAZ == targetAZ
	})
}

// selectCurrentNonLocalActiveGWs selects the current non-local active GWs.
// It excludes unhealthy and non-gateway nodes
func (gc *groupConfig) selectCurrentNonLocalActiveGWs(operatorManager *OperatorManager, az string, currentActiveGWs []netip.Addr) []netip.Addr {
	return gc.selectActiveGWsIf(operatorManager, az, currentActiveGWs, func(nodeAZ, targetAZ string) bool {
		return nodeAZ != targetAZ
	})
}

func (gc *groupConfig) selectActiveGWsIf(operatorManager *OperatorManager, az string, currentActiveGWs []netip.Addr, predicate func(nodeAZ, targetAZ string) bool) []netip.Addr {
	var localGWs []netip.Addr
	for _, gw := range currentActiveGWs {
		node, nodeExists := operatorManager.nodesByIP[gw.String()]
		if nodeExists {
			if nodeAZ, azExists := node.Labels[core_v1.LabelTopologyZone]; azExists && predicate(nodeAZ, az) {
				localGWs = append(localGWs, gw)
			}
		}
	}

	return gc.excludeUnhealthyAndStaleGWs(operatorManager, localGWs)
}

// excludeStaleNodes excludes unhealthy nodes and non-gateway nodes from the current active GWs.
func (gc *groupConfig) excludeUnhealthyAndStaleGWs(operatorManager *OperatorManager, currentActiveGWs []netip.Addr) []netip.Addr {
	var activeGWs []netip.Addr
	for _, gw := range currentActiveGWs {
		node, ok := operatorManager.nodesByIP[gw.String()]
		if ok && operatorManager.nodeIsHealthy(node.Name) && gc.selectsNodeAsGateway(node) {
			activeGWs = append(activeGWs, gw)
		}
	}

	return activeGWs
}

// selectActiveGWs selects the maxGW number of the active GWs from the healthy GWs
// with random probability using a seed.
//
// If currentActiveGWs are specified, we back-fill the currently selected active gateways,
// until maxGateways is reached.
func selectActiveGWs(seed string, maxGW int, currentActiveGWs, healthyGWs []netip.Addr) ([]netip.Addr, error) {
	var activeGWs []netip.Addr

	if len(currentActiveGWs) > 0 {
		for _, gw := range currentActiveGWs {
			activeGWs = append(activeGWs, gw)
			if maxGW != 0 && len(activeGWs) == maxGW {
				return activeGWs, nil
			}
		}

		healthyGWs = excludeCurrentActiveGWsFromHealthyGWs(currentActiveGWs, healthyGWs)
	}

	// Choose active GWs from the healthy GWs list with a pseudo-random permutation
	// using a zone name as a seed
	h := sha256.New()
	if _, err := io.WriteString(h, seed); err != nil {
		return nil, err
	}
	s := binary.BigEndian.Uint64(h.Sum(nil))
	r := rand.New(rand.NewPCG(s, 0))
	for _, p := range r.Perm(len(healthyGWs)) {
		activeGWs = append(activeGWs, healthyGWs[p])
		if maxGW != 0 && len(activeGWs) == maxGW {
			break
		}
	}

	return activeGWs, nil
}

// excludeCurrentActiveGWsFromHealthyGWs excludes the gateway nodes that have been already
// selected from the healthy gateways
func excludeCurrentActiveGWsFromHealthyGWs(currentActiveGWs, healthyGWs []netip.Addr) []netip.Addr {
	activeGWsSet := make(map[netip.Addr]bool)
	for _, gw := range currentActiveGWs {
		activeGWsSet[gw] = true
	}

	var result []netip.Addr
	for _, gw := range healthyGWs {
		if !activeGWsSet[gw] {
			result = append(result, gw)
		}
	}

	return result
}

func (config *PolicyConfig) allocateEgressIPs(operatorManager *OperatorManager, groupStatuses []groupStatus) ([]groupStatus, []meta_v1.Condition) {
	egressCIDRs := make([]netip.Prefix, 0, len(config.egressCIDRs))
	for _, cidr := range config.egressCIDRs {
		// detect conflicting CIDRs
		if conflicting, found := operatorManager.cidrConflicts[policyEgressCIDR{config.id, cidr}]; found {
			msg := fmt.Sprintf(
				"egress CIDR %s in policy %s overlaps with egress group %s in policy %s",
				cidr, config.id, conflicting.cidr, conflicting.origin,
			)
			return groupStatuses, conditionsForFailure(config.generation, []meta_v1.Condition{
				{
					Type:               egwIPAMPoolConflicting,
					Status:             meta_v1.ConditionUnknown,
					ObservedGeneration: config.generation,
					LastTransitionTime: meta_v1.Now(),
					Reason:             "noreason",
					Message:            msg,
				},
			}...)
		}
		egressCIDRs = append(egressCIDRs, cidr)
	}

	egressPool, err := newPool(egressCIDRs...)
	if err != nil {
		operatorManager.health.Degraded(fmt.Sprintf("found invalid egress CIDR in policy %s", config.id), err)
		return groupStatuses, conditionsForFailure(config.generation, []meta_v1.Condition{
			{
				Type:               egwIPAMInvalidCIDR,
				Status:             meta_v1.ConditionUnknown,
				ObservedGeneration: config.generation,
				LastTransitionTime: meta_v1.Now(),
				Reason:             "noreason",
				Message:            fmt.Sprintf("found invalid egress CIDR: %s", err),
			},
		}...)
	}

	haveSeenLatestIEGP := config.groupStatusesGeneration == config.generation

	for i := range groupStatuses {
		if addr := config.groupConfigs[i].egressIP; addr.IsValid() {
			msg := "egressIP not supported together with egressCIDR"
			operatorManager.health.Degraded(msg, fmt.Errorf("found egress IP %s in policy %s", addr, config.id))
			return groupStatuses, conditionsForFailure(config.generation, []meta_v1.Condition{
				{
					Type:               egwIPAMUnsupportedEgressIP,
					Status:             meta_v1.ConditionUnknown,
					ObservedGeneration: config.generation,
					LastTransitionTime: meta_v1.Now(),
					Reason:             "noreason",
					Message:            msg,
				},
			}...)
		}

		// check if this group has at least one active gateway, otherwise there is nothing to allocate
		if len(groupStatuses[i].activeGatewayIPs) == 0 {
			continue
		}

		// For all still-active gateways we strive to keep the same allocated Egress IP as before.
		var prevEgressIPs map[netip.Addr]netip.Addr
		if haveSeenLatestIEGP && i < len(config.groupStatuses) {
			prevEgressIPs = config.groupStatuses[i].egressIPByGatewayIP
		}

		// Sort the active gateway IPs so that the allocation algorithm is deterministic.
		activeGatewayIPs := make([]netip.Addr, len(groupStatuses[i].activeGatewayIPs))
		copy(activeGatewayIPs, groupStatuses[i].activeGatewayIPs)
		slices.SortFunc(activeGatewayIPs, func(a, b netip.Addr) int {
			return a.Compare(b)
		})

		groupStatuses[i].egressIPByGatewayIP, err = allocateEgressIPsForGroup(egressPool, activeGatewayIPs, prevEgressIPs)
		if err != nil {
			operatorManager.health.Degraded(fmt.Sprintf("unable to fulfill allocations for policy %s", config.id), err)
			return groupStatuses, conditionsForFailure(config.generation, []meta_v1.Condition{
				{
					Type:               egwIPAMPoolExhausted,
					Status:             meta_v1.ConditionUnknown,
					ObservedGeneration: config.generation,
					LastTransitionTime: meta_v1.Now(),
					Reason:             "noreason",
					Message:            fmt.Sprintf("unable to fulfill allocations: %s", err),
				},
			}...)
		}
	}

	operatorManager.health.OK(fmt.Sprintf("IP allocations completed successfully for policy %s", config.id))

	return groupStatuses, conditionsForSuccess(config.generation)
}

func conditionsForFailure(generation int64, conditions ...meta_v1.Condition) []meta_v1.Condition {
	return append(
		conditions,
		meta_v1.Condition{
			Type:               egwIPAMRequestSatisfied,
			Status:             meta_v1.ConditionFalse,
			ObservedGeneration: generation,
			LastTransitionTime: meta_v1.Now(),
			Reason:             "noreason",
			Message:            "allocation requests not satisfied",
		},
	)
}

func conditionsForSuccess(generation int64, conditions ...meta_v1.Condition) []meta_v1.Condition {
	return append(
		conditions,
		meta_v1.Condition{
			Type:               egwIPAMRequestSatisfied,
			Status:             meta_v1.ConditionTrue,
			ObservedGeneration: generation,
			LastTransitionTime: meta_v1.Now(),
			Reason:             "noreason",
			Message:            "allocation requests satisfied",
		},
	)
}

func allocateEgressIPsForGroup(egressPool *pool, activeGatewayIPs []netip.Addr, prevEgressIPs map[netip.Addr]netip.Addr) (map[netip.Addr]netip.Addr, error) {
	egressIPs := make(map[netip.Addr]netip.Addr)

	newActiveGatewayIPs := make([]netip.Addr, 0, len(activeGatewayIPs))

	// First, try to reserve the same egress IPs previously allocated
	for _, gatewayIP := range activeGatewayIPs {
		if egressIP, found := prevEgressIPs[gatewayIP]; found {
			// in case of failure, discard the error from the allocation attempt
			// and go ahead with a further attempt using a fresh egress IP
			if err := egressPool.allocate(egressIP); err == nil {
				egressIPs[gatewayIP] = egressIP
				continue
			}
		}
		newActiveGatewayIPs = append(newActiveGatewayIPs, gatewayIP)
	}

	// then, back-fill as needed
	for _, gatewayIP := range newActiveGatewayIPs {
		if egressIP, found := prevEgressIPs[gatewayIP]; found {
			// in case of failure, discard the error from the allocation attempt
			// and go ahead with a further attempt using a fresh egress IP
			if err := egressPool.allocate(egressIP); err == nil {
				egressIPs[gatewayIP] = egressIP
				continue
			}
		}

		egressIP, err := egressPool.allocateNext()
		if err != nil {
			return egressIPs, err
		}
		egressIPs[gatewayIP] = egressIP
	}

	return egressIPs, nil
}

// updateGroupStatuses updates the list of active and healthy gateway IPs in the
// IEGP k8s resource for the receiver PolicyConfig
func (config *PolicyConfig) updateGroupStatuses(operatorManager *OperatorManager) error {
	haveSeenLatestIEGP := config.groupStatusesGeneration == config.generation

	groupStatuses := make([]groupStatus, 0, len(config.groupConfigs))
	for i, gc := range config.groupConfigs {
		var status *groupStatus
		if haveSeenLatestIEGP && i < len(config.groupStatuses) {
			status = &config.groupStatuses[i]
		}
		gs, err := gc.computeGroupStatus(operatorManager, config, status)
		if err != nil {
			return err
		}

		groupStatuses = append(groupStatuses, gs)
	}

	var conditions []meta_v1.Condition
	if len(config.egressCIDRs) > 0 {
		groupStatuses, conditions = config.allocateEgressIPs(operatorManager, groupStatuses)
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

	newIEGP := getIEGPForStatusUpdate(operatorManager.policyCache[config.id], groupStatuses, conditions)

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
		egressIP:             netip.IPv4Unspecified(),
		activeGatewayIPs:     []netip.Addr{},
		activeGatewayIPsByAZ: map[string]azActiveGatewayIPs{},
		healthyGatewayIPs:    []netip.Addr{},
		azAffinity:           config.azAffinity,
	}

	if len(config.groupStatuses) == 0 {
		return
	}

	localNode, err := manager.localNodeStore.Get(context.TODO())
	if err != nil {
		log.Error("Failed to get local node store")
		return
	}

	localNodeK8sAddr, ok := netipx.FromStdIP(localNode.GetK8sNodeIP())
	if !ok {
		log.Error("Failed to parse local node IP")
		return
	}

	var egressIPs []gwEgressIPConfig

	gwc := &config.gatewayConfig
	for groupIndex, gc := range config.groupConfigs {
		groupStatus := &config.groupStatuses[groupIndex]
		// We use the local node IP to determine if the current node
		// matches the list of active gateway IPs
		localNodeMatchesGatewayIP := false

		if !gwc.azAffinity.enabled() {
			gwc.activeGatewayIPs = append(gwc.activeGatewayIPs, groupStatus.activeGatewayIPs...)

			if slices.Contains(groupStatus.activeGatewayIPs, localNodeK8sAddr) {
				localNodeMatchesGatewayIP = true
			}
		} else {
			for az, gwIPs := range groupStatus.activeGatewayIPsByAZ {
				azGwIPs, ok := gwc.activeGatewayIPsByAZ[az]
				if !ok {
					azGwIPs = azActiveGatewayIPs{
						gatewayIPs: []netip.Addr{},
					}
				}
				azGwIPs.gatewayIPs = append(azGwIPs.gatewayIPs, gwIPs...)

				if slices.Contains(gwIPs, localNodeK8sAddr) {
					localNodeMatchesGatewayIP = true
					azGwIPs.localNodeConfiguredAsGateway = true
				}

				gwc.activeGatewayIPsByAZ[az] = azGwIPs
			}
		}
		gwc.healthyGatewayIPs = append(gwc.healthyGatewayIPs, groupStatus.healthyGatewayIPs...)

		logger := log.WithFields(logrus.Fields{
			logfields.IsovalentEgressGatewayPolicyName: config.id,
			logfields.Interface:                        gc.iface,
			logfields.EgressIP:                         gc.egressIP,
		})

		if localNodeMatchesGatewayIP {
			// If localNodeConfiguredAsGateway is already set it means that another
			// egress group for the same policy has already selected it as gateway. In
			// this case don't regenerate a new gatewayConfig and return an error
			if gwc.localNodeConfiguredAsGateway {
				logger.WithError(err).Error("Local node selected by multiple egress gateway groups from the same policy")
			}

			if egressIP, found := groupStatus.egressIPByGatewayIP[localNodeK8sAddr]; found {
				var (
					iface netlink.Link
					err   error
				)
				if gc.iface != "" {
					iface, err = netlink.LinkByName(gc.iface)
				} else {
					iface, err = route.NodeDeviceWithDefaultRoute(true, false)
				}
				if err != nil {
					logger.WithError(err).Error("Failed to find interface while updating node egress IP config")
					continue
				}

				egressIPs = append(egressIPs, gwEgressIPConfig{egressIP, iface.Attrs().Name})

				gwc.ifaceName = iface.Attrs().Name
				gwc.egressIP = egressIP
			} else if err := gwc.deriveFromGroupConfig(&gc); err != nil {
				logger.WithError(err).Error("Failed to derive policy gateway configuration")
			}

			gwc.localNodeConfiguredAsGateway = true
		}
	}

	// upsert all the egress configs <egress IP, egress interface, destination CIDRs>
	// from the current status of the policy and remove the configs from the previous policy status
	nextEgressIPs := sets.New(egressIPs...)
	curEgressIPs := manager.egressConfigsByPolicy[config.id]
	toDel := curEgressIPs.Difference(nextEgressIPs)
	updateEgressIPsConfig(manager.db, manager.egressIPTable, nextEgressIPs, toDel, config.dstCIDRs)
	manager.egressConfigsByPolicy[config.id] = nextEgressIPs

}

func updateEgressIPsConfig(
	db *statedb.DB,
	table statedb.RWTable[*tables.EgressIPEntry],
	toUpsert, toDel sets.Set[gwEgressIPConfig],
	destinations []netip.Prefix,
) {
	txn := db.WriteTxn(table)
	defer txn.Abort()

	for _, config := range toDel.UnsortedList() {
		table.Delete(txn, &tables.EgressIPEntry{
			Addr:      config.addr,
			Interface: config.iface,
		})
	}

	for _, config := range toUpsert.UnsortedList() {
		table.Insert(txn, &tables.EgressIPEntry{
			Addr:         config.addr,
			Interface:    config.iface,
			Destinations: destinations,
			Status:       reconciler.StatusPending(),
		})
	}

	txn.Commit()
}

// deriveFromGroupConfig retrieves all the missing gateway configuration data
// (such as egress IP or interface) given a policy group config
func (gwc *gatewayConfig) deriveFromGroupConfig(gc *groupConfig) error {
	var err error

	switch {
	case gc.iface != "":
		// If the group config specifies an interface, use the first IPv4 assigned to that
		// interface as egress IP
		gwc.ifaceName = gc.iface
		gwc.egressIP, err = netdevice.GetIfaceFirstIPv4Address(gc.iface)
		if err != nil {
			gwc.egressIP = EgressIPNotFoundIPv4
			return fmt.Errorf("failed to retrieve IPv4 address for egress interface: %w", err)
		}
	case gc.egressIP.IsValid():
		// If the group config specifies an egress IP, use the interface with that IP as egress
		// interface
		gwc.egressIP = gc.egressIP
		gwc.ifaceName, err = netdevice.GetIfaceWithIPv4Address(gc.egressIP)
		if err != nil {
			return fmt.Errorf("failed to retrieve interface with egress IP: %w", err)
		}
	default:
		// If the group config doesn't specify any egress IP or interface, us
		// the interface with the IPv4 default route
		iface, err := route.NodeDeviceWithDefaultRoute(true, false)
		if err != nil {
			gwc.egressIP = EgressIPNotFoundIPv4
			return fmt.Errorf("failed to find interface with default route: %w", err)
		}

		gwc.ifaceName = iface.Attrs().Name
		gwc.egressIP, err = netdevice.GetIfaceFirstIPv4Address(gwc.ifaceName)
		if err != nil {
			gwc.egressIP = EgressIPNotFoundIPv4
			return fmt.Errorf("failed to retrieve IPv4 address for egress interface: %w", err)
		}
	}

	return nil
}

// gatewayConfigForEndpoint returns the configuration of active gateway IPs
// and egress IP for a given endpoint
//
// If the AZ resolution fails, this method will fallback to the non AZ-aware list of active gateway IPs
func (gwc *gatewayConfig) gatewayConfigForEndpoint(manager *Manager, endpoint *endpointMetadata) ([]netip.Addr, netip.Addr) {
	egressIP := netip.IPv4Unspecified()
	if gwc.localNodeConfiguredAsGateway {
		egressIP = gwc.egressIP
	}

	if !gwc.azAffinity.enabled() {
		return gwc.activeGatewayIPs, egressIP
	}

	logger := log.WithFields(logrus.Fields{
		logfields.EndpointID: endpoint.id,
		logfields.K8sNodeIP:  endpoint.nodeIP.String,
	})

	endpointNode, ok := manager.nodesByIP[endpoint.nodeIP.String()]
	if !ok {
		logger.Error("cannot find endpoint's node")

		//fallback to the non AZ-aware list of gateway IPs
		return gwc.activeGatewayIPs, egressIP
	}

	az, ok := endpointNode.Labels[core_v1.LabelTopologyZone]
	if !ok {
		logger.Errorf("missing node's AZ label")

		//fallback to the non AZ-aware list of gateway IPs
		return gwc.activeGatewayIPs, egressIP
	}

	egressIP = netip.IPv4Unspecified()
	if gwc.activeGatewayIPsByAZ[az].localNodeConfiguredAsGateway {
		egressIP = gwc.egressIP
	}

	return gwc.activeGatewayIPsByAZ[az].gatewayIPs, egressIP
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
	var egressCIDRs []netip.Prefix

	allowAllNamespacesRequirement := slim_metav1.LabelSelectorRequirement{
		Key:      k8sConst.PodNamespaceLabel,
		Operator: slim_metav1.LabelSelectorOpExists,
	}

	name := iegp.ObjectMeta.Name
	if name == "" {
		return nil, fmt.Errorf("must have a name")
	}

	uid := iegp.UID
	if uid == "" {
		return nil, fmt.Errorf("must have a uid")
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

		gc := groupConfig{
			nodeSelector:    api.NewESFromK8sLabelSelector("", gcSpec.NodeSelector),
			iface:           gcSpec.Interface,
			maxGatewayNodes: gcSpec.MaxGatewayNodes,
		}

		// EgressIP is not a required field, validate and parse it only if non-empty
		if gcSpec.EgressIP != "" {
			egressIP, err := netip.ParseAddr(gcSpec.EgressIP)
			if err != nil {
				return nil, fmt.Errorf("failed to parse egress IP %s: %w", gcSpec.EgressIP, err)
			}
			gc.egressIP = egressIP
		}

		gcs = append(gcs, gc)
	}

	for _, cidrString := range destinationCIDRs {
		cidr, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			return nil, fmt.Errorf("failed to parse destination CIDR %s: %w", cidrString, err)
		}
		dstCidrList = append(dstCidrList, cidr)
	}

	for _, cidrString := range iegp.Spec.ExcludedCIDRs {
		cidr, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			return nil, fmt.Errorf("failed to parse excluded CIDR %s: %w", cidr, err)
		}
		excludedCIDRs = append(excludedCIDRs, cidr)
	}

	for _, cidrString := range iegp.Spec.EgressCIDRs {
		cidr, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			return nil, fmt.Errorf("failed to parse egress CIDR %s: %w", cidr, err)
		}
		egressCIDRs = append(egressCIDRs, cidr)
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
		egressIPByGatewayIP := make(map[netip.Addr]netip.Addr)

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

		for gwIP, egressIP := range policyGroupStatus.EgressIPByGatewayIP {
			gwAddr, err := netip.ParseAddr(gwIP)
			if err != nil {
				log.WithError(err).Error("Cannot parse gateway IP")
				continue
			}

			egressAddr, err := netip.ParseAddr(egressIP)
			if err != nil {
				log.WithError(err).Error("Cannot parse allocated egress IP")
				continue
			}

			egressIPByGatewayIP[gwAddr] = egressAddr
		}

		gs = append(gs, groupStatus{
			activeGatewayIPs,
			activeGatewayIPsByAZ,
			healthyGatewayIPs,
			egressIPByGatewayIP,
		})
	}

	return &PolicyConfig{
		labels:                  iegp.Labels,
		endpointSelectors:       endpointSelectorList,
		dstCIDRs:                dstCidrList,
		excludedCIDRs:           excludedCIDRs,
		egressCIDRs:             egressCIDRs,
		matchedEndpoints:        make(map[endpointID]*endpointMetadata),
		azAffinity:              azAffinity,
		groupConfigs:            gcs,
		groupStatusesGeneration: iegp.Status.ObservedGeneration,
		groupStatuses:           gs,
		id: types.NamespacedName{
			Name: name,
		},
		uid:               uid,
		creationTimestamp: iegp.CreationTimestamp.Time,
		apiVersion:        "isovalent.com/v1",
		generation:        iegp.GetGeneration(),
	}, nil
}

// ParseIEGPConfigID takes a IsovalentEgressGatewayPolicy CR and returns only the config id
func ParseIEGPConfigID(iegp *v1.IsovalentEgressGatewayPolicy) types.NamespacedName {
	return policyID{
		Name: iegp.Name,
	}
}

func toStringSlice(s []netip.Addr) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		out = append(out, v.String())
	}
	return out
}

func toStringMap(m map[netip.Addr]netip.Addr) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k.String()] = v.String()
	}
	return out
}

func toStringMapStringSlice(m map[string][]netip.Addr) map[string][]string {
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = toStringSlice(v)
	}
	return out
}
