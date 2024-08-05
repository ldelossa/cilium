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
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha/healthcheck"
	"github.com/cilium/cilium/pkg/identity"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/policy/api"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	core_v1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

const (
	testInterface1 = "cilium_egwha1"
	testInterface2 = "cilium_egwha2"

	node1Name = "k8s1"
	node2Name = "k8s2"
	node3Name = "k8s3"
	node4Name = "k8s4"
	node5Name = "k8s5"
	node6Name = "k8s6"

	node1IP = "192.168.1.1"
	node2IP = "192.168.1.2"
	node3IP = "192.168.1.3"
	node4IP = "192.168.1.4"
	node5IP = "192.168.1.5"
	node6IP = "192.168.1.6"

	ep1IP = "10.0.0.1"
	ep2IP = "10.0.0.2"
	ep3IP = "10.0.0.3"

	destCIDR        = "1.1.1.0/24"
	destCIDR3       = "1.1.3.0/24"
	destIP          = "1.1.1.1"
	allZeroDestCIDR = "0.0.0.0/0"
	excludedCIDR1   = "1.1.1.22/32"
	excludedCIDR2   = "1.1.1.240/30"
	excludedCIDR3   = "1.1.1.0/28"

	egressIP1   = "192.168.101.1"
	egressCIDR1 = "192.168.101.1/24"

	egressIP2   = "192.168.102.1"
	egressCIDR2 = "192.168.102.1/24"

	zeroIP4 = "0.0.0.0"

	// Special values for gatewayIP, see pkg/egressgateway/manager.go
	gatewayNotFoundValue     = "0.0.0.0"
	gatewayExcludedCIDRValue = "0.0.0.1"

	// Special values for egressIP, see pkg/egressgateway/manager.go
	egressIPNotFoundValue = "0.0.0.0"

	policy1UID = "d68a62ea-f358-4016-87c2-7ae9724f74f7"
	policy2UID = "953b7b1a-1fb3-42e6-add5-4763381e124f"
	policy3UID = "1217a56e-cbe0-472f-8576-040acdbb5f90"
)

var (
	ep1Labels = map[string]string{"test-key": "test-value-1"}
	ep2Labels = map[string]string{"test-key": "test-value-2"}

	identityAllocator = testidentity.NewMockIdentityAllocator(nil)

	noNodeGroup      = map[string]string{}
	nodeGroup1Labels = map[string]string{"label1": "1"}
	nodeGroup2Labels = map[string]string{"label2": "2"}

	nodeGroup1LabelsAZ1  = map[string]string{"label1": "1", core_v1.LabelTopologyZone: "az-1"}
	nodeGroup1LabelsAZ2  = map[string]string{"label1": "1", core_v1.LabelTopologyZone: "az-2"}
	nodeNoGroupLabelsAZ1 = map[string]string{core_v1.LabelTopologyZone: "az-1"}

	advertisePolicyLabels   = map[string]string{"advertise": "bgp"}
	advertisePolicySelector = &slimv1.LabelSelector{
		MatchLabels: advertisePolicyLabels,
	}
)

type fakeResource[T runtime.Object] chan resource.Event[T]

func (fr fakeResource[T]) sync(tb testing.TB) {
	var sync resource.Event[T]
	sync.Kind = resource.Sync
	fr.process(tb, sync)
}

func (fr fakeResource[T]) process(tb testing.TB, ev resource.Event[T]) {
	tb.Helper()
	if err := fr.processWithError(ev); err != nil {
		tb.Fatal("Failed to process event:", err)
	}
}

func (fr fakeResource[T]) processWithError(ev resource.Event[T]) error {
	errs := make(chan error)
	ev.Done = func(err error) {
		errs <- err
	}
	fr <- ev
	return <-errs
}

func (fr fakeResource[T]) Observe(ctx context.Context, next func(event resource.Event[T]), complete func(error)) {
	complete(errors.New("not implemented"))
}

func (fr fakeResource[T]) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[T] {
	if len(opts) > 1 {
		// Ideally we'd only ignore resource.WithRateLimit here, but that
		// isn't possible.
		panic("more than one option is not supported")
	}
	return fr
}

func (fr fakeResource[T]) Store(context.Context) (resource.Store[T], error) {
	return nil, errors.New("not implemented")
}

func addPolicy(tb testing.TB, fakeSet *k8sClient.FakeClientset, policies fakeResource[*Policy], params *policyParams) {
	tb.Helper()

	policy, _ := newIEGP(params)

	if fakeSet != nil {
		_, err := fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().
			Create(context.TODO(), policy, metav1.CreateOptions{})
		if !k8sErrors.IsAlreadyExists(err) {
			assert.Nil(tb, err)
		}
	}

	addIEGP(tb, policies, policy)
}

func addIEGP(tb testing.TB, policies fakeResource[*Policy], policy *v1.IsovalentEgressGatewayPolicy) {
	tb.Helper()

	policies.process(tb, resource.Event[*Policy]{
		Kind:   resource.Upsert,
		Object: policy,
	})
}

func addEndpoint(tb testing.TB, endpoints fakeResource[*k8sTypes.CiliumEndpoint], ep *k8sTypes.CiliumEndpoint) {
	endpoints.process(tb, resource.Event[*k8sTypes.CiliumEndpoint]{
		Kind:   resource.Upsert,
		Object: ep,
	})
}

func deleteEndpoint(tb testing.TB, endpoints fakeResource[*k8sTypes.CiliumEndpoint], ep *k8sTypes.CiliumEndpoint) {
	endpoints.process(tb, resource.Event[*k8sTypes.CiliumEndpoint]{
		Kind:   resource.Delete,
		Object: ep,
	})
}

func addNode(tb testing.TB, nodes fakeResource[*cilium_api_v2.CiliumNode], node nodeTypes.Node) {
	nodes.process(tb, resource.Event[*cilium_api_v2.CiliumNode]{
		Kind:   resource.Upsert,
		Object: node.ToCiliumNode(),
	})
}

type healthcheckerMock struct {
	lock.RWMutex

	nodes  map[string]struct{}
	events chan healthcheck.Event
}

func (h *healthcheckerMock) UpdateNodeList(nodes map[string]nodeTypes.Node) {
}

func (h *healthcheckerMock) NodeIsHealthy(nodeName string) bool {
	h.Lock()
	defer h.Unlock()

	_, ok := h.nodes[nodeName]
	return ok
}

func (h *healthcheckerMock) Events() chan healthcheck.Event {
	return h.events
}

func (h *healthcheckerMock) addNodes(nodes ...string) {
	h.Lock()
	defer h.Unlock()

	for _, n := range nodes {
		h.nodes[n] = struct{}{}
	}
}

func (h *healthcheckerMock) deleteNodes(nodes ...string) {
	h.Lock()
	defer h.Unlock()

	for _, n := range nodes {
		delete(h.nodes, n)
	}
}

func newHealthcheckerMock() *healthcheckerMock {
	return &healthcheckerMock{
		nodes:  make(map[string]struct{}),
		events: make(chan healthcheck.Event),
	}
}

type policyParams struct {
	name                 string
	uid                  types.UID
	generation           int64
	labels               map[string]string
	endpointLabels       map[string]string
	destinationCIDR      string
	excludedCIDRs        []string
	nodeLabels           map[string]string
	iface                string
	egressIP             string
	maxGatewayNodes      int
	azAffinity           azAffinityMode
	activeGatewayIPs     []string
	activeGatewayIPsByAZ map[string][]string
	healthyGatewayIPs    []string
	observedGeneration   int64
}

func newIEGP(params *policyParams) (*Policy, *PolicyConfig) {
	// Note we avoid 'MustParse*()' varieties here to allow testing how
	// poor input is handed to ParseIEGP().
	parsedDestinationCIDR, _ := netip.ParsePrefix(params.destinationCIDR)

	parsedExcludedCIDRs := []netip.Prefix{}
	for _, excludedCIDR := range params.excludedCIDRs {
		parsedExcludedCIDR, _ := netip.ParsePrefix(excludedCIDR)
		parsedExcludedCIDRs = append(parsedExcludedCIDRs, parsedExcludedCIDR)
	}

	parsedActiveGatewayIPs := []netip.Addr{}
	for _, activeGatewayIP := range params.activeGatewayIPs {
		parsedActiveGatewayIPs = append(parsedActiveGatewayIPs, netip.MustParseAddr(activeGatewayIP))
	}

	parsedActiveGatewayIPsByAZ := map[string][]netip.Addr{}
	for az, activeGatewayIPs := range params.activeGatewayIPsByAZ {
		for _, activeGatewayIP := range activeGatewayIPs {
			parsedActiveGatewayIPsByAZ[az] = append(parsedActiveGatewayIPsByAZ[az], netip.MustParseAddr(activeGatewayIP))
		}
	}

	parsedHealthyGatewayIPs := []netip.Addr{}
	for _, healthyGatewayIP := range params.healthyGatewayIPs {
		parsedHealthyGatewayIPs = append(parsedHealthyGatewayIPs, netip.MustParseAddr(healthyGatewayIP))
	}

	policy := &PolicyConfig{
		id: types.NamespacedName{
			Name: params.name,
		},
		uid:                     params.uid,
		generation:              params.generation,
		groupStatusesGeneration: params.observedGeneration,
		dstCIDRs:                []netip.Prefix{parsedDestinationCIDR},
		excludedCIDRs:           parsedExcludedCIDRs,
		azAffinity:              params.azAffinity,
		labels:                  params.labels,
		endpointSelectors: []api.EndpointSelector{
			{
				LabelSelector: &slimv1.LabelSelector{
					MatchLabels: params.endpointLabels,
				},
			},
		},
		groupConfigs: []groupConfig{
			{
				nodeSelector: api.EndpointSelector{
					LabelSelector: &slimv1.LabelSelector{
						MatchLabels: params.endpointLabels,
					},
				},
				iface:           params.iface,
				maxGatewayNodes: params.maxGatewayNodes,
			},
		},
		groupStatuses: []groupStatus{
			{
				activeGatewayIPs:     parsedActiveGatewayIPs,
				activeGatewayIPsByAZ: parsedActiveGatewayIPsByAZ,
				healthyGatewayIPs:    parsedHealthyGatewayIPs,
			},
		},
	}

	if len(params.endpointLabels) != 0 {
		policy.endpointSelectors = []api.EndpointSelector{
			{
				LabelSelector: &slimv1.LabelSelector{
					MatchLabels: params.endpointLabels,
				},
			},
		}
	}

	excludedCIDRs := []v1.IPv4CIDR{}
	for _, excludedCIDR := range params.excludedCIDRs {
		excludedCIDRs = append(excludedCIDRs, v1.IPv4CIDR(excludedCIDR))
	}

	iegp := &Policy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       params.name,
			UID:        params.uid,
			Generation: params.generation,
			Labels:     params.labels,
		},
		Spec: v1.IsovalentEgressGatewayPolicySpec{
			Selectors: []v1.EgressRule{
				{
					PodSelector: &slimv1.LabelSelector{
						MatchLabels: params.endpointLabels,
					},
				},
			},
			DestinationCIDRs: []v1.IPv4CIDR{
				v1.IPv4CIDR(params.destinationCIDR),
			},
			ExcludedCIDRs: excludedCIDRs,
			AZAffinity:    params.azAffinity.toString(),

			EgressGroups: []v1.EgressGroup{
				{
					NodeSelector: &slimv1.LabelSelector{
						MatchLabels: params.nodeLabels,
					},
					Interface:       params.iface,
					EgressIP:        params.egressIP,
					MaxGatewayNodes: params.maxGatewayNodes,
				},
			},
		},
		Status: v1.IsovalentEgressGatewayPolicyStatus{
			GroupStatuses: []v1.IsovalentEgressGatewayPolicyGroupStatus{
				{
					ActiveGatewayIPs:     params.activeGatewayIPs,
					ActiveGatewayIPsByAZ: params.activeGatewayIPsByAZ,
					HealthyGatewayIPs:    params.healthyGatewayIPs,
				},
			},
			ObservedGeneration: params.observedGeneration,
		},
	}

	return iegp, policy
}

func newCiliumNode(name, nodeIP string, nodeLabels map[string]string) nodeTypes.Node {
	n := nodeTypes.Node{
		Name: name,
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP(nodeIP),
			},
		},
	}

	if len(nodeLabels) != 0 {
		n.Labels = nodeLabels
	}

	return n
}

// Mock the creation of endpoint and its corresponding identity, returns endpoint and ID.
func newEndpointAndIdentity(name, ip string, epLabels map[string]string, nodeIP string) (k8sTypes.CiliumEndpoint, *identity.Identity) {
	id, _, _ := identityAllocator.AllocateIdentity(context.Background(), labels.Map2Labels(epLabels, labels.LabelSourceK8s), true, identity.InvalidIdentity)

	return k8sTypes.CiliumEndpoint{
		ObjectMeta: slimv1.ObjectMeta{
			Name: name,
			UID:  types.UID(uuid.New().String()),
		},
		Identity: &cilium_api_v2.EndpointIdentity{
			ID: int64(id.ID),
		},
		Networking: &cilium_api_v2.EndpointNetworking{
			Addressing: cilium_api_v2.AddressPairList{
				&cilium_api_v2.AddressPair{
					IPV4: ip,
				},
			},
			NodeIP: nodeIP,
		},
	}, id
}

// Mock the update of endpoint and its corresponding identity, with new labels. Returns new ID.
func updateEndpointAndIdentity(endpoint *k8sTypes.CiliumEndpoint, oldID *identity.Identity, newEpLabels map[string]string) *identity.Identity {
	ctx := context.Background()

	identityAllocator.Release(ctx, oldID, true)
	newID, _, _ := identityAllocator.AllocateIdentity(ctx, labels.Map2Labels(newEpLabels, labels.LabelSourceK8s), true, identity.InvalidIdentity)
	endpoint.Identity.ID = int64(newID.ID)
	return newID
}
