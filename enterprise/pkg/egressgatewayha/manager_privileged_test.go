// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgatewayha

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/enterprise/pkg/maps/egressmapha"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/identity"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

type EgressGatewayTestSuite struct {
	manager     *Manager
	policies    fakeResource[*Policy]
	endpoints   fakeResource[*k8sTypes.CiliumEndpoint]
	ciliumNodes fakeResource[*cilium_api_v2.CiliumNode]

	reconciliationEventsCount uint64
}

func setupEgressGatewayTestSuite(t *testing.T) *EgressGatewayTestSuite {
	testutils.PrivilegedTest(t)

	bpf.CheckOrMountFS("")
	require.NoError(t, rlimit.RemoveMemlock())

	k := &EgressGatewayTestSuite{}
	k.policies = make(fakeResource[*Policy])
	k.endpoints = make(fakeResource[*k8sTypes.CiliumEndpoint])
	k.ciliumNodes = make(fakeResource[*cilium_api_v2.CiliumNode])

	lc := hivetest.Lifecycle(t)
	policyMap := egressmapha.CreatePrivatePolicyMap(lc, egressmapha.DefaultPolicyConfig)
	ctMap := egressmapha.CreatePrivateCtMap(lc)

	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{
		Node: nodeTypes.Node{
			Name: node1Name,
			IPAddresses: []nodeTypes.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP(node1IP)},
			},
		},
	})

	var err error
	k.manager, err = newEgressGatewayManager(Params{
		Lifecycle:         lc,
		Config:            Config{2 * time.Second, 1 * time.Millisecond},
		DaemonConfig:      &option.DaemonConfig{},
		IdentityAllocator: identityAllocator,
		PolicyMap:         policyMap,
		CtMap:             ctMap,
		Policies:          k.policies,
		Endpoints:         k.endpoints,
		Nodes:             k.ciliumNodes,
		LocalNodeStore:    localNodeStore,
	})
	require.NoError(t, err)
	require.NotNil(t, k.manager)

	k.reconciliationEventsCount = k.manager.reconciliationEventsCount.Load()

	createTestInterface(t, testInterface1, egressCIDR1)
	createTestInterface(t, testInterface2, egressCIDR2)

	k.policies.sync(t)
	k.endpoints.sync(t)
	k.ciliumNodes.sync(t)

	k.waitForReconciliationRun(t)

	return k
}

func createTestInterface(tb testing.TB, iface string, addr string) {
	tb.Helper()

	la := netlink.NewLinkAttrs()
	la.Name = iface
	dummy := &netlink.Dummy{LinkAttrs: la}
	if err := netlink.LinkAdd(dummy); err != nil {
		tb.Fatal(err)
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() {
		if err := netlink.LinkDel(link); err != nil {
			tb.Error(err)
		}
	})

	if err := netlink.LinkSetUp(link); err != nil {
		tb.Fatal(err)
	}

	a, _ := netlink.ParseAddr(addr)
	if err := netlink.AddrAdd(link, a); err != nil {
		tb.Fatal(err)
	}
}

func (k *EgressGatewayTestSuite) waitForReconciliationRun(t *testing.T) {
	for i := 0; i < 100; i++ {
		count := k.manager.reconciliationEventsCount.Load()
		if count > k.reconciliationEventsCount {
			k.reconciliationEventsCount = count
			return
		}

		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("Reconciliation is taking too long to run")
}

func filter(slice []string, x string) []string {
	oldSlice := slice

	slice = []string{}
	for _, oldEntry := range oldSlice {
		if oldEntry != x {
			slice = append(slice, oldEntry)
		}
	}

	return slice
}

func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func (k *EgressGatewayTestSuite) addNode(t *testing.T, name, nodeIP string, nodeLabels map[string]string) nodeTypes.Node {
	node := newCiliumNode(name, nodeIP, nodeLabels)
	addNode(t, k.ciliumNodes, node)
	k.waitForReconciliationRun(t)

	return node
}

func (k *EgressGatewayTestSuite) addPolicy(t *testing.T, policy *policyParams) *policyParams {
	addPolicy(t, nil, k.policies, policy)
	k.waitForReconciliationRun(t)

	return policy
}

func (k *EgressGatewayTestSuite) addHealthyGateway(t *testing.T, policy *policyParams, gwIP string) {
	policy.healthyGatewayIPs = unique(append(policy.activeGatewayIPs, gwIP))

	addPolicy(t, nil, k.policies, policy)
	k.waitForReconciliationRun(t)
}

func (k *EgressGatewayTestSuite) addActiveGateway(t *testing.T, policy *policyParams, gwIP, az string) {
	policy.activeGatewayIPs = unique(append(policy.activeGatewayIPs, gwIP))
	policy.healthyGatewayIPs = unique(append(policy.healthyGatewayIPs, gwIP))

	if az != "" {
		policy.activeGatewayIPsByAZ[az] = unique(append(policy.activeGatewayIPsByAZ[az], gwIP))
	}

	addPolicy(t, nil, k.policies, policy)
	k.waitForReconciliationRun(t)
}

func (k *EgressGatewayTestSuite) removeHealthyGateway(t *testing.T, policy *policyParams, gwIP string) {
	policy.activeGatewayIPs = filter(policy.activeGatewayIPs, gwIP)
	policy.healthyGatewayIPs = filter(policy.healthyGatewayIPs, gwIP)

	for az := range policy.activeGatewayIPsByAZ {
		policy.activeGatewayIPsByAZ[az] = filter(policy.activeGatewayIPsByAZ[az], gwIP)
	}

	addPolicy(t, nil, k.policies, policy)
	k.waitForReconciliationRun(t)
}

func (k *EgressGatewayTestSuite) removeActiveGateway(t *testing.T, policy *policyParams, gwIP string) {
	policy.activeGatewayIPs = filter(policy.activeGatewayIPs, gwIP)

	for az := range policy.activeGatewayIPsByAZ {
		policy.activeGatewayIPsByAZ[az] = filter(policy.activeGatewayIPsByAZ[az], gwIP)
	}

	addPolicy(t, nil, k.policies, policy)
	k.waitForReconciliationRun(t)
}

func (k *EgressGatewayTestSuite) addExcludedCIDR(t *testing.T, policy *policyParams, excludedCIDR string) {
	policy.excludedCIDRs = unique(append(policy.excludedCIDRs, excludedCIDR))

	addPolicy(t, nil, k.policies, policy)
	k.waitForReconciliationRun(t)
}

func (k *EgressGatewayTestSuite) removeExcludedCIDR(t *testing.T, policy *policyParams, excludedCIDR string) {
	policy.excludedCIDRs = filter(policy.excludedCIDRs, excludedCIDR)

	addPolicy(t, nil, k.policies, policy)
	k.waitForReconciliationRun(t)
}

func (k *EgressGatewayTestSuite) addEndpoint(t *testing.T, name, ip string, epLabels map[string]string, nodeIP string) (k8sTypes.CiliumEndpoint, *identity.Identity) {
	ep, id := newEndpointAndIdentity(name, ip, epLabels, nodeIP)
	addEndpoint(t, k.endpoints, &ep)
	k.waitForReconciliationRun(t)

	return ep, id
}

func (k *EgressGatewayTestSuite) updateEndpointLabels(t *testing.T, ep *k8sTypes.CiliumEndpoint, oldID *identity.Identity, newEpLabels map[string]string) *identity.Identity {
	id := updateEndpointAndIdentity(ep, oldID, newEpLabels)
	addEndpoint(t, k.endpoints, ep)
	k.waitForReconciliationRun(t)

	return id
}

type egressRule struct {
	sourceIP  string
	destCIDR  string
	egressIP  string
	gatewayIP string
}

type parsedEgressRule struct {
	sourceIP  netip.Addr
	destCIDR  netip.Prefix
	egressIP  netip.Addr
	gatewayIP netip.Addr
}

func parseEgressRule(sourceIP, destCIDR, egressIP, gatewayIP string) parsedEgressRule {
	sip := netip.MustParseAddr(sourceIP)
	dc := netip.MustParsePrefix(destCIDR)
	eip := netip.MustParseAddr(egressIP)
	gip := netip.MustParseAddr(gatewayIP)

	return parsedEgressRule{
		sourceIP:  sip,
		destCIDR:  dc,
		egressIP:  eip,
		gatewayIP: gip,
	}
}

func (k *EgressGatewayTestSuite) assertEgressRules(t *testing.T, rules []egressRule) {
	t.Helper()

	err := tryAssertEgressRules(k.manager.policyMap, rules)
	require.NoError(t, err)
}

func tryAssertEgressRules(policyMap egressmapha.PolicyMap, rules []egressRule) error {
	parsedRules := []parsedEgressRule{}
	for _, r := range rules {
		parsedRules = append(parsedRules, parseEgressRule(r.sourceIP, r.destCIDR, r.egressIP, r.gatewayIP))
	}

	for _, r := range parsedRules {
		policyVal, err := policyMap.Lookup(r.sourceIP, r.destCIDR)
		if err != nil {
			return fmt.Errorf("cannot lookup policy entry: %w", err)
		}

		if policyVal.GetEgressIP() != r.egressIP {
			return fmt.Errorf("policy egress IP %s doesn't match rule egress IP %s", policyVal.GetEgressIP(), r.egressIP)
		}

		if r.gatewayIP == netip.IPv4Unspecified() {
			if policyVal.Size != 0 {
				return fmt.Errorf("policy size is %d even though no gateway is set", policyVal.Size)
			}
		} else {
			gwFound := false
			for _, policyGatewayIP := range policyVal.GetGatewayIPs() {
				if policyGatewayIP == r.gatewayIP {
					gwFound = true
					break
				}
			}
			if !gwFound {
				return fmt.Errorf("missing gateway %s in policy", r.gatewayIP)
			}
		}
	}

	untrackedRule := false
	policyMap.IterateWithCallback(
		func(key *egressmapha.EgressPolicyKey4, val *egressmapha.EgressPolicyVal4) {
		nextPolicyGateway:
			for _, gatewayIP := range val.GetGatewayIPs() {
				for _, r := range parsedRules {
					if key.Match(r.sourceIP, r.destCIDR) {
						if val.GetEgressIP() == r.egressIP && gatewayIP == r.gatewayIP {
							continue nextPolicyGateway
						}
					}
				}

				untrackedRule = true
				return
			}
		},
	)

	if untrackedRule {
		return fmt.Errorf("Untracked egress policy")
	}

	return nil
}

type egressCtEntry struct {
	// ignoring sport, dport, etc for now
	sourceIP  string
	destIP    string
	gatewayIP string
}

type parsedEgressCtEntry struct {
	sourceIP  netip.Addr
	destIP    netip.Addr
	gatewayIP netip.Addr
}

func parseEgressCtEntry(sourceIP, destIP, gatewayIP string) parsedEgressCtEntry {
	sip := netip.MustParseAddr(sourceIP)
	dip := netip.MustParseAddr(destIP)
	gip := netip.MustParseAddr(gatewayIP)

	return parsedEgressCtEntry{
		sourceIP:  sip,
		destIP:    dip,
		gatewayIP: gip,
	}
}

func (k *EgressGatewayTestSuite) insertEgressCtEntry(t *testing.T, sourceIP, destIP, gatewayIP string) {
	entry := parseEgressCtEntry(sourceIP, destIP, gatewayIP)

	key := &egressmapha.EgressCtKey4{
		TupleKey4: tuple.TupleKey4{
			DestPort:   0,
			SourcePort: 0,
			NextHeader: u8proto.TCP,
			Flags:      0,
		},
	}

	key.DestAddr.FromAddr(entry.destIP)
	key.SourceAddr.FromAddr(entry.sourceIP)

	val := &egressmapha.EgressCtVal4{}
	val.Gateway.FromAddr(entry.gatewayIP)

	err := k.manager.ctMap.Update(key, val, 0)
	require.NoError(t, err)
}

func (k *EgressGatewayTestSuite) assertEgressCtEntries(tb testing.TB, entries []egressCtEntry) {
	tb.Helper()

	err := tryAssertEgressCtEntries(k.manager.ctMap, entries)
	require.NoError(tb, err)
}

func tryAssertEgressCtEntries(ctMap egressmapha.CtMap, entries []egressCtEntry) error {
	parsedEntries := []parsedEgressCtEntry{}
	for _, e := range entries {
		parsedEntries = append(parsedEntries, parseEgressCtEntry(e.sourceIP, e.destIP, e.gatewayIP))
	}

	for _, e := range parsedEntries {
		var val egressmapha.EgressCtVal4

		key := &egressmapha.EgressCtKey4{
			TupleKey4: tuple.TupleKey4{
				DestPort:   0,
				SourcePort: 0,
				NextHeader: u8proto.TCP,
				Flags:      0,
			},
		}

		key.DestAddr.FromAddr(e.destIP)
		key.SourceAddr.FromAddr(e.sourceIP)

		err := ctMap.Lookup(key, &val)
		if err != nil {
			return err
		}

		if val.Gateway.Addr() != e.gatewayIP {
			return fmt.Errorf("%v doesn't match %v", val.Gateway.IP(), e.gatewayIP)
		}
	}

	var err error
	ctMap.IterateWithCallback(
		func(key *egressmapha.EgressCtKey4, val *egressmapha.EgressCtVal4) {
			for _, e := range parsedEntries {
				if key.DestAddr.Addr() == e.destIP && key.SourceAddr.Addr() == e.sourceIP && val.Gateway.Addr() == e.gatewayIP {
					return
				}
			}

			err = fmt.Errorf("untracked egress CT entry: from %v to %v via %v", key.SourceAddr.IP(), key.DestAddr.IP(), val.Gateway.IP())
		})

	return err
}

func TestEgressGatewayIEGPParser(t *testing.T) {
	// must specify name
	policy := policyParams{
		name:            "",
		destinationCIDR: destCIDR,
		iface:           testInterface1,
	}

	iegp, _ := newIEGP(&policy)
	_, err := ParseIEGP(iegp)
	require.Error(t, err)

	// catch nil DestinationCIDR field
	policy = policyParams{
		name:  "policy-1",
		iface: testInterface1,
	}

	iegp, _ = newIEGP(&policy)
	iegp.Spec.DestinationCIDRs = nil
	_, err = ParseIEGP(iegp)
	require.Error(t, err)
	// must specify at least one DestinationCIDR
	policy = policyParams{
		name:  "policy-1",
		iface: testInterface1,
	}

	iegp, _ = newIEGP(&policy)
	_, err = ParseIEGP(iegp)
	require.Error(t, err)

	// catch nil EgressGateway field
	policy = policyParams{
		name:            "policy-1",
		destinationCIDR: destCIDR,
		iface:           testInterface1,
	}

	iegp, _ = newIEGP(&policy)
	iegp.Spec.EgressGroups = nil
	_, err = ParseIEGP(iegp)
	require.Error(t, err)

	// must specify some sort of endpoint selector
	policy = policyParams{
		name:            "policy-1",
		destinationCIDR: destCIDR,
		iface:           testInterface1,
	}

	iegp, _ = newIEGP(&policy)
	iegp.Spec.Selectors[0].NamespaceSelector = nil
	iegp.Spec.Selectors[0].PodSelector = nil
	_, err = ParseIEGP(iegp)
	require.Error(t, err)

	// can't specify both egress iface and IP
	policy = policyParams{
		name:            "policy-1",
		destinationCIDR: destCIDR,
		iface:           testInterface1,
		egressIP:        egressIP1,
	}

	iegp, _ = newIEGP(&policy)
	_, err = ParseIEGP(iegp)
	require.Error(t, err)
}

func TestEgressGatewayManagerHAGroup(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	// Create a new HA policy that selects k8s1 and k8s2 nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:              "policy-1",
		uid:               policy1UID,
		endpointLabels:    ep1Labels,
		destinationCIDR:   destCIDR,
		nodeLabels:        nodeGroup1Labels,
		iface:             testInterface1,
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	k.assertEgressRules(t, []egressRule{})

	// Add a new endpoint which matches policy-1
	ep1, id1 := k.addEndpoint(t, "ep-1", ep1IP, ep1Labels, node1IP)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Remove k8s1
	k.removeHealthyGateway(t, policy1, node1IP)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, zeroIP4, node2IP},
	})

	// Add back node1
	k.addActiveGateway(t, policy1, node1IP, "")
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Remove k8s2
	k.removeHealthyGateway(t, policy1, node2IP)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// Add back k8s2
	k.addActiveGateway(t, policy1, node2IP, "")
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Update the EP labels in order for it to not be a match
	id1 = k.updateEndpointLabels(t, &ep1, id1, map[string]string{})
	k.assertEgressRules(t, []egressRule{})

	// Add back the endpoint
	id1 = k.updateEndpointLabels(t, &ep1, id1, ep1Labels)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Create a new HA policy that matches no nodes
	policy2 := k.addPolicy(t, &policyParams{
		name:            "policy-2",
		uid:             policy2UID,
		endpointLabels:  ep2Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup2Labels,
		iface:           testInterface2,
	})

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Add k8s1 node to policy-2
	k.addActiveGateway(t, policy2, node1IP, "")
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Add a new endpoint that matches policy-2
	ep2, id2 := k.addEndpoint(t, "ep-2", ep2IP, ep2Labels, node1IP)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
		{ep2IP, destCIDR, egressIP2, node1IP},
	})

	// Add also k8s2 to policy-2
	k.addActiveGateway(t, policy2, node2IP, "")
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
		{ep2IP, destCIDR, egressIP2, node1IP},
		{ep2IP, destCIDR, egressIP2, node2IP},
	})

	// Test excluded CIDRs by adding one to policy-1
	k.addExcludedCIDR(t, policy1, excludedCIDR1)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
		{ep1IP, excludedCIDR1, egressIP1, gatewayExcludedCIDRValue},
		{ep2IP, destCIDR, egressIP2, node1IP},
		{ep2IP, destCIDR, egressIP2, node2IP},
	})

	// Add a second excluded CIDR to policy-1
	k.addExcludedCIDR(t, policy1, excludedCIDR2)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
		{ep1IP, excludedCIDR1, egressIP1, gatewayExcludedCIDRValue},
		{ep1IP, excludedCIDR2, egressIP1, gatewayExcludedCIDRValue},
		{ep2IP, destCIDR, egressIP2, node1IP},
		{ep2IP, destCIDR, egressIP2, node2IP},
	})

	// Remove the first excluded CIDR from policy-1
	k.removeExcludedCIDR(t, policy1, excludedCIDR1)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
		{ep1IP, excludedCIDR2, egressIP1, gatewayExcludedCIDRValue},
		{ep2IP, destCIDR, egressIP2, node1IP},
		{ep2IP, destCIDR, egressIP2, node2IP},
	})

	// Remove the second excluded CIDR
	k.removeExcludedCIDR(t, policy1, excludedCIDR2)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
		{ep2IP, destCIDR, egressIP2, node1IP},
		{ep2IP, destCIDR, egressIP2, node2IP},
	})

	// Update the EP 1 labels in order for it to not be a match
	k.updateEndpointLabels(t, &ep1, id1, map[string]string{})
	k.assertEgressRules(t, []egressRule{
		{ep2IP, destCIDR, egressIP2, node1IP},
		{ep2IP, destCIDR, egressIP2, node2IP},
	})

	// Update the EP 2 labels in order for it to not be a match
	k.updateEndpointLabels(t, &ep2, id2, map[string]string{})
	k.assertEgressRules(t, []egressRule{})
}

func TestEgressGatewayManagerHAGroupAZAffinity(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)
	k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s1 and k8s2 nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:             "policy-1",
		uid:              policy1UID,
		endpointLabels:   ep1Labels,
		destinationCIDR:  destCIDR,
		azAffinity:       azAffinityLocalOnly,
		nodeLabels:       nodeGroup1Labels,
		iface:            testInterface1,
		activeGatewayIPs: []string{node1IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node2IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	k.assertEgressRules(t, []egressRule{})

	// Add a new endpoint on node-1 which matches policy-1
	k.addEndpoint(t, "ep-1", ep1IP, ep1Labels, node1IP)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// Add a new endpoint on node-2 which matches policy-1
	k.addEndpoint(t, "ep-2", ep2IP, ep1Labels, node2IP)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})

	// Remove k8s1
	k.removeHealthyGateway(t, policy1, node1IP)
	k.assertEgressRules(t, []egressRule{
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})

	// Add back node1
	k.addActiveGateway(t, policy1, node1IP, "az-1")
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep2IP, destCIDR, zeroIP4, node2IP},
	})
}

func TestEgressGatewayManagerCtEntries(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	// Create a new HA policy based on a group config
	policy1 := k.addPolicy(t, &policyParams{
		name:              "policy-1",
		uid:               policy1UID,
		endpointLabels:    ep1Labels,
		destinationCIDR:   destCIDR,
		nodeLabels:        nodeGroup1Labels,
		iface:             testInterface1,
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	k.assertEgressRules(t, []egressRule{})
	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Add a new endpoint which matches 1
	k.addEndpoint(t, "ep-1", ep1IP, ep1Labels, node1IP)

	/* Scenario:
	 * 1. A gateway becomes unhealthy. Its CT entries should expire.
	 */

	// pretend that the endpoint also opened a connection via k8s2
	k.insertEgressCtEntry(t, ep1IP, destIP, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{
		{ep1IP, destIP, node2IP},
	})

	// Remove k8s2 from 1
	k.removeHealthyGateway(t, policy1, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// CT entry is gone:
	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Add back k8s2 to policy-1
	k.addActiveGateway(t, policy1, node2IP, "")

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{})

	/*
	 * Scenario:
	 * 1. A gateway is no longer selected by the policy's labels.
	 *    Its CT entries should expire.
	 */

	// pretend that the endpoint also opened a connection via k8s2
	k.insertEgressCtEntry(t, ep1IP, destIP, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{
		{ep1IP, destIP, node2IP},
	})

	// Remove k8s2 from node-group-1
	k.removeHealthyGateway(t, policy1, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// CT entry should now also be gone
	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Add back k8s2
	k.addActiveGateway(t, policy1, node2IP, "")

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{})

	/*
	 * Scenario:
	 * 1. De-activate a gateway that is used by an CT entry.
	 *    (the CT entry should not expire, as the gateway is healthy and still selected by labels)
	 * 2. Make the gateway unhealthy.
	 *    (the CT entry should now expire)
	 */

	// pretend that the endpoint also opened a connection via k8s2
	k.insertEgressCtEntry(t, ep1IP, destIP, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{
		{ep1IP, destIP, node2IP},
	})

	// Update the policy group config to allow at most 1 gateway at a time (k8s1)
	k.removeActiveGateway(t, policy1, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// CT entry should still exist, as k8s2 is healthy
	k.assertEgressCtEntries(t, []egressCtEntry{
		{ep1IP, destIP, node2IP},
	})

	// Make k8s2 unhealthy
	k.removeHealthyGateway(t, policy1, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// CT entry should now also be gone
	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Make k8s2 healthy again
	k.addHealthyGateway(t, policy1, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Update the policy group config to allow all gateways again
	k.addActiveGateway(t, policy1, node2IP, "")

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{})

	/*
	 * Scenario:
	 * 1. De-activate a gateway that is used by an CT entry.
	 *    (the CT entry should not expire, as the gateway is healthy and still selected by labels)
	 * 2. De-select the gateway from the policy
	 *    (the CT entry should now expire)
	 */

	// pretend that the endpoint also opened a connection via k8s2
	k.insertEgressCtEntry(t, ep1IP, destIP, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{
		{ep1IP, destIP, node2IP},
	})

	// Update the policy group config to allow at most 1 gateway at a time (k8s1)
	k.removeActiveGateway(t, policy1, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// CT entry should still exist, as k8s2 is healthy
	k.assertEgressCtEntries(t, []egressCtEntry{
		{ep1IP, destIP, node2IP},
	})

	// Remove k8s2 from node-group-1
	k.removeHealthyGateway(t, policy1, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	// CT entry should now also be gone
	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Add back k8s2
	k.addHealthyGateway(t, policy1, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{})

	// Update the policy group config to allow all gateways again
	k.addActiveGateway(t, policy1, node2IP, "")

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{})

	/*
	 * Scenario:
	 * 1. A policy changes and a CT entry is now matched by an excluded CIDR
	 *    (the CT entry should now expire)
	 */
	k.insertEgressCtEntry(t, ep1IP, destIP, node2IP)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{
		{ep1IP, destIP, node2IP},
	})

	// Add the destination IP to the policy excluded CIDRs list
	k.addExcludedCIDR(t, policy1, excludedCIDR3)

	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
		{ep1IP, excludedCIDR3, egressIP1, gatewayExcludedCIDRValue},
	})

	k.assertEgressCtEntries(t, []egressCtEntry{})
}

func TestEndpointDataStore(t *testing.T) {
	k := setupEgressGatewayTestSuite(t)

	// Create a new policy
	k.addPolicy(t, &policyParams{
		name:              "policy-1",
		uid:               policy1UID,
		endpointLabels:    ep1Labels,
		destinationCIDR:   destCIDR,
		nodeLabels:        nodeGroup1Labels,
		iface:             testInterface1,
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	k.assertEgressRules(t, []egressRule{})

	// Add a new endpoint & ID which matches policy-1
	ep1, _ := k.addEndpoint(t, "ep-1", ep1IP, ep1Labels, node1IP)
	k.assertEgressRules(t, []egressRule{
		{ep1IP, destCIDR, egressIP1, node1IP},
		{ep1IP, destCIDR, egressIP1, node2IP},
	})

	// Simulate statefulset pod migrations to a different node.

	// Produce a new endpoint ep2 similar to ep1 - with the same name & labels, but with a different IP address.
	// The ep1 will be deleted.
	ep2, _ := newEndpointAndIdentity(ep1.Name, ep2IP, ep1Labels, node1IP)

	// Test event order: add new -> delete old
	addEndpoint(t, k.endpoints, &ep2)
	k.waitForReconciliationRun(t)
	deleteEndpoint(t, k.endpoints, &ep1)
	k.waitForReconciliationRun(t)

	k.assertEgressRules(t, []egressRule{
		{ep2IP, destCIDR, egressIP1, node1IP},
		{ep2IP, destCIDR, egressIP1, node2IP},
	})

	// Produce a new endpoint ep3 similar to ep2 (and ep1) - with the same name & labels, but with a different IP address.
	ep3, _ := newEndpointAndIdentity(ep1.Name, ep3IP, ep1Labels, node1IP)

	// Test event order: delete old -> update new
	deleteEndpoint(t, k.endpoints, &ep2)
	k.waitForReconciliationRun(t)
	addEndpoint(t, k.endpoints, &ep3)
	k.waitForReconciliationRun(t)

	k.assertEgressRules(t, []egressRule{
		{ep3IP, destCIDR, egressIP1, node1IP},
		{ep3IP, destCIDR, egressIP1, node2IP},
	})
}
