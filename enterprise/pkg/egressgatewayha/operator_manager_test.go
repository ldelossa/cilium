// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgatewayha

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_fake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type EgressGatewayOperatorTestSuite struct {
	manager           *OperatorManager
	fakeSet           *k8sClient.FakeClientset
	healthcheckerMock *healthcheckerMock

	policies fakeResource[*Policy]
	nodes    fakeResource[*cilium_api_v2.CiliumNode]
}

func setupEgressGatewayOperatorTestSuite(t *testing.T) *EgressGatewayOperatorTestSuite {
	k := &EgressGatewayOperatorTestSuite{}
	k.fakeSet = &k8sClient.FakeClientset{CiliumFakeClientset: cilium_fake.NewSimpleClientset()}
	k.policies = make(fakeResource[*Policy])
	k.nodes = make(fakeResource[*cilium_api_v2.CiliumNode])
	k.healthcheckerMock = newHealthcheckerMock()

	k.manager = newEgressGatewayOperatorManager(OperatorParams{
		Config:        OperatorConfig{1 * time.Millisecond},
		Clientset:     k.fakeSet,
		Policies:      k.policies,
		Nodes:         k.nodes,
		Healthchecker: k.healthcheckerMock,
		Lifecycle:     hivetest.Lifecycle(t),
	})

	k.healthcheckerMock.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
		"k8s5": {},
		"k8s6": {},
	}

	require.NotNil(t, k.manager)

	k.policies.sync(t)
	k.nodes.sync(t)

	return k
}

func (k *EgressGatewayOperatorTestSuite) addNode(t *testing.T, name, nodeIP string, nodeLabels map[string]string) nodeTypes.Node {
	node := newCiliumNode(name, nodeIP, nodeLabels)
	addNode(t, k.nodes, node)

	return node
}

func (k *EgressGatewayOperatorTestSuite) updateNodeLabels(t *testing.T, node nodeTypes.Node, labels map[string]string) nodeTypes.Node {
	node.Labels = labels
	addNode(t, k.nodes, node)

	return node
}

func (k *EgressGatewayOperatorTestSuite) addPolicy(t *testing.T, policy *policyParams) *policyParams {
	addPolicy(t, k.fakeSet, k.policies, policy)
	return policy
}

func (k *EgressGatewayOperatorTestSuite) updatePolicyMaxGatewayNodes(t *testing.T, policy *policyParams, n int) *policyParams {
	policy.maxGatewayNodes = n
	addPolicy(t, k.fakeSet, k.policies, policy)
	return policy
}

func (k *EgressGatewayOperatorTestSuite) getCurrentStatusForUpdate(t *testing.T, policy *policyParams) *policyParams {
	iegp, err := k.fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Get(context.TODO(), policy.name, metav1.GetOptions{})
	assert.Nil(t, err)

	policy.generation = iegp.Generation + 1

	iegpGs := iegp.Status.GroupStatuses[0]
	policy.activeGatewayIPs = iegpGs.ActiveGatewayIPs
	policy.activeGatewayIPsByAZ = iegpGs.ActiveGatewayIPsByAZ
	policy.healthyGatewayIPs = iegpGs.HealthyGatewayIPs
	// The operator is responsible for updating the ObservedGeneration
	policy.observedGeneration = iegp.Status.ObservedGeneration

	return policy
}

func (k *EgressGatewayOperatorTestSuite) makeNodesHealthy(nodes ...string) {
	k.healthcheckerMock.addNodes(nodes...)
	k.manager.reconciliationTrigger.Trigger()
}

func (k *EgressGatewayOperatorTestSuite) makeNodesUnhealthy(nodes ...string) {
	k.healthcheckerMock.deleteNodes(nodes...)
	k.manager.reconciliationTrigger.Trigger()
}

type gatewayStatus struct {
	activeGatewayIPs     []string
	activeGatewayIPsByAZ map[string][]string
	healthyGatewayIPs    []string
	egressIPByGatewayIP  map[string]string
}

func (k *EgressGatewayOperatorTestSuite) assertIegpGatewayStatus(tb testing.TB, gs gatewayStatus) {
	k.assertIegpGatewayStatusFromPolicy(tb, "policy-1", gs)
}

func (k *EgressGatewayOperatorTestSuite) assertIegpGatewayStatusFromPolicy(tb testing.TB, policy string, gs gatewayStatus) {
	var err error
	for i := 0; i < 10; i++ {
		if err = tryAssertIegpGatewayStatus(k.fakeSet, policy, gs); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	assert.Nil(tb, err)
}

func tryAssertIegpGatewayStatus(fakeSet *k8sClient.FakeClientset, policy string, gs gatewayStatus) error {
	iegp, err := fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Get(context.TODO(), policy, metav1.GetOptions{})
	if err != nil {
		return err
	}

	iegpGs := iegp.Status.GroupStatuses[0]

	if !cmp.Equal(gs.activeGatewayIPs, iegpGs.ActiveGatewayIPs, cmpopts.EquateEmpty()) {
		return fmt.Errorf("active gateway IPs don't match expected ones: %v vs expected %v", iegpGs.ActiveGatewayIPs, gs.activeGatewayIPs)
	}

	if !cmp.Equal(gs.activeGatewayIPsByAZ, iegpGs.ActiveGatewayIPsByAZ, cmpopts.EquateEmpty()) {
		return fmt.Errorf("active gateway IPs by AZ don't match expected ones: %v vs expected %v", iegpGs.ActiveGatewayIPsByAZ, gs.activeGatewayIPsByAZ)
	}

	if !cmp.Equal(gs.healthyGatewayIPs, iegpGs.HealthyGatewayIPs, cmpopts.EquateEmpty()) {
		return fmt.Errorf("healthy gateway IPs don't match expected ones: %v vs expected %v", iegpGs.HealthyGatewayIPs, gs.healthyGatewayIPs)
	}

	if !cmp.Equal(gs.egressIPByGatewayIP, iegpGs.EgressIPByGatewayIP, cmpopts.EquateEmpty()) {
		return fmt.Errorf("egress IPs by gateway IPs don't match expected ones: %v vs expected %v", iegpGs.EgressIPByGatewayIP, gs.egressIPByGatewayIP)
	}

	return nil
}

func (k *EgressGatewayOperatorTestSuite) assertIegpStatusConditions(tb testing.TB, conds []metav1.Condition) {
	k.assertIegpStatusConditionsFromPolicy(tb, "policy-1", conds)
}

func (k *EgressGatewayOperatorTestSuite) assertIegpStatusConditionsFromPolicy(tb testing.TB, policy string, conds []metav1.Condition) {
	var err error
	for i := 0; i < 10; i++ {
		if err = tryAssertIegpStatusConditions(k.fakeSet, policy, conds); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	assert.Nil(tb, err)
}

func tryAssertIegpStatusConditions(fakeSet *k8sClient.FakeClientset, policy string, conds []metav1.Condition) error {
	iegp, err := fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Get(context.TODO(), policy, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if len(conds) != len(iegp.Status.Conditions) {
		return fmt.Errorf("expected %d conditions, got %d", len(conds), len(iegp.Status.Conditions))
	}
	for _, cond := range conds {
		found := meta.FindStatusCondition(iegp.Status.Conditions, cond.Type)
		if found == nil {
			return fmt.Errorf("unable to find expected condition type %s", cond.Type)
		}
		if found.Status != cond.Status {
			return fmt.Errorf("expected condition type %s to have status %s, got %s", cond.Type, cond.Status, found.Status)
		}
	}

	return nil
}

func TestEgressGatewayOperatorManagerHAGroup(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	node1 := k.addNode(t, node1Name, node1IP, nodeGroup1Labels)
	k.addNode(t, node2Name, node2IP, nodeGroup1Labels)

	// Create a new HA policy that selects k8s1 and k8s2 nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP, node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	k.makeNodesUnhealthy("k8s1")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node2IP},
	})

	k.makeNodesHealthy("k8s1")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP, node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	// Remove k8s1 from node-group-1
	k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node2IP},
	})

	// Add back k8s1
	k.updateNodeLabels(t, node1, nodeGroup1Labels)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP, node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	// Update the policy to allow at most 1 gateway
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updatePolicyMaxGatewayNodes(t, policy1, 1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	k.makeNodesUnhealthy("k8s2")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP},
		healthyGatewayIPs: []string{node1IP},
	})

	k.makeNodesHealthy("k8s2")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	// Allow all gateways
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updatePolicyMaxGatewayNodes(t, policy1, 0)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP, node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})
}

func TestEgressGatewayOperatorManagerHAGroupNodeRestartScenario(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	// Check if we don't calculate the active GWs twice when an active GW restarts
	// When activeGWs are node1 and node2, if node1 goes down, then activeGWs are node2 and node3
	// Even if node1 is up again , activeGWs, node2 and node3 stay.
	k.addNode(t, node1Name, node1IP, nodeGroup1Labels)
	k.addNode(t, node2Name, node2IP, nodeGroup1Labels)
	node3 := k.addNode(t, node3Name, node3IP, nodeGroup1Labels)

	// Create a new HA policy that selects k8s1, k8s2 and k8s3 nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
		maxGatewayNodes: 2,
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP},
	})

	k.makeNodesUnhealthy("k8s1")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP, node3IP},
		healthyGatewayIPs: []string{node2IP, node3IP},
	})

	k.makeNodesHealthy("k8s1")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP, node3IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP},
	})

	// Check if we don't recalculate the active GWs twice when an active GW is removed and added
	k.updateNodeLabels(t, node3, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP, node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	k.updateNodeLabels(t, node3, nodeGroup1Labels)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP, node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP},
	})

	// Check if we ignore the previous status when we update the IEGP. (increment its generation)
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updatePolicyMaxGatewayNodes(t, policy1, 2)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP},
	})
}

func TestEgressGatewayManagerWithoutNodeSelector(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	k.addNode(t, node1Name, node1IP, nodeGroup1Labels)
	k.addNode(t, node2Name, node2IP, nodeGroup1Labels)

	// Create a new policy without nodeSelector
	k.addPolicy(t, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		egressIP:        egressIP1,
	})

	// Operator should select no active / healthy gateways for this policy
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{},
		healthyGatewayIPs: []string{},
	})
}

func TestEgressGatewayOperatorManagerHAGroupAZAffinityLocalOnly(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	node1 := k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	node2 := k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node3Name, node3IP, nodeGroup1LabelsAZ2)
	k.addNode(t, node4Name, node4IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4} nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
		azAffinity:      azAffinityLocalOnly,
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.makeNodesHealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = k.updateNodeLabels(t, node1, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = k.updateNodeLabels(t, node2, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s1
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Add back k8s2
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1 and az-1
	node1 = k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1 and az-1
	node2 = k.updateNodeLabels(t, node2, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s1
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Add back k8s2
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Update the policy to allow at most 1 gateway
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updatePolicyMaxGatewayNodes(t, policy1, 1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.makeNodesHealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = k.updateNodeLabels(t, node1, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = k.updateNodeLabels(t, node2, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s1
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Add back k8s2
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1 and az-1
	node1 = k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1 and az-1
	node2 = k.updateNodeLabels(t, node2, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s1
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Add back k8s2
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow all gateways
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updatePolicyMaxGatewayNodes(t, policy1, 0)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
}

func TestEgressGatewayOperatorManagerNodeRestartScenarioLocalOnly(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	// Check if we don't calculate the active GWs for az-1 twice when an active GW restarts
	//
	// When activeGWs are node1 and node2, if node1 goes down, then activeGWs are node2, node3
	// Even if node1 is up again, the activeGWs, node2 and node3 stay.
	k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node3Name, node3IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node4Name, node4IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4} nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
		azAffinity:      azAffinityLocalOnlyFirst,
		maxGatewayNodes: 2,
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Check if we ignore the previous status when we update the IEGP. (increment its generation)
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updatePolicyMaxGatewayNodes(t, policy1, 2)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
}

func TestEgressGatewayOperatorManagerHAGroupAZAffinityLocalOnlyFirst(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	node1 := k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	node2 := k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node3Name, node3IP, nodeGroup1LabelsAZ2)
	k.addNode(t, node4Name, node4IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4} nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
		azAffinity:      azAffinityLocalOnlyFirst,
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP, node4IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.makeNodesHealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = k.updateNodeLabels(t, node1, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = k.updateNodeLabels(t, node2, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP, node4IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s1
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Add back k8s2
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1 and az-1
	node1 = k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1 and az-1
	node2 = k.updateNodeLabels(t, node2, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s1
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Add back k8s2
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Update the policy to allow at most 1 gateway
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updatePolicyMaxGatewayNodes(t, policy1, 1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Make k8s1 healthy again
	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Make k8s2 healthy again
	k.makeNodesHealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = k.updateNodeLabels(t, node1, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = k.updateNodeLabels(t, node2, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s1
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Add back k8s2
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1 and az-1
	node1 = k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1 and az-1
	node2 = k.updateNodeLabels(t, node2, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s1
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Add back k8s2
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow all gateways
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updatePolicyMaxGatewayNodes(t, policy1, 0)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
}

func TestEgressGatewayOperatorManagerNodeRestartScenarioLocalOnlyFirst(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	// Check if we don't calculate the active GWs for az-1 twice when an active GW restarts
	//
	// For local GWs:
	// When activeGWs are node1 and node2, if node1 goes down, then activeGWs are node2 and node3
	// Even if node1 is up again, the activeGWs, node2 and node3 stay.
	//
	// For non-local GWs:
	// When all local GWs go down, activeGWs are node4 and node5, if node4 goes down, then activeGWs are node5 and  node6
	// Even if node5 is up again, the activeGWs, node5 and node6 stay,
	k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node3Name, node3IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node4Name, node4IP, nodeGroup1LabelsAZ2)
	k.addNode(t, node5Name, node5IP, nodeGroup1LabelsAZ2)
	k.addNode(t, node6Name, node6IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4,5,6} nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
		azAffinity:      azAffinityLocalOnlyFirst,
		maxGatewayNodes: 2,
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node5IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP},
			"az-2": {node6IP, node5IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP, node5IP, node6IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node5IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP},
			"az-2": {node6IP, node5IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP, node5IP, node6IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node5IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP},
			"az-2": {node6IP, node5IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP, node5IP, node6IP},
	})

	k.makeNodesUnhealthy(node1Name, node2Name, node3Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node5IP, node6IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node5IP, node4IP},
			"az-2": {node6IP, node5IP},
		},
		healthyGatewayIPs: []string{node4IP, node5IP, node6IP},
	})

	k.makeNodesUnhealthy(node4Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node5IP, node6IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node5IP, node6IP},
			"az-2": {node6IP, node5IP},
		},
		healthyGatewayIPs: []string{node5IP, node6IP},
	})

	k.makeNodesHealthy(node4Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node5IP, node6IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node5IP, node6IP},
			"az-2": {node6IP, node5IP},
		},
		healthyGatewayIPs: []string{node4IP, node5IP, node6IP},
	})

	// Check if we ignore the previous status when we update the IEGP. (increment its generation)
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updatePolicyMaxGatewayNodes(t, policy1, 2)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node5IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node5IP, node4IP},
			"az-2": {node6IP, node5IP},
		},
		healthyGatewayIPs: []string{node4IP, node5IP, node6IP},
	})
}

func TestEgressGatewayOperatorManagerHAGroupAZAffinityLocalPriority(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	node1 := k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	node2 := k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node3Name, node3IP, nodeGroup1LabelsAZ2)
	k.addNode(t, node4Name, node4IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4} nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
		azAffinity:      azAffinityLocalPriority,
		maxGatewayNodes: 4,
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node4IP, node3IP, node2IP, node1IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP, node4IP},
			"az-2": {node4IP, node3IP, node2IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP, node4IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node3IP, node4IP},
			"az-2": {node4IP, node3IP, node1IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.makeNodesHealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node4IP, node3IP, node1IP, node2IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	node1 = k.updateNodeLabels(t, node1, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP, node4IP},
			"az-2": {node4IP, node3IP, node2IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	node2 = k.updateNodeLabels(t, node2, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP, node4IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node3IP, node4IP},
			"az-2": {node4IP, node3IP, node1IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node4IP, node3IP, node1IP, node2IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	node1 = k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP, node4IP},
			"az-2": {node4IP, node3IP, node2IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	node2 = k.updateNodeLabels(t, node2, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node3IP, node4IP},
			"az-2": {node4IP, node3IP, node1IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP, node1IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node4IP, node3IP, node1IP, node2IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Update the policy to allow at most 1 gateway
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updatePolicyMaxGatewayNodes(t, policy1, 1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.makeNodesHealthy(node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	node1 = k.updateNodeLabels(t, node1, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	node2 = k.updateNodeLabels(t, node2, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1 and az-1
	node1 = k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1 and az-1
	node2 = k.updateNodeLabels(t, node2, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow 2 gateways
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updatePolicyMaxGatewayNodes(t, policy1, 2)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow 3 gateways
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updatePolicyMaxGatewayNodes(t, policy1, 3)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP},
			"az-2": {node4IP, node3IP, node2IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow all 4 gateways
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updatePolicyMaxGatewayNodes(t, policy1, 4)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node4IP, node3IP, node2IP, node1IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
}

func TestEgressGatewayOperatorManagerNodeRestartScenarioLocalPriority(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	// Check if we don't calculate the active GWs for az-1 twice when an active GW restarts
	//
	// When activeGWs are node1 and node2, if node1 goes down, then activeGWs are node2 and node3
	// Even if node1 is up again, the activeGWs, node2 and node3 stay.
	//
	// When node1 and node3 go down, select node2(local) and node5(non-local)
	// If node5 goes down, pick another non-local node4.
	// Even if node5 is up again, the activeGWs, node2 and node4 stay.
	k.addNode(t, node1Name, node1IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node3Name, node3IP, nodeGroup1LabelsAZ1)
	k.addNode(t, node4Name, node4IP, nodeGroup1LabelsAZ2)
	k.addNode(t, node5Name, node5IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4,5} nodes
	policy1 := k.addPolicy(t, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
		azAffinity:      azAffinityLocalPriority,
		maxGatewayNodes: 2,
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP},
			"az-2": {node5IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP, node5IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP},
			"az-2": {node5IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP, node5IP},
	})

	k.makeNodesHealthy(node1Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node3IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP},
			"az-2": {node5IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP, node5IP},
	})

	k.makeNodesUnhealthy(node1Name, node3Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node5IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node4IP},
			"az-2": {node5IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node4IP, node5IP},
	})

	k.makeNodesUnhealthy(node4Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node5IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node5IP},
			"az-2": {node5IP, node2IP},
		},
		healthyGatewayIPs: []string{node2IP, node5IP},
	})

	k.makeNodesHealthy(node4Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node5IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node5IP},
			"az-2": {node5IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node4IP, node5IP},
	})

	// Check if we ignore the previous status when we update the IEGP. (increment its generation)
	policy1 = k.getCurrentStatusForUpdate(t, policy1)
	k.updatePolicyMaxGatewayNodes(t, policy1, 2)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node4IP},
			"az-2": {node5IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node4IP, node5IP},
	})
}

func TestEgressCIDRConflictsDetection(t *testing.T) {
	testCases := []struct {
		name     string
		policies []v1.IsovalentEgressGatewayPolicy
		expected map[policyEgressCIDR]policyEgressCIDR
	}{
		{
			name: "no egress cidrs",
			policies: []v1.IsovalentEgressGatewayPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "policy-1",
						UID:  policy1UID,
					},
					Spec: v1.IsovalentEgressGatewayPolicySpec{
						DestinationCIDRs: []v1.IPv4CIDR{destCIDR},
						EgressCIDRs:      []v1.IPv4CIDR{},
					},
				},
			},
			expected: map[policyEgressCIDR]policyEgressCIDR{},
		},
		{
			name: "internal conflict for repeated egress cidr",
			policies: []v1.IsovalentEgressGatewayPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "policy-1",
						UID:  policy1UID,
					},
					Spec: v1.IsovalentEgressGatewayPolicySpec{
						DestinationCIDRs: []v1.IPv4CIDR{destCIDR},
						EgressCIDRs: []v1.IPv4CIDR{
							v1.IPv4CIDR("10.100.255.48/30"),
							v1.IPv4CIDR("10.100.255.48/30"),
							v1.IPv4CIDR("10.100.255.48/30"),
						},
					},
				},
			},
			expected: map[policyEgressCIDR]policyEgressCIDR{
				{policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.48/30")}: {policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.48/30")},
			},
		},
		{
			name: "internal conflict",
			policies: []v1.IsovalentEgressGatewayPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "policy-1",
						UID:  policy1UID,
					},
					Spec: v1.IsovalentEgressGatewayPolicySpec{
						DestinationCIDRs: []v1.IPv4CIDR{destCIDR},
						EgressCIDRs: []v1.IPv4CIDR{
							v1.IPv4CIDR("10.100.255.48/30"),
							v1.IPv4CIDR("10.100.255.49/30"),
						},
					},
				},
			},
			expected: map[policyEgressCIDR]policyEgressCIDR{
				{policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.48/30")}: {policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.49/30")},
				{policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.49/30")}: {policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.48/30")},
			},
		},
		{
			name: "external conflict",
			policies: []v1.IsovalentEgressGatewayPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "policy-1",
						UID:               policy1UID,
						CreationTimestamp: metav1.NewTime(time.Now()),
					},
					Spec: v1.IsovalentEgressGatewayPolicySpec{
						DestinationCIDRs: []v1.IPv4CIDR{destCIDR},
						EgressCIDRs: []v1.IPv4CIDR{
							v1.IPv4CIDR("10.100.255.48/30"),
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "policy-2",
						UID:               policy2UID,
						CreationTimestamp: metav1.NewTime(time.Now().Add(time.Second)),
					},
					Spec: v1.IsovalentEgressGatewayPolicySpec{
						DestinationCIDRs: []v1.IPv4CIDR{destCIDR},
						EgressCIDRs: []v1.IPv4CIDR{
							v1.IPv4CIDR("10.100.255.49/30"),
						},
					},
				},
			},
			expected: map[policyEgressCIDR]policyEgressCIDR{
				{policyID{Name: "policy-2"}, netip.MustParsePrefix("10.100.255.49/30")}: {policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.48/30")},
			},
		},
		{
			name: "internal conflict overrides external",
			policies: []v1.IsovalentEgressGatewayPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "policy-1",
						UID:  policy1UID,
					},
					Spec: v1.IsovalentEgressGatewayPolicySpec{
						DestinationCIDRs: []v1.IPv4CIDR{destCIDR},
						EgressCIDRs: []v1.IPv4CIDR{
							v1.IPv4CIDR("10.100.255.48/30"),
							v1.IPv4CIDR("10.100.255.49/30"),
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "policy-2",
						UID:  policy2UID,
					},
					Spec: v1.IsovalentEgressGatewayPolicySpec{
						DestinationCIDRs: []v1.IPv4CIDR{destCIDR},
						EgressCIDRs: []v1.IPv4CIDR{
							v1.IPv4CIDR("10.100.255.49/30"),
						},
					},
				},
			},
			expected: map[policyEgressCIDR]policyEgressCIDR{
				{policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.48/30")}: {policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.49/30")},
				{policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.49/30")}: {policyID{Name: "policy-1"}, netip.MustParsePrefix("10.100.255.48/30")},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			manager := OperatorManager{
				policyConfigs: make(map[policyID]*PolicyConfig),
			}

			for i, policy := range tc.policies {
				// EgressGroups cannot be empty when parsing IEGP
				policy.Spec.EgressGroups = []v1.EgressGroup{
					{
						NodeSelector: &slimv1.LabelSelector{
							MatchLabels: noNodeGroup,
						},
					},
				}

				policyCfg, err := ParseIEGP(&policy)
				if err != nil {
					t.Fatalf("failed to parse policy %d: %s", i, err)
				}
				manager.policyConfigs[policyCfg.id] = policyCfg
			}

			manager.updateEgressCIDRConflicts()

			if !maps.Equal(manager.cidrConflicts, tc.expected) {
				t.Fatalf("expected conflicts:\n%v\nfound:\n%v", tc.expected, manager.cidrConflicts)
			}
		})
	}
}

func TestEgressCIDRAllocation(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	k.addNode(t, node1Name, node1IP, nodeGroup1Labels)
	k.addNode(t, node2Name, node2IP, nodeGroup1Labels)
	k.addNode(t, node3Name, node3IP, nodeGroup1Labels)
	k.addNode(t, node4Name, node4IP, nodeGroup1Labels)

	// Create a new HA policy that selects all four nodes and request IPs from
	// CIDR "10.100.255.48/30"
	policy := k.addPolicy(t, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		egressCIDRs:     []string{"10.100.255.48/30"},
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
	})

	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node4IP, node2IP, node1IP, node3IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		egressIPByGatewayIP: map[string]string{
			node1IP: "10.100.255.48",
			node2IP: "10.100.255.49",
			node3IP: "10.100.255.50",
			node4IP: "10.100.255.51",
		},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionTrue,
		},
	})

	// Adding one node should lead to only 4 IPs allocated, since the pool is a "/30" CIDR
	k.addNode(t, node5Name, node5IP, nodeGroup1Labels)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node4IP, node2IP, node1IP, node3IP, node5IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP, node5IP},
		egressIPByGatewayIP: map[string]string{
			node1IP: "10.100.255.48",
			node2IP: "10.100.255.49",
			node3IP: "10.100.255.50",
			node4IP: "10.100.255.51",
		},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionFalse,
		},
		{
			Type:   egwIPAMPoolExhausted,
			Status: metav1.ConditionUnknown,
		},
	})

	// If 3 nodes goes unhealthy, IPs will be allocated only for the 2 nodes still healthy
	k.makeNodesUnhealthy("k8s2")
	k.makeNodesUnhealthy("k8s3")
	k.makeNodesUnhealthy("k8s4")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node5IP},
		healthyGatewayIPs: []string{node1IP, node5IP},
		egressIPByGatewayIP: map[string]string{
			node1IP: "10.100.255.48",
			node5IP: "10.100.255.49",
		},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionTrue,
		},
	})

	// When 2 out of the 3 nodes become healthy again, the previous active gateways (k8s1 and k8s5)
	// retain the allocated IP
	k.makeNodesHealthy("k8s2")
	k.makeNodesHealthy("k8s3")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node5IP, node3IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node5IP},
		egressIPByGatewayIP: map[string]string{
			node1IP: "10.100.255.48",
			node5IP: "10.100.255.49",
			node2IP: "10.100.255.50",
			node3IP: "10.100.255.51",
		},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionTrue,
		},
	})

	// Update the policy to allow at most 1 gateway, only a single IP will be allocated
	k.updatePolicyMaxGatewayNodes(t, policy, 1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node5IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node5IP},
		egressIPByGatewayIP: map[string]string{
			node5IP: "10.100.255.48",
		},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionTrue,
		},
	})

	// User-specified EgressIP are not supported when relying on egress-gateway IPAM
	policy.egressIP = "10.100.255.48"
	policy.iface = "" // clear the interface, since having both iface and egressIP is not supported
	addPolicy(t, k.fakeSet, k.policies, policy)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node5IP},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node5IP},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionFalse,
		},
		{
			Type:   egwIPAMUnsupportedEgressIP,
			Status: metav1.ConditionUnknown,
		},
	})
}

func TestEgressCIDRAllocationWithConflicts(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	k.addNode(t, node1Name, node1IP, nodeGroup1Labels)
	k.addNode(t, node2Name, node2IP, nodeGroup1Labels)

	// Create a new HA policy that selects nodes k8s1 and k8s2 and request IPs from
	// CIDR "10.100.255.48/30"
	policy1 := k.addPolicy(t, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		egressCIDRs:     []string{"10.100.255.48/30"},
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
	})

	k.addNode(t, node3Name, node3IP, nodeGroup2Labels)
	k.addNode(t, node4Name, node4IP, nodeGroup2Labels)

	// Create a new HA policy that selects nodes k8s3 and k8s4 and request IPs from
	// the same CIDR "10.100.255.48/30"
	policy2 := k.addPolicy(t, &policyParams{
		name:            "policy-2",
		uid:             policy2UID,
		endpointLabels:  ep2Labels,
		destinationCIDR: destCIDR,
		egressCIDRs:     []string{"10.100.255.48/30"},
		nodeLabels:      nodeGroup2Labels,
		iface:           testInterface1,
	})

	// since policy2 is requesting allocations from a conflicting CIDR, it won't get any IP
	k.assertIegpGatewayStatusFromPolicy(t, policy1.name, gatewayStatus{
		activeGatewayIPs:  []string{node2IP, node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
		egressIPByGatewayIP: map[string]string{
			node1IP: "10.100.255.48",
			node2IP: "10.100.255.49",
		},
	})
	k.assertIegpStatusConditionsFromPolicy(t, policy1.name, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionTrue,
		},
	})
	k.assertIegpGatewayStatusFromPolicy(t, policy2.name, gatewayStatus{
		activeGatewayIPs:    []string{node4IP, node3IP},
		healthyGatewayIPs:   []string{node3IP, node4IP},
		egressIPByGatewayIP: map[string]string{},
	})
	k.assertIegpStatusConditionsFromPolicy(t, policy2.name, []metav1.Condition{
		{
			Type:   egwIPAMRequestSatisfied,
			Status: metav1.ConditionFalse,
		},
		{
			Type:   egwIPAMPoolConflicting,
			Status: metav1.ConditionUnknown,
		},
	})
}

func TestEgressCIDRAllocationWithoutCIDRs(t *testing.T) {
	k := setupEgressGatewayOperatorTestSuite(t)

	k.addNode(t, node1Name, node1IP, nodeGroup1Labels)
	k.addNode(t, node2Name, node2IP, nodeGroup1Labels)
	k.addNode(t, node3Name, node3IP, nodeGroup1Labels)
	k.addNode(t, node4Name, node4IP, nodeGroup1Labels)

	// Create a new HA policy that selects all four nodes and do not specify
	// any egress CIDRs (no IPAM)
	k.addPolicy(t, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
	})

	// no egress IPs and no Condition should be found in Status
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:    []string{node4IP, node2IP, node1IP, node3IP},
		healthyGatewayIPs:   []string{node1IP, node2IP, node3IP, node4IP},
		egressIPByGatewayIP: map[string]string{},
	})
	k.assertIegpStatusConditions(t, []metav1.Condition{})
}
