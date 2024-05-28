// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgatewayha

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_fake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
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
}

func (k *EgressGatewayOperatorTestSuite) assertIegpGatewayStatus(tb testing.TB, gs gatewayStatus) {
	var err error
	for i := 0; i < 10; i++ {
		if err = tryAssertIegpGatewayStatus(k.fakeSet, gs); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	assert.Nil(tb, err)
}

func tryAssertIegpGatewayStatus(fakeSet *k8sClient.FakeClientset, gs gatewayStatus) error {
	iegp, err := fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().Get(context.TODO(), "policy-1", metav1.GetOptions{})
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
	k.updatePolicyMaxGatewayNodes(t, policy1, 1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	k.makeNodesUnhealthy("k8s1")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node2IP},
	})

	k.makeNodesHealthy("k8s1")
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	// Allow all gateways
	k.updatePolicyMaxGatewayNodes(t, policy1, 0)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs:  []string{node2IP, node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
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
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
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

	k.makeNodesHealthy(node1Name, node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = k.updateNodeLabels(t, node1, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
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

	// Add back k8s{1,2}
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1 and az-1
	node1 = k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
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

	// Add back k8s{1,2}
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Update the policy to allow at most 1 gateway
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
		activeGatewayIPs: []string{node2IP},
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

	k.makeNodesHealthy(node1Name, node2Name)
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
		activeGatewayIPs: []string{node2IP},
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

	// Add back k8s{1,2}
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
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
		activeGatewayIPs: []string{node2IP},
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

	// Add back k8s{1,2}
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
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
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
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

	k.makeNodesHealthy(node1Name, node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = k.updateNodeLabels(t, node1, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
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

	// Add back k8s{1,2}
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1 and az-1
	node1 = k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
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

	// Add back k8s{1,2}
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node4IP, node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Update the policy to allow at most 1 gateway
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
		activeGatewayIPs: []string{node2IP},
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

	// Make k8s{1,2} healthy again
	k.makeNodesHealthy(node1Name, node2Name)
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
		activeGatewayIPs: []string{node2IP},
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

	// Add back k8s{1,2}
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
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
		activeGatewayIPs: []string{node2IP},
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

	// Add back k8s{1,2}
	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
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
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
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

	k.makeNodesHealthy(node1Name, node2Name)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node4IP, node3IP, node2IP, node1IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	node1 = k.updateNodeLabels(t, node1, nodeNoGroupLabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
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
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node4IP, node3IP, node2IP, node1IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	node1 = k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
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
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node1IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node4IP, node3IP, node2IP, node1IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Update the policy to allow at most 1 gateway
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
		activeGatewayIPs: []string{node2IP},
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

	k.makeNodesHealthy(node1Name, node2Name)
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
		activeGatewayIPs: []string{node2IP},
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
	k.updateNodeLabels(t, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = k.updateNodeLabels(t, node1, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	node2 = k.updateNodeLabels(t, node2, noNodeGroup)
	k.assertIegpGatewayStatus(t, gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.updateNodeLabels(t, node1, nodeGroup1LabelsAZ1)
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
