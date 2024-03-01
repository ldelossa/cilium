// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgatewayha

import (
	"context"
	"fmt"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/hive/hivetest"
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

var _ = Suite(&EgressGatewayOperatorTestSuite{})

func (k *EgressGatewayOperatorTestSuite) SetUpTest(c *C) {
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
		Lifecycle:     hivetest.Lifecycle(c),
	})

	k.healthcheckerMock.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
	}

	c.Assert(k.manager, NotNil)

	k.policies.sync(c)
	k.nodes.sync(c)
}

func (k *EgressGatewayOperatorTestSuite) addNode(c *C, name, nodeIP string, nodeLabels map[string]string) nodeTypes.Node {
	node := newCiliumNode(name, nodeIP, nodeLabels)
	addNode(c, k.nodes, node)

	return node
}

func (k *EgressGatewayOperatorTestSuite) updateNodeLabels(c *C, node nodeTypes.Node, labels map[string]string) nodeTypes.Node {
	node.Labels = labels
	addNode(c, k.nodes, node)

	return node
}

func (k *EgressGatewayOperatorTestSuite) addPolicy(c *C, policy *policyParams) *policyParams {
	addPolicy(c, k.fakeSet, k.policies, policy)
	return policy
}

func (k *EgressGatewayOperatorTestSuite) updatePolicyMaxGatewayNodes(c *C, policy *policyParams, n int) *policyParams {
	policy.maxGatewayNodes = n
	addPolicy(c, k.fakeSet, k.policies, policy)
	return policy
}

func (k *EgressGatewayOperatorTestSuite) makeNodesHealthy(nodes ...string) {
	for _, n := range nodes {
		k.healthcheckerMock.nodes[n] = struct{}{}
	}

	k.manager.reconciliationTrigger.Trigger()
}

func (k *EgressGatewayOperatorTestSuite) makeNodesUnhealthy(nodes ...string) {
	for _, n := range nodes {
		delete(k.healthcheckerMock.nodes, n)
	}

	k.manager.reconciliationTrigger.Trigger()
}

type gatewayStatus struct {
	activeGatewayIPs     []string
	activeGatewayIPsByAZ map[string][]string
	healthyGatewayIPs    []string
}

func (k *EgressGatewayOperatorTestSuite) assertIegpGatewayStatus(tb testing.TB, policyName string, gs gatewayStatus) {
	var err error
	for i := 0; i < 10; i++ {
		if err = tryAssertIegpGatewayStatus(tb, k.fakeSet, policyName, gs); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	assert.Nil(tb, err)
}

func tryAssertIegpGatewayStatus(tb testing.TB, fakeSet *k8sClient.FakeClientset, policyName string, gs gatewayStatus) error {
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

func (k *EgressGatewayOperatorTestSuite) TestEgressGatewayOperatorManagerHAGroup(c *C) {
	node1 := k.addNode(c, node1Name, node1IP, nodeGroup1Labels)
	k.addNode(c, node2Name, node2IP, nodeGroup1Labels)

	// Create a new HA policy that selects k8s1 and k8s2 nodes
	policy1 := k.addPolicy(c, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
	})

	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node2IP, node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	k.makeNodesUnhealthy("k8s1")
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node2IP},
	})

	k.makeNodesHealthy("k8s1")
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node2IP, node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	// Remove k8s1 from node-group-1
	k.updateNodeLabels(c, node1, noNodeGroup)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node2IP},
	})

	// Add back k8s1
	k.updateNodeLabels(c, node1, nodeGroup1Labels)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node2IP, node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	// Update the policy to allow at most 1 gateway
	k.updatePolicyMaxGatewayNodes(c, policy1, 1)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	k.makeNodesUnhealthy("k8s1")
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node2IP},
	})

	k.makeNodesHealthy("k8s1")
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	// Allow all gateways
	k.updatePolicyMaxGatewayNodes(c, policy1, 0)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node2IP, node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})
}

func (k *EgressGatewayOperatorTestSuite) TestEgressGatewayManagerWithoutNodeSelector(c *C) {
	k.addNode(c, node1Name, node1IP, nodeGroup1Labels)
	k.addNode(c, node2Name, node2IP, nodeGroup1Labels)

	// Create a new policy without nodeSelector
	k.addPolicy(c, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		egressIP:        egressIP1,
	})

	// Operator should select no active / healthy gateways for this policy
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{},
		healthyGatewayIPs: []string{},
	})
}

func (k *EgressGatewayOperatorTestSuite) TestEgressGatewayOperatorManagerHAGroupAZAffinityLocalOnly(c *C) {
	node1 := k.addNode(c, node1Name, node1IP, nodeGroup1LabelsAZ1)
	node2 := k.addNode(c, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(c, node3Name, node3IP, nodeGroup1LabelsAZ2)
	k.addNode(c, node4Name, node4IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4} nodes
	policy1 := k.addPolicy(c, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
		azAffinity:      azAffinityLocalOnly,
	})

	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node1IP, node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name, node2Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node1IP, node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = k.updateNodeLabels(c, node1, noNodeGroup)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = k.updateNodeLabels(c, node2, noNodeGroup)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s{1,2}
	k.updateNodeLabels(c, node1, nodeGroup1LabelsAZ1)
	k.updateNodeLabels(c, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node1IP, node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Update the policy to allow at most 1 gateway
	k.updatePolicyMaxGatewayNodes(c, policy1, 1)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name, node2Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = k.updateNodeLabels(c, node2, noNodeGroup)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = k.updateNodeLabels(c, node1, noNodeGroup)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s{1,2}
	k.updateNodeLabels(c, node1, nodeGroup1LabelsAZ1)
	k.updateNodeLabels(c, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow all gateways
	k.updatePolicyMaxGatewayNodes(c, policy1, 0)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node1IP, node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
}

func (k *EgressGatewayOperatorTestSuite) TestEgressGatewayOperatorManagerHAGroupAZAffinityLocalOnlyFirst(c *C) {
	node1 := k.addNode(c, node1Name, node1IP, nodeGroup1LabelsAZ1)
	node2 := k.addNode(c, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(c, node3Name, node3IP, nodeGroup1LabelsAZ2)
	k.addNode(c, node4Name, node4IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4} nodes
	policy1 := k.addPolicy(c, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
		azAffinity:      azAffinityLocalOnlyFirst,
	})

	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node1IP, node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node4IP, node3IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name, node2Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node1IP, node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = k.updateNodeLabels(c, node1, noNodeGroup)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = k.updateNodeLabels(c, node2, noNodeGroup)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s{1,2}
	k.updateNodeLabels(c, node1, nodeGroup1LabelsAZ1)
	k.updateNodeLabels(c, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node1IP, node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Update the policy to allow at most 1 gateway
	k.updatePolicyMaxGatewayNodes(c, policy1, 1)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node4IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Make k8s{1,2} healthy again
	k.makeNodesHealthy(node1Name, node2Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = k.updateNodeLabels(c, node2, noNodeGroup)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = k.updateNodeLabels(c, node1, noNodeGroup)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s{1,2}
	k.updateNodeLabels(c, node1, nodeGroup1LabelsAZ1)
	k.updateNodeLabels(c, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow all gateways
	k.updatePolicyMaxGatewayNodes(c, policy1, 0)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node1IP, node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
}

func (k *EgressGatewayOperatorTestSuite) TestEgressGatewayOperatorManagerHAGroupAZAffinityLocalPriority(c *C) {
	node1 := k.addNode(c, node1Name, node1IP, nodeGroup1LabelsAZ1)
	node2 := k.addNode(c, node2Name, node2IP, nodeGroup1LabelsAZ1)
	k.addNode(c, node3Name, node3IP, nodeGroup1LabelsAZ2)
	k.addNode(c, node4Name, node4IP, nodeGroup1LabelsAZ2)

	// Create a new HA policy that selects k8s{1,2,3,4} nodes
	policy1 := k.addPolicy(c, &policyParams{
		name:            "policy-1",
		uid:             policy1UID,
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
		azAffinity:      azAffinityLocalPriority,
		maxGatewayNodes: 4,
	})

	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node1IP, node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP, node4IP, node3IP},
			"az-2": {node3IP, node4IP, node1IP, node2IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node4IP, node3IP},
			"az-2": {node3IP, node4IP, node2IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node4IP, node3IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name, node2Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node1IP, node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP, node4IP, node3IP},
			"az-2": {node3IP, node4IP, node1IP, node2IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	node1 = k.updateNodeLabels(c, node1, noNodeGroup)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP, node2IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node4IP, node3IP},
			"az-2": {node3IP, node4IP, node2IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	node2 = k.updateNodeLabels(c, node2, noNodeGroup)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP, node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.updateNodeLabels(c, node1, nodeGroup1LabelsAZ1)
	k.updateNodeLabels(c, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node1IP, node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP, node4IP, node3IP},
			"az-2": {node3IP, node4IP, node1IP, node2IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Update the policy to allow at most 1 gateway
	k.updatePolicyMaxGatewayNodes(c, policy1, 1)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node2Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	k.makeNodesUnhealthy(node1Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node4IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.makeNodesHealthy(node1Name, node2Name)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = k.updateNodeLabels(c, node2, noNodeGroup)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node3IP, node4IP},
	})

	node1 = k.updateNodeLabels(c, node1, noNodeGroup)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	k.updateNodeLabels(c, node1, nodeGroup1LabelsAZ1)
	k.updateNodeLabels(c, node2, nodeGroup1LabelsAZ1)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow 2 gateways
	k.updatePolicyMaxGatewayNodes(c, policy1, 2)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow 3 gateways
	k.updatePolicyMaxGatewayNodes(c, policy1, 3)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node1IP, node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP, node4IP},
			"az-2": {node3IP, node4IP, node1IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow all 4 gateways
	k.updatePolicyMaxGatewayNodes(c, policy1, 4)
	k.assertIegpGatewayStatus(c, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node1IP, node2IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node1IP, node4IP, node3IP},
			"az-2": {node3IP, node4IP, node1IP, node2IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
}
