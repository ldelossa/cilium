// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgatewayha

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha/healthcheck"
	"github.com/cilium/cilium/pkg/hive/hivetest"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_fake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type healthcheckerMock struct {
	nodes  map[string]struct{}
	events chan healthcheck.Event
}

func (h *healthcheckerMock) UpdateNodeList(nodes map[string]nodeTypes.Node) {
}

func (h *healthcheckerMock) NodeIsHealthy(nodeName string) bool {
	_, ok := h.nodes[nodeName]
	return ok
}

func (h *healthcheckerMock) Events() chan healthcheck.Event {
	return h.events
}

func newHealthcheckerMock() *healthcheckerMock {
	return &healthcheckerMock{
		nodes:  make(map[string]struct{}),
		events: make(chan healthcheck.Event),
	}
}

func TestEgressGatewayOperatorManagerHAGroup(t *testing.T) {
	fakeSet := &k8sClient.FakeClientset{CiliumFakeClientset: cilium_fake.NewSimpleClientset()}
	policies := make(fakeResource[*Policy])
	nodes := make(fakeResource[*cilium_api_v2.CiliumNode])
	healthcheckerMock := newHealthcheckerMock()

	egressGatewayOperatorManager := newEgressGatewayOperatorManager(OperatorParams{
		Config:        OperatorConfig{1 * time.Millisecond},
		Clientset:     fakeSet,
		Policies:      policies,
		Nodes:         nodes,
		Healthchecker: healthcheckerMock,
		Lifecycle:     hivetest.Lifecycle(t),
	})

	healthcheckerMock.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
	}

	policies.sync(t)
	nodes.sync(t)

	node1 := newCiliumNode(node1Name, node1IP, nodeGroup1Labels)
	addNode(t, nodes, node1)

	node2 := newCiliumNode(node2Name, node2IP, nodeGroup1Labels)
	addNode(t, nodes, node2)

	// Create a new HA policy that selects k8s1 and k8s2 nodes
	policy1 := &policyParams{
		name:            "policy-1",
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
	}

	iegp, _ := newIEGP(policy1)
	_, err := fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().
		Create(context.TODO(), iegp, meta_v1.CreateOptions{})
	assert.Nil(t, err)
	addIEGP(t, policies, iegp)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	// Make k8s1 unhealthy
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s2": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node2IP},
	})

	// Make k8s1 healthy again
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	// Remove k8s1 from node-group-1
	node1 = newCiliumNode(node1Name, node1IP, noNodeGroup)
	addNode(t, nodes, node1)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node2IP},
	})

	// Add back k8s1
	node1 = newCiliumNode(node1Name, node1IP, nodeGroup1Labels)
	addNode(t, nodes, node1)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	// Update the policy to allow at most 1 gateway
	policy1.maxGatewayNodes = 1
	iegp, _ = newIEGP(policy1)

	_, err = fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().
		Update(context.TODO(), iegp, meta_v1.UpdateOptions{})
	assert.Nil(t, err)
	addIEGP(t, policies, iegp)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	// Make k8s1 unhealthy
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s2": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node2IP},
		healthyGatewayIPs: []string{node2IP},
	})

	// Make k8s1 healthy again
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node1IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})

	// Allow all gateways
	policy1.maxGatewayNodes = 0
	iegp, _ = newIEGP(policy1)
	_, err = fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().
		Update(context.TODO(), iegp, meta_v1.UpdateOptions{})
	assert.Nil(t, err)
	addIEGP(t, policies, iegp)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{node1IP, node2IP},
		healthyGatewayIPs: []string{node1IP, node2IP},
	})
}

func TestEgressGatewayManagerWithoutNodeSelector(t *testing.T) {
	fakeSet := &k8sClient.FakeClientset{CiliumFakeClientset: cilium_fake.NewSimpleClientset()}
	policies := make(fakeResource[*Policy])
	nodes := make(fakeResource[*cilium_api_v2.CiliumNode])
	healthcheckerMock := newHealthcheckerMock()

	egressGatewayOperatorManager := newEgressGatewayOperatorManager(OperatorParams{
		Config:        OperatorConfig{1 * time.Millisecond},
		Clientset:     fakeSet,
		Policies:      policies,
		Nodes:         nodes,
		Healthchecker: healthcheckerMock,
		Lifecycle:     hivetest.Lifecycle(t),
	})

	healthcheckerMock.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
	}

	policies.sync(t)
	nodes.sync(t)

	node1 := newCiliumNode(node1Name, node1IP, nodeGroup1Labels)
	addNode(t, nodes, node1)

	node2 := newCiliumNode(node2Name, node2IP, nodeGroup1Labels)
	addNode(t, nodes, node2)

	// Create a new policy without nodeSelector
	iegp, _ := newIEGP(&policyParams{
		name:            "policy-1",
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		egressIP:        egressIP1,
	})

	_, err := fakeSet.CiliumFakeClientset.IsovalentV1().
		IsovalentEgressGatewayPolicies().
		Create(context.TODO(), iegp, meta_v1.CreateOptions{})
	assert.Nil(t, err)
	addIEGP(t, policies, iegp)

	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	// Operator should select no active / healthy gateways for this policy
	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs:  []string{},
		healthyGatewayIPs: []string{},
	})
}

func TestEgressGatewayOperatorManagerHAGroupAZAffinityLocalOnly(t *testing.T) {
	fakeSet := &k8sClient.FakeClientset{CiliumFakeClientset: cilium_fake.NewSimpleClientset()}
	policies := make(fakeResource[*Policy])
	nodes := make(fakeResource[*cilium_api_v2.CiliumNode])
	healthcheckerMock := newHealthcheckerMock()

	egressGatewayOperatorManager := newEgressGatewayOperatorManager(OperatorParams{
		Config:        OperatorConfig{1 * time.Millisecond},
		Clientset:     fakeSet,
		Policies:      policies,
		Nodes:         nodes,
		Healthchecker: healthcheckerMock,
		Lifecycle:     hivetest.Lifecycle(t),
	})

	healthcheckerMock.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
	}

	policies.sync(t)
	nodes.sync(t)

	node1 := newCiliumNode(node1Name, node1IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node1)

	node2 := newCiliumNode(node2Name, node2IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node2)

	node3 := newCiliumNode(node3Name, node3IP, nodeGroup1LabelsAZ2)
	addNode(t, nodes, node3)

	node4 := newCiliumNode(node4Name, node4IP, nodeGroup1LabelsAZ2)
	addNode(t, nodes, node4)

	// Create a new HA policy that selects k8s{1,2,3,4} nodes
	policy1 := &policyParams{
		name:            "policy-1",
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
		azAffinity:      azAffinityLocalOnly,
	}

	iegp, _ := newIEGP(policy1)
	_, err := fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().
		Create(context.TODO(), iegp, meta_v1.CreateOptions{})
	assert.Nil(t, err)
	addIEGP(t, policies, iegp)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Make k8s1 unhealthy
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Make also k8s2 unhealthy
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Make k8s{1,2} healthy again
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = newCiliumNode(node1Name, node1IP, noNodeGroup)
	addNode(t, nodes, node1)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = newCiliumNode(node2Name, node2IP, noNodeGroup)
	addNode(t, nodes, node2)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s{1,2}
	node1 = newCiliumNode(node1Name, node1IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node1)

	node2 = newCiliumNode(node2Name, node2IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node2)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Update the policy to allow at most 1 gateway
	policy1.maxGatewayNodes = 1
	iegp, _ = newIEGP(policy1)

	_, err = fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().
		Update(context.TODO(), iegp, meta_v1.UpdateOptions{})
	assert.Nil(t, err)
	addIEGP(t, policies, iegp)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Make k8s1 unhealthy
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Make also k8s2 unhealthy
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Make k8s{1,2} healthy again
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = newCiliumNode(node1Name, node1IP, noNodeGroup)
	addNode(t, nodes, node1)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = newCiliumNode(node2Name, node2IP, noNodeGroup)
	addNode(t, nodes, node2)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s{1,2}
	node1 = newCiliumNode(node1Name, node1IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node1)

	node2 = newCiliumNode(node2Name, node2IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node2)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow all gateways
	policy1.maxGatewayNodes = 0
	iegp, _ = newIEGP(policy1)
	_, err = fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().
		Update(context.TODO(), iegp, meta_v1.UpdateOptions{})
	assert.Nil(t, err)
	addIEGP(t, policies, iegp)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
}

func TestEgressGatewayOperatorManagerHAGroupAZAffinityLocalOnlyFirst(t *testing.T) {
	fakeSet := &k8sClient.FakeClientset{CiliumFakeClientset: cilium_fake.NewSimpleClientset()}
	policies := make(fakeResource[*Policy])
	nodes := make(fakeResource[*cilium_api_v2.CiliumNode])
	healthcheckerMock := newHealthcheckerMock()

	egressGatewayOperatorManager := newEgressGatewayOperatorManager(OperatorParams{
		Config:        OperatorConfig{1 * time.Millisecond},
		Clientset:     fakeSet,
		Policies:      policies,
		Nodes:         nodes,
		Healthchecker: healthcheckerMock,
		Lifecycle:     hivetest.Lifecycle(t),
	})

	healthcheckerMock.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
	}

	policies.sync(t)
	nodes.sync(t)

	node1 := newCiliumNode(node1Name, node1IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node1)

	node2 := newCiliumNode(node2Name, node2IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node2)

	node3 := newCiliumNode(node3Name, node3IP, nodeGroup1LabelsAZ2)
	addNode(t, nodes, node3)

	node4 := newCiliumNode(node4Name, node4IP, nodeGroup1LabelsAZ2)
	addNode(t, nodes, node4)

	// Create a new HA policy that selects k8s{1,2,3,4} nodes
	policy1 := &policyParams{
		name:            "policy-1",
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
		azAffinity:      azAffinityLocalOnlyFirst,
	}

	iegp, _ := newIEGP(policy1)
	_, err := fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().
		Create(context.TODO(), iegp, meta_v1.CreateOptions{})
	assert.Nil(t, err)
	addIEGP(t, policies, iegp)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Make k8s1 unhealthy
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Make also k8s2 unhealthy
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP, node4IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Make k8s{1,2} healthy again
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = newCiliumNode(node1Name, node1IP, noNodeGroup)
	addNode(t, nodes, node1)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = newCiliumNode(node2Name, node2IP, noNodeGroup)
	addNode(t, nodes, node2)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s{1,2}
	node1 = newCiliumNode(node1Name, node1IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node1)

	node2 = newCiliumNode(node2Name, node2IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node2)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Update the policy to allow at most 1 gateway
	policy1.maxGatewayNodes = 1
	iegp, _ = newIEGP(policy1)

	_, err = fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().
		Update(context.TODO(), iegp, meta_v1.UpdateOptions{})
	assert.Nil(t, err)
	addIEGP(t, policies, iegp)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Make k8s1 unhealthy
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Make also k8s2 unhealthy (az-1 group should remain empty)
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Make k8s{1,2} healthy again
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = newCiliumNode(node1Name, node1IP, noNodeGroup)
	addNode(t, nodes, node1)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = newCiliumNode(node2Name, node2IP, noNodeGroup)
	addNode(t, nodes, node2)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s{1,2}
	node1 = newCiliumNode(node1Name, node1IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node1)

	node2 = newCiliumNode(node2Name, node2IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node2)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow all gateways
	policy1.maxGatewayNodes = 0
	iegp, _ = newIEGP(policy1)
	_, err = fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().
		Update(context.TODO(), iegp, meta_v1.UpdateOptions{})
	assert.Nil(t, err)
	addIEGP(t, policies, iegp)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
}

func TestEgressGatewayOperatorManagerHAGroupAZAffinityLocalPriority(t *testing.T) {
	fakeSet := &k8sClient.FakeClientset{CiliumFakeClientset: cilium_fake.NewSimpleClientset()}
	policies := make(fakeResource[*Policy])
	nodes := make(fakeResource[*cilium_api_v2.CiliumNode])
	healthcheckerMock := newHealthcheckerMock()

	egressGatewayOperatorManager := newEgressGatewayOperatorManager(OperatorParams{
		Config:        OperatorConfig{1 * time.Millisecond},
		Clientset:     fakeSet,
		Policies:      policies,
		Nodes:         nodes,
		Healthchecker: healthcheckerMock,
		Lifecycle:     hivetest.Lifecycle(t),
	})

	healthcheckerMock.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
	}

	policies.sync(t)
	nodes.sync(t)

	node1 := newCiliumNode(node1Name, node1IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node1)

	node2 := newCiliumNode(node2Name, node2IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node2)

	node3 := newCiliumNode(node3Name, node3IP, nodeGroup1LabelsAZ2)
	addNode(t, nodes, node3)

	node4 := newCiliumNode(node4Name, node4IP, nodeGroup1LabelsAZ2)
	addNode(t, nodes, node4)

	// Create a new HA policy that selects k8s{1,2,3,4} nodes
	policy1 := &policyParams{
		name:            "policy-1",
		endpointLabels:  ep1Labels,
		destinationCIDR: destCIDR,
		nodeLabels:      nodeGroup1Labels,
		iface:           testInterface1,
		azAffinity:      azAffinityLocalPriority,
		maxGatewayNodes: 4,
	}

	iegp, _ := newIEGP(policy1)
	_, err := fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().
		Create(context.TODO(), iegp, meta_v1.CreateOptions{})
	assert.Nil(t, err)
	addIEGP(t, policies, iegp)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node3IP, node4IP, node1IP, node2IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Make k8s1 unhealthy
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP, node4IP},
			"az-2": {node3IP, node4IP, node2IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Make also k8s2 unhealthy (az-1 group should remain empty)
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP, node4IP},
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Make k8s{1,2} healthy again
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node3IP, node4IP, node1IP, node2IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = newCiliumNode(node1Name, node1IP, noNodeGroup)
	addNode(t, nodes, node1)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP, node3IP, node4IP},
			"az-2": {node3IP, node4IP, node2IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = newCiliumNode(node2Name, node2IP, noNodeGroup)
	addNode(t, nodes, node2)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node3IP, node4IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s{1,2}
	node1 = newCiliumNode(node1Name, node1IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node1)

	node2 = newCiliumNode(node2Name, node2IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node2)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node3IP, node4IP, node1IP, node2IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Update the policy to allow at most 1 gateway
	policy1.maxGatewayNodes = 1
	iegp, _ = newIEGP(policy1)

	_, err = fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().
		Update(context.TODO(), iegp, meta_v1.UpdateOptions{})
	assert.Nil(t, err)
	addIEGP(t, policies, iegp)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Make k8s1 unhealthy
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Make also k8s2 unhealthy (az-1 group should remain empty)
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node3IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Make k8s{1,2} healthy again
	healthcheckerMock.nodes = map[string]struct{}{
		"k8s1": {},
		"k8s2": {},
		"k8s3": {},
		"k8s4": {},
	}
	egressGatewayOperatorManager.reconciliationTrigger.Trigger()

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Remove k8s1 from node-group-1
	node1 = newCiliumNode(node1Name, node1IP, noNodeGroup)
	addNode(t, nodes, node1)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node2IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node2IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node2IP, node3IP, node4IP},
	})

	// Remove k8s2 from node-group-1
	node2 = newCiliumNode(node2Name, node2IP, noNodeGroup)
	addNode(t, nodes, node2)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node3IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node3IP, node4IP},
	})

	// Add back k8s{1,2}
	node1 = newCiliumNode(node1Name, node1IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node1)

	node2 = newCiliumNode(node2Name, node2IP, nodeGroup1LabelsAZ1)
	addNode(t, nodes, node2)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP},
			"az-2": {node3IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})

	// Allow all 4 gateways
	policy1.maxGatewayNodes = 4
	iegp, _ = newIEGP(policy1)
	_, err = fakeSet.CiliumFakeClientset.IsovalentV1().IsovalentEgressGatewayPolicies().
		Update(context.TODO(), iegp, meta_v1.UpdateOptions{})
	assert.Nil(t, err)
	addIEGP(t, policies, iegp)

	assertIegpGatewayStatus(t, fakeSet, "policy-1", gatewayStatus{
		activeGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
		activeGatewayIPsByAZ: map[string][]string{
			"az-1": {node1IP, node2IP, node3IP, node4IP},
			"az-2": {node3IP, node4IP, node1IP, node2IP},
		},
		healthyGatewayIPs: []string{node1IP, node2IP, node3IP, node4IP},
	})
}
