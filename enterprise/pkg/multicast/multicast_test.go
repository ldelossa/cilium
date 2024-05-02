//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package multicast

import (
	"context"
	"net/netip"
	"reflect"
	"sort"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	isovalent_api_v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	maps_multicast "github.com/cilium/cilium/pkg/maps/multicast"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// test NodeIPs
	testLocalNodeIP      = "192.168.1.100"
	testNode2IP          = "192.168.1.101"
	testNode3IP          = "192.168.1.102"
	testLocalSubscriber1 = "10.200.0.1"
	testLocalSubscriber2 = "10.200.0.2"

	// test Node Names
	testLocalNodeName = "test-node"
	testNode2Name     = "node2"
	testNode3Name     = "node3"

	// testVxlanIfIndex is the ifindex of the vxlan device used in tests
	testVxlanIfIndex = 11
	testSub1IfIndex  = 1
	testSub2IfIndex  = 2

	testGroup1 = isovalent_api_v1alpha1.MulticastGroupAddr("225.0.0.100")
	testGroup2 = isovalent_api_v1alpha1.MulticastGroupAddr("225.0.0.101")
	testGroup3 = isovalent_api_v1alpha1.MulticastGroupAddr("225.0.0.102")
	testGroup4 = isovalent_api_v1alpha1.MulticastGroupAddr("225.0.0.103")

	// Group CRD objects
	testOneGroupObj = &isovalent_api_v1alpha1.IsovalentMulticastGroup{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "multicast-groupMap-1",
		},
		Spec: isovalent_api_v1alpha1.IsovalentMulticastGroupSpec{
			GroupAddrs: []isovalent_api_v1alpha1.MulticastGroupAddr{testGroup1},
		},
	}

	testThreeGroupObj = &isovalent_api_v1alpha1.IsovalentMulticastGroup{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "multicast-groupMap-1",
		},
		Spec: isovalent_api_v1alpha1.IsovalentMulticastGroupSpec{
			GroupAddrs: []isovalent_api_v1alpha1.MulticastGroupAddr{
				testGroup1,
				testGroup2,
				testGroup3,
			},
		},
	}

	// Node CRD objects
	testLocalNodeObj = &isovalent_api_v1alpha1.IsovalentMulticastNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: testLocalNodeName,
		},
		Spec: isovalent_api_v1alpha1.IsovalentMulticastNodeSpec{
			NodeIP: testLocalNodeIP,
		},
		Status: isovalent_api_v1alpha1.IsovalentMulticastNodeStatus{
			MulticastSubscribers: []isovalent_api_v1alpha1.MulticastNodeSubscriberData{},
		},
	}

	testRemoteNode2ObjOneGroup = &isovalent_api_v1alpha1.IsovalentMulticastNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: testNode2Name,
		},
		Spec: isovalent_api_v1alpha1.IsovalentMulticastNodeSpec{
			NodeIP: testNode2IP,
		},
		Status: isovalent_api_v1alpha1.IsovalentMulticastNodeStatus{
			MulticastSubscribers: []isovalent_api_v1alpha1.MulticastNodeSubscriberData{
				{
					GroupAddr: testGroup1,
				},
			},
		},
	}

	testRemoteNode2ObjThreeGroups = &isovalent_api_v1alpha1.IsovalentMulticastNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: testNode2Name,
		},
		Spec: isovalent_api_v1alpha1.IsovalentMulticastNodeSpec{
			NodeIP: testNode2IP,
		},
		Status: isovalent_api_v1alpha1.IsovalentMulticastNodeStatus{
			MulticastSubscribers: []isovalent_api_v1alpha1.MulticastNodeSubscriberData{
				{
					GroupAddr: testGroup1,
				},
				{
					GroupAddr: testGroup2,
				},
				{
					GroupAddr: testGroup3,
				},
			},
		},
	}

	testRemoteNode3ObjOneGroup = &isovalent_api_v1alpha1.IsovalentMulticastNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: testNode3Name,
		},
		Spec: isovalent_api_v1alpha1.IsovalentMulticastNodeSpec{
			NodeIP: testNode3IP,
		},
		Status: isovalent_api_v1alpha1.IsovalentMulticastNodeStatus{
			MulticastSubscribers: []isovalent_api_v1alpha1.MulticastNodeSubscriberData{
				{
					GroupAddr: testGroup1,
				},
			},
		},
	}

	testRemoteNode3ObjThreeGroups = &isovalent_api_v1alpha1.IsovalentMulticastNode{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: testNode3Name,
		},
		Spec: isovalent_api_v1alpha1.IsovalentMulticastNodeSpec{
			NodeIP: testNode3IP,
		},
		Status: isovalent_api_v1alpha1.IsovalentMulticastNodeStatus{
			MulticastSubscribers: []isovalent_api_v1alpha1.MulticastNodeSubscriberData{
				{
					GroupAddr: testGroup1,
				},
				{
					GroupAddr: testGroup2,
				},
				{
					GroupAddr: testGroup3,
				},
			},
		},
	}

	// test cilium endpoints
	testEPSub1 = &v2.CiliumEndpoint{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "endpoint1",
		},
		Status: v2.EndpointStatus{
			Identity: &v2.EndpointIdentity{ID: 1},
			Networking: &v2.EndpointNetworking{
				Addressing: v2.AddressPairList{
					{
						IPV4: testLocalSubscriber1,
					},
				},
				NodeIP: testLocalNodeIP,
			},
		},
	}

	testEPSub2 = &v2.CiliumEndpoint{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "endpoint2",
		},
		Status: v2.EndpointStatus{
			Identity: &v2.EndpointIdentity{ID: 2},
			Networking: &v2.EndpointNetworking{
				Addressing: v2.AddressPairList{
					{
						IPV4: testLocalSubscriber2,
					},
				},
				NodeIP: testLocalNodeIP,
			},
		},
	}
)

func Test_MulticastGroups(t *testing.T) {
	tests := []struct {
		description     string
		group           *isovalent_api_v1alpha1.IsovalentMulticastGroup
		bpfInit         map[netip.Addr][]*maps_multicast.SubscriberV4
		expectedGroups  []netip.Addr
		expectedNodeObj *isovalent_api_v1alpha1.IsovalentMulticastNode
	}{
		{
			description: "multiple groups in CRD, none in BPF map, add all missing groups",
			group:       testThreeGroupObj,
			bpfInit:     make(map[netip.Addr][]*maps_multicast.SubscriberV4),
			expectedGroups: []netip.Addr{
				netip.MustParseAddr(string(testGroup1)),
				netip.MustParseAddr(string(testGroup2)),
				netip.MustParseAddr(string(testGroup3)),
			},
			expectedNodeObj: testLocalNodeObj,
		},
		{
			description: "multiple groups in CRD, 2 in BPF map, add missing",
			group:       testThreeGroupObj,
			bpfInit: map[netip.Addr][]*maps_multicast.SubscriberV4{
				netip.MustParseAddr(string(testGroup1)): {},
				netip.MustParseAddr(string(testGroup2)): {},
			},
			expectedGroups: []netip.Addr{
				netip.MustParseAddr(string(testGroup1)),
				netip.MustParseAddr(string(testGroup2)),
				netip.MustParseAddr(string(testGroup3)),
			},
			expectedNodeObj: testLocalNodeObj,
		},
		{
			description: "multiple groups in CRD, 4 in BPF map, deleting extra",
			group:       testThreeGroupObj,
			bpfInit: map[netip.Addr][]*maps_multicast.SubscriberV4{
				netip.MustParseAddr(string(testGroup1)): {},
				netip.MustParseAddr(string(testGroup2)): {},
				netip.MustParseAddr(string(testGroup3)): {},
				netip.MustParseAddr(string(testGroup4)): {},
			},
			expectedGroups: []netip.Addr{
				netip.MustParseAddr(string(testGroup1)),
				netip.MustParseAddr(string(testGroup2)),
				netip.MustParseAddr(string(testGroup3)),
			},
			expectedNodeObj: testLocalNodeObj,
		},
	}

	req := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), maxTestDuration)
	defer cancel()

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			f := newFixture(ctx, req, test.bpfInit)

			_, err := f.mcastGroupClient.Create(ctx, test.group, meta_v1.CreateOptions{})
			req.NoError(err)

			log := hivetest.Logger(t)
			f.hive.Start(log, ctx)
			defer f.hive.Stop(log, ctx)

			req.Eventually(func() bool {
				// compare BPF map
				bpfGroups, err := f.bpfMap.List()
				req.NoError(err)
				if !groupElementsMatch(bpfGroups, test.expectedGroups) {
					return false
				}

				// compare node object
				if !compareNodeObjs(f, test.expectedNodeObj) {
					return false
				}
				return true
			}, maxTestDuration, 100*time.Millisecond)
		})
	}
}

func Test_MulticastRemoteSubscribers(t *testing.T) {
	tests := []struct {
		description     string
		group           *isovalent_api_v1alpha1.IsovalentMulticastGroup
		bpfInit         map[netip.Addr][]*maps_multicast.SubscriberV4
		remoteNodeObjs  []*isovalent_api_v1alpha1.IsovalentMulticastNode
		expectedBPFMap  map[netip.Addr][]*maps_multicast.SubscriberV4 // key is group addr, value is subscriber list
		expectedNodeObj *isovalent_api_v1alpha1.IsovalentMulticastNode
	}{
		{
			description:    "empty BPF init, 1 group 2 remote subscribers",
			group:          testOneGroupObj,
			bpfInit:        make(map[netip.Addr][]*maps_multicast.SubscriberV4),
			remoteNodeObjs: []*isovalent_api_v1alpha1.IsovalentMulticastNode{testRemoteNode2ObjOneGroup, testRemoteNode3ObjOneGroup},
			expectedBPFMap: map[netip.Addr][]*maps_multicast.SubscriberV4{
				netip.MustParseAddr(string(testGroup1)): {
					{
						SAddr:    netip.MustParseAddr(testNode2IP),
						Ifindex:  uint32(testVxlanIfIndex),
						IsRemote: true,
					},
					{
						SAddr:    netip.MustParseAddr(testNode3IP),
						Ifindex:  uint32(testVxlanIfIndex),
						IsRemote: true,
					},
				},
			},
			expectedNodeObj: testLocalNodeObj,
		},
		{
			description: "BPF init with extra item, 2 node obj 1 group each",
			group:       testOneGroupObj,
			bpfInit: map[netip.Addr][]*maps_multicast.SubscriberV4{
				netip.MustParseAddr(string(testGroup1)): {
					{
						SAddr:    netip.MustParseAddr("10.10.10.10"), // extra item, should be removed
						Ifindex:  uint32(testVxlanIfIndex),
						IsRemote: true,
					},
				},
			},
			remoteNodeObjs: []*isovalent_api_v1alpha1.IsovalentMulticastNode{testRemoteNode2ObjOneGroup, testRemoteNode3ObjOneGroup},
			expectedBPFMap: map[netip.Addr][]*maps_multicast.SubscriberV4{
				netip.MustParseAddr(string(testGroup1)): {
					{
						SAddr:    netip.MustParseAddr(testNode2IP),
						Ifindex:  uint32(testVxlanIfIndex),
						IsRemote: true,
					},
					{
						SAddr:    netip.MustParseAddr(testNode3IP),
						Ifindex:  uint32(testVxlanIfIndex),
						IsRemote: true,
					},
				},
			},
			expectedNodeObj: testLocalNodeObj,
		},
		{
			description: "empty BPF init, 2 node obj 3 groups each",
			group:       testThreeGroupObj,
			bpfInit:     make(map[netip.Addr][]*maps_multicast.SubscriberV4),
			remoteNodeObjs: []*isovalent_api_v1alpha1.IsovalentMulticastNode{
				testRemoteNode2ObjThreeGroups,
				testRemoteNode3ObjThreeGroups,
			},
			expectedBPFMap: map[netip.Addr][]*maps_multicast.SubscriberV4{
				netip.MustParseAddr(string(testGroup1)): {
					{
						SAddr:    netip.MustParseAddr(testNode2IP),
						Ifindex:  uint32(testVxlanIfIndex),
						IsRemote: true,
					},
					{
						SAddr:    netip.MustParseAddr(testNode3IP),
						Ifindex:  uint32(testVxlanIfIndex),
						IsRemote: true,
					},
				},
				netip.MustParseAddr(string(testGroup2)): {
					{
						SAddr:    netip.MustParseAddr(testNode2IP),
						Ifindex:  uint32(testVxlanIfIndex),
						IsRemote: true,
					},
					{
						SAddr:    netip.MustParseAddr(testNode3IP),
						Ifindex:  uint32(testVxlanIfIndex),
						IsRemote: true,
					},
				},
				netip.MustParseAddr(string(testGroup3)): {
					{
						SAddr:    netip.MustParseAddr(testNode2IP),
						Ifindex:  uint32(testVxlanIfIndex),
						IsRemote: true,
					},
					{
						SAddr:    netip.MustParseAddr(testNode3IP),
						Ifindex:  uint32(testVxlanIfIndex),
						IsRemote: true,
					},
				},
			},
			expectedNodeObj: testLocalNodeObj,
		},
	}

	req := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), maxTestDuration)
	defer cancel()

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			f := newFixture(ctx, req, test.bpfInit)

			// setup group crd
			_, err := f.mcastGroupClient.Create(ctx, test.group, meta_v1.CreateOptions{})
			req.NoError(err)

			log := hivetest.Logger(t)
			f.hive.Start(log, ctx)
			defer f.hive.Stop(log, ctx)

			// setup remote nodes
			for _, node := range test.remoteNodeObjs {
				_, err := f.manager.MulticastNodeClient.Create(ctx, node, meta_v1.CreateOptions{})
				req.NoError(err)
			}

			// validate BPF and node state
			req.Eventually(func() bool {
				// compare BPF map
				if !compareBPFMaps(f, test.expectedBPFMap) {
					return false
				}

				// compare node object
				if !compareNodeObjs(f, test.expectedNodeObj) {
					return false
				}
				return true
			}, maxTestDuration, 100*time.Millisecond)
		})
	}
}

func Test_MulticastNodeStatus(t *testing.T) {
	tests := []struct {
		description     string
		endpoints       []*v2.CiliumEndpoint
		group           *isovalent_api_v1alpha1.IsovalentMulticastGroup
		bpfInit         map[netip.Addr][]*maps_multicast.SubscriberV4
		remoteNodeObjs  []*isovalent_api_v1alpha1.IsovalentMulticastNode
		expectedBPFMap  map[netip.Addr][]*maps_multicast.SubscriberV4 // key is group addr, value is subscriber list
		expectedNodeObj *isovalent_api_v1alpha1.IsovalentMulticastNode
	}{
		{
			description: "BPF map have 1 local subscriber, 1 remote subscriber, 1 group",
			endpoints:   []*v2.CiliumEndpoint{testEPSub1},
			group:       testOneGroupObj,
			bpfInit: map[netip.Addr][]*maps_multicast.SubscriberV4{
				netip.MustParseAddr(string(testGroup1)): {
					{
						SAddr:    netip.MustParseAddr(testLocalSubscriber1),
						Ifindex:  uint32(testSub1IfIndex),
						IsRemote: false,
					},
					{
						SAddr:    netip.MustParseAddr(testNode2IP),
						Ifindex:  uint32(testVxlanIfIndex),
						IsRemote: true,
					},
				},
			},
			remoteNodeObjs: []*isovalent_api_v1alpha1.IsovalentMulticastNode{testRemoteNode2ObjOneGroup},
			expectedBPFMap: map[netip.Addr][]*maps_multicast.SubscriberV4{
				netip.MustParseAddr(string(testGroup1)): {
					{
						SAddr:    netip.MustParseAddr(testLocalSubscriber1),
						Ifindex:  uint32(testSub1IfIndex),
						IsRemote: false,
					},
					{
						SAddr:    netip.MustParseAddr(testNode2IP),
						Ifindex:  uint32(testVxlanIfIndex),
						IsRemote: true,
					},
				},
			},
			expectedNodeObj: func(base *isovalent_api_v1alpha1.IsovalentMulticastNode) *isovalent_api_v1alpha1.IsovalentMulticastNode {
				baseCopy := base.DeepCopy()
				baseCopy.Status.MulticastSubscribers = []isovalent_api_v1alpha1.MulticastNodeSubscriberData{
					{
						GroupAddr: testGroup1,
					},
				}
				return baseCopy
			}(testLocalNodeObj),
		},
		{
			description: "BPF map have 3 group",
			endpoints:   []*v2.CiliumEndpoint{testEPSub1, testEPSub2},
			group:       testThreeGroupObj,
			bpfInit: map[netip.Addr][]*maps_multicast.SubscriberV4{
				netip.MustParseAddr(string(testGroup1)): {
					{
						SAddr:    netip.MustParseAddr(testLocalSubscriber1),
						Ifindex:  uint32(testSub1IfIndex),
						IsRemote: false,
					},
				},
				netip.MustParseAddr(string(testGroup2)): {
					{
						SAddr:    netip.MustParseAddr(testLocalSubscriber2),
						Ifindex:  uint32(testSub2IfIndex),
						IsRemote: false,
					},
				},
				netip.MustParseAddr(string(testGroup3)): {
					{
						SAddr:    netip.MustParseAddr(testLocalSubscriber1),
						Ifindex:  uint32(testSub1IfIndex),
						IsRemote: false,
					},
				},
			},
			remoteNodeObjs: []*isovalent_api_v1alpha1.IsovalentMulticastNode{},
			expectedBPFMap: map[netip.Addr][]*maps_multicast.SubscriberV4{
				netip.MustParseAddr(string(testGroup1)): {
					{
						SAddr:    netip.MustParseAddr(testLocalSubscriber1),
						Ifindex:  uint32(testSub1IfIndex),
						IsRemote: false,
					},
				},
				netip.MustParseAddr(string(testGroup2)): {
					{
						SAddr:    netip.MustParseAddr(testLocalSubscriber2),
						Ifindex:  uint32(testSub2IfIndex),
						IsRemote: false,
					},
				},
				netip.MustParseAddr(string(testGroup3)): {
					{
						SAddr:    netip.MustParseAddr(testLocalSubscriber1),
						Ifindex:  uint32(testSub1IfIndex),
						IsRemote: false,
					},
				},
			},
			expectedNodeObj: func(base *isovalent_api_v1alpha1.IsovalentMulticastNode) *isovalent_api_v1alpha1.IsovalentMulticastNode {
				baseCopy := base.DeepCopy()
				baseCopy.Status.MulticastSubscribers = []isovalent_api_v1alpha1.MulticastNodeSubscriberData{
					{
						GroupAddr: testGroup1,
					},
					{
						GroupAddr: testGroup2,
					},
					{
						GroupAddr: testGroup3,
					},
				}
				return baseCopy
			}(testLocalNodeObj),
		},
	}

	req := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), maxTestDuration)
	defer cancel()

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			f := newFixture(ctx, req, test.bpfInit)

			// setup group crd
			_, err := f.mcastGroupClient.Create(ctx, test.group, meta_v1.CreateOptions{})
			req.NoError(err)

			// setup local endpoints
			for _, ep := range test.endpoints {
				_, err := f.endpointClient.Create(ctx, ep, meta_v1.CreateOptions{})
				req.NoError(err)
			}

			log := hivetest.Logger(t)
			f.hive.Start(log, ctx)
			defer f.hive.Stop(log, ctx)

			// setup remote nodes
			for _, node := range test.remoteNodeObjs {
				_, err := f.manager.MulticastNodeClient.Create(ctx, node, meta_v1.CreateOptions{})
				req.NoError(err)
			}

			// validate BPF and node state
			req.Eventually(func() bool {
				// compare BPF map
				if !compareBPFMaps(f, test.expectedBPFMap) {
					return false
				}

				// compare node object
				if !compareNodeObjs(f, test.expectedNodeObj) {
					return false
				}
				return true
			}, maxTestDuration, 100*time.Millisecond)
		})
	}
}

func Test_LocalEndpoint(t *testing.T) {
	tests := []struct {
		description     string
		endpoints       []*v2.CiliumEndpoint
		group           *isovalent_api_v1alpha1.IsovalentMulticastGroup
		bpfInit         map[netip.Addr][]*maps_multicast.SubscriberV4
		expectedBPFMap  map[netip.Addr][]*maps_multicast.SubscriberV4 // key is group addr, value is subscriber list
		expectedNodeObj *isovalent_api_v1alpha1.IsovalentMulticastNode
	}{
		{
			description: "Endpoing exist, BPF map has matching local subscriber - no change",
			endpoints:   []*v2.CiliumEndpoint{testEPSub1},
			group:       testOneGroupObj,
			bpfInit: map[netip.Addr][]*maps_multicast.SubscriberV4{
				netip.MustParseAddr(string(testGroup1)): {
					{
						SAddr:    netip.MustParseAddr(testLocalSubscriber1),
						Ifindex:  uint32(testSub1IfIndex),
						IsRemote: false,
					},
				},
			},
			expectedBPFMap: map[netip.Addr][]*maps_multicast.SubscriberV4{
				netip.MustParseAddr(string(testGroup1)): {
					{
						SAddr:    netip.MustParseAddr(testLocalSubscriber1),
						Ifindex:  uint32(testSub1IfIndex),
						IsRemote: false,
					},
				},
			},
			expectedNodeObj: func(base *isovalent_api_v1alpha1.IsovalentMulticastNode) *isovalent_api_v1alpha1.IsovalentMulticastNode {
				baseCopy := base.DeepCopy()
				baseCopy.Status.MulticastSubscribers = []isovalent_api_v1alpha1.MulticastNodeSubscriberData{
					{
						GroupAddr: testGroup1,
					},
				}
				return baseCopy
			}(testLocalNodeObj),
		},
		{
			description: "Endpoing exist, BPF map does not have that subscriber - no change",
			endpoints:   []*v2.CiliumEndpoint{testEPSub1},
			group:       testOneGroupObj,
			bpfInit: map[netip.Addr][]*maps_multicast.SubscriberV4{
				netip.MustParseAddr(string(testGroup1)): {},
			},
			expectedBPFMap: map[netip.Addr][]*maps_multicast.SubscriberV4{
				netip.MustParseAddr(string(testGroup1)): {},
			},
			expectedNodeObj: testLocalNodeObj,
		},
		{
			description: "Endpoing does not exist, BPF map have a local subscriber - clean up BFP subscriber",
			endpoints:   []*v2.CiliumEndpoint{},
			group:       testOneGroupObj,
			bpfInit: map[netip.Addr][]*maps_multicast.SubscriberV4{
				netip.MustParseAddr(string(testGroup1)): {
					{
						SAddr:    netip.MustParseAddr(testLocalSubscriber1),
						Ifindex:  uint32(testSub1IfIndex),
						IsRemote: false,
					},
				},
			},
			expectedBPFMap: map[netip.Addr][]*maps_multicast.SubscriberV4{
				netip.MustParseAddr(string(testGroup1)): {},
			},
			expectedNodeObj: testLocalNodeObj,
		},
	}

	req := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), maxTestDuration)
	defer cancel()

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			f := newFixture(ctx, req, test.bpfInit)

			// setup local endpoints
			for _, ep := range test.endpoints {
				_, err := f.endpointClient.Create(ctx, ep, meta_v1.CreateOptions{})
				req.NoError(err)
			}

			// setup group crd
			_, err := f.mcastGroupClient.Create(ctx, test.group, meta_v1.CreateOptions{})
			req.NoError(err)

			log := hivetest.Logger(t)
			f.hive.Start(log, ctx)
			defer f.hive.Stop(log, ctx)

			// validate BPF and node state
			req.Eventually(func() bool {
				// compare BPF map
				if !compareBPFMaps(f, test.expectedBPFMap) {
					return false
				}

				// compare node object
				if !compareNodeObjs(f, test.expectedNodeObj) {
					return false
				}
				return true
			}, maxTestDuration, 100*time.Millisecond)
		})
	}

}

func groupElementsMatch(a, b []netip.Addr) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}

	if len(a) != len(b) {
		return false
	}

	sort.Slice(a, func(i, j int) bool {
		return a[i].Compare(a[j]) < 0
	})

	sort.Slice(b, func(i, j int) bool {
		return b[i].Compare(b[j]) < 0
	})

	return reflect.DeepEqual(a, b)
}

func subscriberElementsMatch(a, b []*maps_multicast.SubscriberV4) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}

	if len(a) != len(b) {
		return false
	}

	sort.Slice(a, func(i, j int) bool {
		return a[i].SAddr.Compare(a[j].SAddr) < 0
	})

	sort.Slice(b, func(i, j int) bool {
		return b[i].SAddr.Compare(b[j].SAddr) < 0
	})

	return reflect.DeepEqual(a, b)
}

func compareBPFMaps(f *fixture, expected map[netip.Addr][]*maps_multicast.SubscriberV4) bool {
	// compare BPF map
	bpfGroups, err := f.bpfMap.List()
	f.req.NoError(err)

	var expectedGroupsList []netip.Addr
	for expectedGroup := range expected {
		expectedGroupsList = append(expectedGroupsList, expectedGroup)
	}

	if !groupElementsMatch(bpfGroups, expectedGroupsList) {
		return false
	}

	for _, groupAddr := range bpfGroups {
		expectedGroupSubs, exists := expected[groupAddr]
		if !exists {
			return false
		}

		bpfGroupSubMap, err := f.bpfMap.Lookup(groupAddr)
		f.req.NoError(err)

		bpfGroupSubs, err := bpfGroupSubMap.List()
		f.req.NoError(err)

		if !subscriberElementsMatch(bpfGroupSubs, expectedGroupSubs) {
			return false
		}
	}

	return true
}

func compareNodeObjs(f *fixture, expected *isovalent_api_v1alpha1.IsovalentMulticastNode) bool {
	// compare node object
	nodeObj, err := f.mcastNodeClient.Get(f.testCtx, testLocalNodeName, meta_v1.GetOptions{})
	if err != nil && k8sErrors.IsNotFound(err) {
		return false
	}
	f.req.NoError(err)

	if nodeObj.Name != expected.Name ||
		!nodeObj.Spec.DeepEqual(&expected.Spec) ||
		!nodeObj.Status.DeepEqual(&expected.Status) {

		return false
	}

	return true
}
