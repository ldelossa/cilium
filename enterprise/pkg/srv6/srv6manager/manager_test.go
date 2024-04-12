//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package srv6manager

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	srv6Types "github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	slimMetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/srv6map"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/types"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	k8sTesting "k8s.io/client-go/testing"
)

type fakeSIDAllocator struct {
	sid           srv6Types.SID
	structure     srv6Types.SIDStructure
	behaviorType  srv6Types.BehaviorType
	allocatedSIDs []*sidmanager.SIDInfo
}

func (fsa *fakeSIDAllocator) Locator() srv6Types.Locator {
	return srv6Types.Locator{}
}

func (fsa *fakeSIDAllocator) Structure() srv6Types.SIDStructure {
	return fsa.structure
}

func (fsa *fakeSIDAllocator) BehaviorType() srv6Types.BehaviorType {
	return fsa.behaviorType
}

func (fsa *fakeSIDAllocator) Allocate(_ netip.Addr, owner string, metadata string, behavior srv6Types.Behavior) (*sidmanager.SIDInfo, error) {
	return &sidmanager.SIDInfo{
		Owner:        owner,
		MetaData:     metadata,
		SID:          fsa.sid,
		BehaviorType: fsa.behaviorType,
		Behavior:     behavior,
	}, nil
}

func (fsa *fakeSIDAllocator) AllocateNext(owner string, metadata string, behavior srv6Types.Behavior) (*sidmanager.SIDInfo, error) {
	return &sidmanager.SIDInfo{
		Owner:        owner,
		MetaData:     metadata,
		SID:          fsa.sid,
		BehaviorType: fsa.behaviorType,
		Behavior:     behavior,
	}, nil
}

func (fsa *fakeSIDAllocator) Release(sid netip.Addr) error {
	return nil
}

func (fsa *fakeSIDAllocator) AllocatedSIDs(owner string) []*sidmanager.SIDInfo {
	return fsa.allocatedSIDs
}

type fakeSIDAllocatorSyncer struct {
	sidmanager.SIDAllocator
}

func (fsas *fakeSIDAllocatorSyncer) Sync() {
}

type fakeSIDManager struct {
	pools map[string]sidmanager.SIDAllocator
}

func (fsm *fakeSIDManager) Observe(ctx context.Context, next func(sidmanager.Event), complete func(error)) {
	go func() {
		// Just replay the initial state and do nothing after that
		for poolName, allocator := range fsm.pools {
			next(sidmanager.Event{
				Kind:     sidmanager.Upsert,
				PoolName: poolName,
				Allocator: &fakeSIDAllocatorSyncer{
					SIDAllocator: allocator,
				},
			})
		}
		next(sidmanager.Event{Kind: sidmanager.Sync})
		<-ctx.Done()
		complete(ctx.Err())
	}()
}

type fakeIPAMAllocator struct {
	sid net.IP
}

var _ ipam.Allocator = (*fakeIPAMAllocator)(nil)

func (fa *fakeIPAMAllocator) Allocate(ip net.IP, owner string, pool ipam.Pool) (*ipam.AllocationResult, error) {
	return nil, nil
}

func (fa *fakeIPAMAllocator) AllocateWithoutSyncUpstream(ip net.IP, owner string, pool ipam.Pool) (*ipam.AllocationResult, error) {
	return nil, nil
}

func (fa *fakeIPAMAllocator) Release(ip net.IP, pool ipam.Pool) error {
	return nil
}

func (fa *fakeIPAMAllocator) AllocateNext(owner string, pool ipam.Pool) (*ipam.AllocationResult, error) {
	return &ipam.AllocationResult{
		IP: fa.sid,
	}, nil
}

func (fa *fakeIPAMAllocator) AllocateNextWithoutSyncUpstream(owner string, pool ipam.Pool) (*ipam.AllocationResult, error) {
	return nil, nil
}

func (fa *fakeIPAMAllocator) Dump() (map[ipam.Pool]map[string]string, string) {
	return nil, ""
}

func (fa *fakeIPAMAllocator) RestoreFinished() {
}

func (fa *fakeIPAMAllocator) Capacity() uint64 {
	return 0
}

type comparableObject[T any] interface {
	metav1.Object
	DeepEqual(obj T) bool
}

func planK8sObj[T comparableObject[T]](oldObjs, newObjs []T) (toAdd, toUpdate, toDelete []T) {
	for _, newObj := range newObjs {
		found := false
		for _, oldObj := range oldObjs {
			if newObj.GetName() == oldObj.GetName() {
				found = true
				if !newObj.DeepEqual(oldObj) {
					toUpdate = append(toUpdate, newObj)
				}
				break
			}
		}
		if !found {
			toAdd = append(toAdd, newObj)
		}
	}
	for _, oldObj := range oldObjs {
		found := false
		for _, newObj := range newObjs {
			if oldObj.GetName() == newObj.GetName() {
				found = true
				break
			}
		}
		if !found {
			toDelete = append(toDelete, oldObj)
		}
	}
	return
}

type comparableKV[T any] interface {
	Equal(obj T) bool
}

type vrfKV struct {
	k *srv6map.VRFKey
	v *srv6map.VRFValue
}

func (a *vrfKV) Equal(b *vrfKV) bool {
	return a.k.Equal(b.k) && a.v.Equal(b.v)
}

type policyKV struct {
	k *srv6map.PolicyKey
	v *srv6map.PolicyValue
}

func (a *policyKV) Equal(b *policyKV) bool {
	return a.k.Equal(b.k) && a.v.Equal(b.v)
}

type sidKV struct {
	k *srv6map.SIDKey
	v *srv6map.SIDValue
}

func (a *sidKV) Equal(b *sidKV) bool {
	return a.k.Equal(b.k) && a.v.Equal(b.v)
}

func bpfMapsEqual[T comparableKV[T]](a, b []T) bool {
	for _, kva := range a {
		found := false
		for _, kvb := range a {
			if kva.Equal(kvb) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	for _, kvb := range b {
		found := false
		for _, kva := range a {
			if kvb.Equal(kva) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

type fakeDaemon struct {
	a ipam.Allocator
}

func (fd *fakeDaemon) GetIPv6Allocator() ipam.Allocator {
	return fd.a
}

type fixture struct {
	watching chan struct{}
	hive     *hive.Hive
}

func newFixture(t *testing.T, useRealSIDManager bool, invokeFn any) *fixture {
	fixture := &fixture{
		watching: make(chan struct{}),
	}

	cells := []cell.Cell{}

	if useRealSIDManager {
		cells = append(cells, sidmanager.SIDManagerCell)
	} else {
		cells = append(cells,
			cell.Provide(
				func() (promise.Promise[sidmanager.SIDManager], *fakeSIDManager) {
					smResolver, smPromise := promise.New[sidmanager.SIDManager]()
					fsm := &fakeSIDManager{
						pools: map[string]sidmanager.SIDAllocator{},
					}
					smResolver.Resolve(fsm)
					return smPromise, fsm
				},
			),
		)
	}

	cells = append(cells,
		cell.Provide(
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableSRv6: true,
				}
			},
			func() (promise.Promise[daemon], *fakeIPAMAllocator) {
				fia := &fakeIPAMAllocator{}
				fd := &fakeDaemon{a: fia}
				daemonResolver, daemonPromise := promise.New[daemon]()
				daemonResolver.Resolve(fd)
				return daemonPromise, fia
			},
			func() cache.IdentityAllocator {
				return testidentity.NewMockIdentityAllocator(nil)
			},
			NewSRv6Manager,
			node.NewLocalNodeStore,
			client.NewFakeClientset,
			newIsovalentVRFResource,
			signaler.NewBGPCPSignaler,
			k8s.CiliumSlimEndpointResource,
			newIsovalentSRv6EgressPolicyResource,
		),
		cell.Invoke(
			invokeFn,

			// This is a workaround for https://github.com/cilium/cilium/pull/31010. We should
			// have the same issue here.
			func(fcs *client.FakeClientset) {
				var once sync.Once
				fcs.CiliumFakeClientset.PrependWatchReactor("*", func(action k8sTesting.Action) (handled bool, ret watch.Interface, err error) {
					w := action.(k8sTesting.WatchAction)
					gvr := w.GetResource()
					ns := w.GetNamespace()
					watch, err := fcs.CiliumFakeClientset.Tracker().Watch(gvr, ns)
					if err != nil {
						return false, nil, err
					}
					once.Do(func() { close(fixture.watching) })
					return true, watch, nil
				})
			},
		),
	)

	fixture.hive = hive.New(cells...)

	return fixture
}

func allocateIdentity(t *testing.T, identityAllocator cache.IdentityAllocator, ep *v2.CiliumEndpoint) {
	labels := labels.NewLabelsFromModel(ep.Status.Identity.Labels)
	id, _, err := identityAllocator.AllocateIdentity(context.TODO(), labels, false, identity.NumericIdentity(ep.Status.Identity.ID))
	require.NoError(t, err)
	ep.Status.Identity.ID = int64(id.ID)
}

func TestSRv6Manager(t *testing.T) {
	testutils.PrivilegedTest(t)

	log.Logger.SetLevel(logrus.DebugLevel)

	// Fixtures
	endpoint1 := &v2.CiliumEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "pod1",
			Labels: map[string]string{
				"vrf": "vrf0",
			},
		},
		Status: v2.EndpointStatus{
			Identity: &v2.EndpointIdentity{
				Labels: []string{
					"k8s:vrf=vrf0",
				},
			},
			Networking: &v2.EndpointNetworking{
				Addressing: v2.AddressPairList{
					{
						IPV4: "10.0.0.1",
					},
				},
			},
		},
	}

	ip1 := net.ParseIP("10.0.0.1")
	_, cidr1, _ := net.ParseCIDR("0.0.0.0/0")
	_, cidr2, _ := net.ParseCIDR("10.0.0.0/24")

	sid1IP := net.ParseIP("fd00:0:0:1::")
	sid2IP := net.ParseIP("fd00:0:1:1::")
	sid3 := srv6Types.MustNewSID(netip.MustParseAddr("fd00:0:1:2::"))

	vrf0 := &v1alpha1.IsovalentVRF{
		ObjectMeta: metav1.ObjectMeta{
			Name: "vrf0",
		},
		Spec: v1alpha1.IsovalentVRFSpec{
			VRFID: 1,
			Rules: []v1alpha1.IsovalentVRFRule{
				{
					Selectors: []v1alpha1.IsovalentVRFEgressRule{
						{
							EndpointSelector: &slimMetav1.LabelSelector{
								MatchLabels: map[string]slimMetav1.MatchLabelsValue{
									"vrf": "vrf0",
								},
							},
						},
					},
					DestinationCIDRs: []v1alpha1.CIDR{
						v1alpha1.CIDR(cidr1.String()),
					},
				},
			},
		},
	}

	vrf0WithVRFID2 := vrf0.DeepCopy()
	vrf0WithVRFID2.Spec.VRFID = 2

	vrf0WithDestinationCIDR := vrf0.DeepCopy()
	vrf0WithDestinationCIDR.Spec.Rules[0].DestinationCIDRs[0] = v1alpha1.CIDR(cidr2.String())

	vrf0WithExportRouteTarget := vrf0.DeepCopy()
	vrf0WithExportRouteTarget.Spec.ExportRouteTarget = "65000:1"

	vrf0WithExportRouteTarget2 := vrf0.DeepCopy()
	vrf0WithExportRouteTarget2.Spec.ExportRouteTarget = "65000:2"

	vrf0WithExportRouteTargetAndLocatorPoolRef := vrf0WithExportRouteTarget.DeepCopy()
	vrf0WithExportRouteTargetAndLocatorPoolRef.Spec.LocatorPoolRef = "pool1"

	policy0 := &v1alpha1.IsovalentSRv6EgressPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy0",
		},
		Spec: v1alpha1.IsovalentSRv6EgressPolicySpec{
			VRFID: 1,
			DestinationCIDRs: []v1alpha1.CIDR{
				v1alpha1.CIDR(cidr2.String()),
			},
			DestinationSID: sid1IP.String(),
		},
	}

	policy0WithVRFID2 := policy0.DeepCopy()
	policy0WithVRFID2.Spec.VRFID = 2

	tests := []struct {
		name                    string
		initEndpoints           []*v2.CiliumEndpoint
		initVRFs                []*v1alpha1.IsovalentVRF
		initPolicies            []*v1alpha1.IsovalentSRv6EgressPolicy
		initVRFMapEntries       []*vrfKV
		initPolicyMapEntries    []*policyKV
		initSIDMapEntries       []*sidKV
		updatedEndpoints        []*v2.CiliumEndpoint
		updatedVRFs             []*v1alpha1.IsovalentVRF
		updatedPolicies         []*v1alpha1.IsovalentSRv6EgressPolicy
		updatedVRFMapEntries    []*vrfKV
		updatedPolicyMapEntries []*policyKV
		updatedSIDMapEntries    []*sidKV
	}{
		{
			name:             "Add VRF",
			updatedEndpoints: []*v2.CiliumEndpoint{endpoint1},
			updatedVRFs:      []*v1alpha1.IsovalentVRF{vrf0},
			updatedVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
		},
		{
			name:          "Update VRF VRFID",
			initEndpoints: []*v2.CiliumEndpoint{endpoint1},
			initVRFs:      []*v1alpha1.IsovalentVRF{vrf0},
			initVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
			updatedEndpoints: []*v2.CiliumEndpoint{endpoint1},
			updatedVRFs:      []*v1alpha1.IsovalentVRF{vrf0WithVRFID2},
			updatedVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 2},
				},
			},
		},
		{
			name:          "Update VRF DestinationCIDR",
			initEndpoints: []*v2.CiliumEndpoint{endpoint1},
			initVRFs:      []*v1alpha1.IsovalentVRF{vrf0},
			initVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
			updatedEndpoints: []*v2.CiliumEndpoint{endpoint1},
			updatedVRFs:      []*v1alpha1.IsovalentVRF{vrf0WithDestinationCIDR},
			updatedVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr2},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
		},
		{
			name:          "Update VRF ExportRouteTarget",
			initEndpoints: []*v2.CiliumEndpoint{endpoint1},
			initVRFs:      []*v1alpha1.IsovalentVRF{vrf0WithExportRouteTarget},
			initVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
			updatedEndpoints: []*v2.CiliumEndpoint{endpoint1},
			updatedVRFs:      []*v1alpha1.IsovalentVRF{vrf0WithExportRouteTarget2},
			updatedVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
		},
		{
			name:             "Allocate SID with default allocator",
			updatedEndpoints: []*v2.CiliumEndpoint{endpoint1},
			updatedVRFs:      []*v1alpha1.IsovalentVRF{vrf0WithExportRouteTarget},
			updatedVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
			updatedSIDMapEntries: []*sidKV{
				{
					k: &srv6map.SIDKey{SID: types.IPv6(sid2IP.To16())},
					v: &srv6map.SIDValue{VRFID: 1},
				},
			},
		},
		{
			name:          "Remove VRF ExportRouteTarget",
			initEndpoints: []*v2.CiliumEndpoint{endpoint1},
			initVRFs:      []*v1alpha1.IsovalentVRF{vrf0WithExportRouteTarget},
			initVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
			initSIDMapEntries: []*sidKV{
				{
					k: &srv6map.SIDKey{SID: types.IPv6(sid2IP.To16())},
					v: &srv6map.SIDValue{VRFID: 1},
				},
			},
			updatedEndpoints: []*v2.CiliumEndpoint{endpoint1},
			updatedVRFs:      []*v1alpha1.IsovalentVRF{vrf0},
			updatedVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
		},
		{
			name:             "Allocate SID with SIDManager",
			updatedEndpoints: []*v2.CiliumEndpoint{endpoint1},
			updatedVRFs:      []*v1alpha1.IsovalentVRF{vrf0WithExportRouteTargetAndLocatorPoolRef},
			updatedVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
			updatedSIDMapEntries: []*sidKV{
				{
					k: &srv6map.SIDKey{SID: types.IPv6(sid3.As16())},
					v: &srv6map.SIDValue{VRFID: 1},
				},
			},
		},
		{
			name:          "Update SID allocation from default allocator to SIDManager",
			initEndpoints: []*v2.CiliumEndpoint{endpoint1},
			initVRFs:      []*v1alpha1.IsovalentVRF{vrf0WithExportRouteTarget},
			initVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
			initSIDMapEntries: []*sidKV{
				{
					k: &srv6map.SIDKey{SID: types.IPv6(sid2IP.To16())},
					v: &srv6map.SIDValue{VRFID: 1},
				},
			},
			updatedEndpoints: []*v2.CiliumEndpoint{endpoint1},
			updatedVRFs:      []*v1alpha1.IsovalentVRF{vrf0WithExportRouteTargetAndLocatorPoolRef},
			updatedVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
			updatedSIDMapEntries: []*sidKV{
				{
					k: &srv6map.SIDKey{SID: types.IPv6(sid3.As16())},
					v: &srv6map.SIDValue{VRFID: 1},
				},
			},
		},
		{
			name:          "Update SID allocation from SIDManager to default allocator",
			initEndpoints: []*v2.CiliumEndpoint{endpoint1},
			initVRFs:      []*v1alpha1.IsovalentVRF{vrf0WithExportRouteTargetAndLocatorPoolRef},
			initVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
			initSIDMapEntries: []*sidKV{
				{
					k: &srv6map.SIDKey{SID: types.IPv6(sid3.As16())},
					v: &srv6map.SIDValue{VRFID: 1},
				},
			},
			updatedEndpoints: []*v2.CiliumEndpoint{endpoint1},
			updatedVRFs:      []*v1alpha1.IsovalentVRF{vrf0WithExportRouteTarget},
			updatedVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
			updatedSIDMapEntries: []*sidKV{
				{
					k: &srv6map.SIDKey{SID: types.IPv6(sid2IP.To16())},
					v: &srv6map.SIDValue{VRFID: 1},
				},
			},
		},
		{
			name:          "Delete VRF",
			initEndpoints: []*v2.CiliumEndpoint{endpoint1},
			initVRFs:      []*v1alpha1.IsovalentVRF{vrf0},
			initVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
			updatedEndpoints: []*v2.CiliumEndpoint{endpoint1},
		},
		{
			name:             "Add Endpoint",
			initVRFs:         []*v1alpha1.IsovalentVRF{vrf0},
			updatedEndpoints: []*v2.CiliumEndpoint{endpoint1},
			updatedVRFs:      []*v1alpha1.IsovalentVRF{vrf0},
			updatedVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
		},
		{
			name:          "Delete Endpoint",
			initEndpoints: []*v2.CiliumEndpoint{endpoint1},
			initVRFs:      []*v1alpha1.IsovalentVRF{vrf0},
			initVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
			updatedVRFs: []*v1alpha1.IsovalentVRF{vrf0},
		},
		{
			name:             "Create Policy",
			updatedEndpoints: []*v2.CiliumEndpoint{endpoint1},
			updatedVRFs:      []*v1alpha1.IsovalentVRF{vrf0},
			updatedPolicies:  []*v1alpha1.IsovalentSRv6EgressPolicy{policy0},
			updatedVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
			updatedPolicyMapEntries: []*policyKV{
				{
					k: &srv6map.PolicyKey{VRFID: 1, DestCIDR: cidr2},
					v: &srv6map.PolicyValue{SID: types.IPv6(sid1IP.To16())},
				},
			},
		},
		{
			name:          "Update Policy VRFID",
			initEndpoints: []*v2.CiliumEndpoint{endpoint1},
			initVRFs:      []*v1alpha1.IsovalentVRF{vrf0},
			initPolicies:  []*v1alpha1.IsovalentSRv6EgressPolicy{policy0},
			initVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
			initPolicyMapEntries: []*policyKV{
				{
					k: &srv6map.PolicyKey{VRFID: 1, DestCIDR: cidr2},
					v: &srv6map.PolicyValue{SID: types.IPv6(sid1IP.To16())},
				},
			},
			updatedEndpoints: []*v2.CiliumEndpoint{endpoint1},
			updatedVRFs:      []*v1alpha1.IsovalentVRF{vrf0},
			updatedPolicies:  []*v1alpha1.IsovalentSRv6EgressPolicy{policy0WithVRFID2},
			updatedVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
			updatedPolicyMapEntries: []*policyKV{
				{
					k: &srv6map.PolicyKey{VRFID: 2, DestCIDR: cidr2},
					v: &srv6map.PolicyValue{SID: types.IPv6(sid1IP.To16())},
				},
			},
		},
		{
			name:          "Delete Policy",
			initEndpoints: []*v2.CiliumEndpoint{endpoint1},
			initVRFs:      []*v1alpha1.IsovalentVRF{vrf0},
			initPolicies:  []*v1alpha1.IsovalentSRv6EgressPolicy{policy0},
			initVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
			initPolicyMapEntries: []*policyKV{
				{
					k: &srv6map.PolicyKey{VRFID: 1, DestCIDR: cidr2},
					v: &srv6map.PolicyValue{SID: types.IPv6(sid1IP.To16())},
				},
			},
			updatedEndpoints: []*v2.CiliumEndpoint{endpoint1},
			updatedVRFs:      []*v1alpha1.IsovalentVRF{vrf0},
			updatedVRFMapEntries: []*vrfKV{
				{
					k: &srv6map.VRFKey{SourceIP: &ip1, DestCIDR: cidr1},
					v: &srv6map.VRFValue{ID: 1},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv6map.CreateMaps()
			t.Cleanup(func() {
				srv6map.DeleteMaps()
			})

			var (
				ia cache.IdentityAllocator
				cs client.Clientset
			)

			fixture := newFixture(
				t,
				false,
				func(
					identityAllocator cache.IdentityAllocator,
					clientset client.Clientset,
					manager *Manager,
					fia *fakeIPAMAllocator,
					fsm *fakeSIDManager,
				) {
					ia = identityAllocator
					cs = clientset

					fia.sid = sid2IP
					fsm.pools["pool1"] = &fakeSIDAllocator{
						sid:          sid3,
						behaviorType: srv6Types.BehaviorTypeBase,
					}
				},
			)

			require.NoError(t, fixture.hive.Start(context.TODO()))
			t.Cleanup(func() {
				fixture.hive.Stop(context.TODO())
			})

			<-fixture.watching

			// Create initial CiliumEndpoints
			for _, ep := range test.initEndpoints {
				copied := ep.DeepCopy()
				allocateIdentity(t, ia, copied)
				_, err := cs.CiliumV2().CiliumEndpoints(ep.Namespace).Create(context.TODO(), copied, metav1.CreateOptions{})
				require.NoError(t, err)
			}

			for _, vrf := range test.initVRFs {
				_, err := cs.IsovalentV1alpha1().IsovalentVRFs().Create(context.TODO(), vrf.DeepCopy(), metav1.CreateOptions{})
				require.NoError(t, err)
			}

			for _, policy := range test.initPolicies {
				_, err := cs.IsovalentV1alpha1().IsovalentSRv6EgressPolicies().Create(context.TODO(), policy.DeepCopy(), metav1.CreateOptions{})
				require.NoError(t, err)
			}

			// Ensure all maps are initialized as expected
			require.Eventually(t, func() bool {
				currentVRFMapEntries := []*vrfKV{}
				srv6map.SRv6VRFMap4.IterateWithCallback4(func(k *srv6map.VRFKey, v *srv6map.VRFValue) {
					currentVRFMapEntries = append(currentVRFMapEntries, &vrfKV{k: k, v: v})
				})
				if !bpfMapsEqual(currentVRFMapEntries, test.initVRFMapEntries) {
					t.Log("VRF map entries are mismatched, retrying")
					return false
				}

				currentPolicyMapEntries := []*policyKV{}
				srv6map.SRv6PolicyMap4.IterateWithCallback4(func(k *srv6map.PolicyKey, v *srv6map.PolicyValue) {
					currentPolicyMapEntries = append(currentPolicyMapEntries, &policyKV{k: k, v: v})
				})
				if !bpfMapsEqual(currentPolicyMapEntries, test.initPolicyMapEntries) {
					t.Log("Policy map entries are mismatching, retrying")
					return false
				}

				currentSIDMapEntries := []*sidKV{}
				srv6map.SRv6SIDMap.IterateWithCallback(func(k *srv6map.SIDKey, v *srv6map.SIDValue) {
					currentSIDMapEntries = append(currentSIDMapEntries, &sidKV{k: k, v: v})
				})
				if !bpfMapsEqual(currentSIDMapEntries, test.initSIDMapEntries) {
					t.Log("SID map entries are mismatched, retrying")
					return false
				}

				return true
			}, time.Second*3, time.Millisecond*100)

			// Do CRUD for Endpoints
			epsToAdd, epsToUpdate, epsToDelete := planK8sObj(test.initEndpoints, test.updatedEndpoints)

			for _, ep := range epsToAdd {
				copied := ep.DeepCopy()
				allocateIdentity(t, ia, copied)
				_, err := cs.CiliumV2().CiliumEndpoints(ep.Namespace).Create(context.TODO(), copied, metav1.CreateOptions{})
				require.NoError(t, err)
			}

			for _, ep := range epsToUpdate {
				_, err := cs.CiliumV2().CiliumEndpoints(ep.Namespace).Update(context.TODO(), ep.DeepCopy(), metav1.UpdateOptions{})
				require.NoError(t, err)
			}

			for _, ep := range epsToDelete {
				err := cs.CiliumV2().CiliumEndpoints(ep.Namespace).Delete(context.TODO(), ep.Name, metav1.DeleteOptions{})
				require.NoError(t, err)
			}

			// Do CRUD for VRFs
			vrfsToAdd, vrfsToUpdate, vrfsToDel := planK8sObj(test.initVRFs, test.updatedVRFs)

			for _, vrf := range vrfsToAdd {
				_, err := cs.IsovalentV1alpha1().IsovalentVRFs().Create(context.TODO(), vrf.DeepCopy(), metav1.CreateOptions{})
				require.NoError(t, err)
			}

			for _, vrf := range vrfsToUpdate {
				_, err := cs.IsovalentV1alpha1().IsovalentVRFs().Update(context.TODO(), vrf.DeepCopy(), metav1.UpdateOptions{})
				require.NoError(t, err)
			}

			for _, vrf := range vrfsToDel {
				err := cs.IsovalentV1alpha1().IsovalentVRFs().Delete(context.TODO(), vrf.GetName(), metav1.DeleteOptions{})
				require.NoError(t, err)
			}

			// Do CRUD for Policies
			policiesToAdd, policiesToUpdate, policiesToDel := planK8sObj(test.initPolicies, test.updatedPolicies)

			for _, policy := range policiesToAdd {
				_, err := cs.IsovalentV1alpha1().IsovalentSRv6EgressPolicies().Create(context.TODO(), policy.DeepCopy(), metav1.CreateOptions{})
				require.NoError(t, err)
			}

			for _, policy := range policiesToUpdate {
				_, err := cs.IsovalentV1alpha1().IsovalentSRv6EgressPolicies().Update(context.TODO(), policy.DeepCopy(), metav1.UpdateOptions{})
				require.NoError(t, err)
			}

			for _, policy := range policiesToDel {
				err := cs.IsovalentV1alpha1().IsovalentSRv6EgressPolicies().Delete(context.TODO(), policy.GetName(), metav1.DeleteOptions{})
				require.NoError(t, err)
			}

			// Make sure all maps are updated as expected
			require.Eventually(t, func() bool {
				currentVRFMapEntries := []*vrfKV{}
				srv6map.SRv6VRFMap4.IterateWithCallback4(func(k *srv6map.VRFKey, v *srv6map.VRFValue) {
					currentVRFMapEntries = append(currentVRFMapEntries, &vrfKV{k: k, v: v})
				})
				if !bpfMapsEqual(currentVRFMapEntries, test.updatedVRFMapEntries) {
					t.Log("VRF map entries are mismatched, retrying")
					return false
				}

				currentPolicyMapEntries := []*policyKV{}
				srv6map.SRv6PolicyMap4.IterateWithCallback4(func(k *srv6map.PolicyKey, v *srv6map.PolicyValue) {
					currentPolicyMapEntries = append(currentPolicyMapEntries, &policyKV{k: k, v: v})
				})
				if !bpfMapsEqual(currentPolicyMapEntries, test.updatedPolicyMapEntries) {
					t.Log("Policy map entries are mismatched, retrying")
					return false
				}

				currentSIDMapEntries := []*sidKV{}
				srv6map.SRv6SIDMap.IterateWithCallback(func(k *srv6map.SIDKey, v *srv6map.SIDValue) {
					currentSIDMapEntries = append(currentSIDMapEntries, &sidKV{k: k, v: v})
				})
				if !bpfMapsEqual(currentSIDMapEntries, test.updatedSIDMapEntries) {
					t.Log("SID map entries are mismatched, retrying")
					return false
				}

				return true
			}, time.Second*3, time.Millisecond*100)
		})
	}
}

func eventually(t *testing.T, f func() bool) {
	require.Eventually(t, f, time.Second*3, time.Millisecond*200)
}

func TestSRv6ManagerWithSIDManager(t *testing.T) {
	testutils.PrivilegedTest(t)

	log.Logger.SetLevel(logrus.DebugLevel)

	vrf0 := &v1alpha1.IsovalentVRF{
		ObjectMeta: metav1.ObjectMeta{
			Name: "vrf0",
		},
		Spec: v1alpha1.IsovalentVRFSpec{
			VRFID:             1,
			ExportRouteTarget: "65000:1",
			LocatorPoolRef:    "pool1",
			Rules: []v1alpha1.IsovalentVRFRule{
				{
					Selectors: []v1alpha1.IsovalentVRFEgressRule{
						{
							EndpointSelector: &slimMetav1.LabelSelector{
								MatchLabels: map[string]slimMetav1.MatchLabelsValue{
									"vrf": "vrf0",
								},
							},
						},
					},
					DestinationCIDRs: []v1alpha1.CIDR{
						v1alpha1.CIDR("0.0.0.0/0"),
					},
				},
			},
		},
	}

	ep := &v2.CiliumEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "pod1",
			Labels: map[string]string{
				"vrf": "vrf0",
			},
		},
		Status: v2.EndpointStatus{
			Identity: &v2.EndpointIdentity{
				Labels: []string{
					"k8s:vrf=vrf0",
				},
			},
			Networking: &v2.EndpointNetworking{
				Addressing: v2.AddressPairList{
					{
						IPV4: "10.0.0.1",
					},
				},
			},
		},
	}

	sidmanager1 := &v1alpha1.IsovalentSRv6SIDManager{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeTypes.GetName(),
		},
		Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
			LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
				{
					PoolRef: "pool1",
					Locators: []*v1alpha1.IsovalentSRv6Locator{
						{
							Prefix: "fd00:1:1::/48",
							Structure: v1alpha1.IsovalentSRv6SIDStructure{
								LocatorBlockLenBits: 32,
								LocatorNodeLenBits:  16,
								FunctionLenBits:     16,
								ArgumentLenBits:     0,
							},
							BehaviorType: "Base",
						},
					},
				},
			},
		},
	}

	srv6map.CreateMaps()
	t.Cleanup(func() {
		srv6map.DeleteMaps()
	})

	var (
		c                 client.Clientset
		manager           *Manager
		identityAllocator cache.IdentityAllocator
	)

	fixture := newFixture(
		t,
		true,
		func(cs client.Clientset, m *Manager, ia cache.IdentityAllocator) {
			c = cs
			manager = m
			identityAllocator = ia
		},
	)

	err := fixture.hive.Start(context.TODO())
	require.NoError(t, err)
	t.Cleanup(func() {
		err := fixture.hive.Stop(context.TODO())
		require.NoError(t, err)
	})

	<-fixture.watching

	copied := ep.DeepCopy()
	allocateIdentity(t, identityAllocator, copied)
	_, err = c.CiliumV2().CiliumEndpoints(ep.Namespace).Create(context.TODO(), copied, metav1.CreateOptions{})
	require.NoError(t, err)

	_, err = c.IsovalentV1alpha1().IsovalentVRFs().Create(context.TODO(), vrf0.DeepCopy(), metav1.CreateOptions{})
	require.NoError(t, err)

	smClient := c.IsovalentV1alpha1().IsovalentSRv6SIDManagers()

	var sid1, sid2 netip.Addr

	t.Run("TestAddLocator", func(t *testing.T) {
		_, err := smClient.Create(context.TODO(), sidmanager1, metav1.CreateOptions{})
		require.NoError(t, err)

		// Get allocated SID from status field
		eventually(t, func() bool {
			sm, err := smClient.Get(context.TODO(), sidmanager1.Name, metav1.GetOptions{})
			if err != nil {
				return false
			}
			if len(sm.Status.SIDAllocations) != 1 {
				return false
			}
			if len(sm.Status.SIDAllocations[0].SIDs) != 1 {
				return false
			}
			sid1 = netip.MustParseAddr(sm.Status.SIDAllocations[0].SIDs[0].SID.Addr)
			return strings.HasPrefix(sid1.String(), "fd00:1:1:")
		})

		// Now the SID allocation from SIDManager and update to the SIDMap should happen eventually
		eventually(t, func() bool {
			vrfs := manager.GetAllVRFs()
			if len(vrfs) != 1 {
				return false
			}

			if vrfs[0].SIDInfo == nil {
				return false
			}

			info := vrfs[0].SIDInfo
			if ownerName != info.Owner ||
				vrf0.Name != info.MetaData ||
				sid1.String() != info.SID.Addr.String() ||
				srv6Types.BehaviorTypeBase != info.BehaviorType ||
				srv6Types.BehaviorEndDT4 != info.Behavior {
				return false
			}

			var val srv6map.SIDValue
			return srv6map.SRv6SIDMap.Lookup(srv6map.SIDKey{SID: sid1.As16()}, &val) == nil
		})
	})

	t.Run("TestUpdateLocator", func(t *testing.T) {
		sidmanager := sidmanager1.DeepCopy()
		sidmanager.Spec.LocatorAllocations[0].Locators[0].Prefix = "fd00:1:2::/48"
		_, err := c.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(context.TODO(), sidmanager, metav1.UpdateOptions{})
		require.NoError(t, err)

		// Get allocated SID from status field
		eventually(t, func() bool {
			sm, err := smClient.Get(context.TODO(), sidmanager1.Name, metav1.GetOptions{})
			if err != nil {
				return false
			}
			if len(sm.Status.SIDAllocations) != 1 {
				return false
			}
			if len(sm.Status.SIDAllocations[0].SIDs) != 1 {
				return false
			}
			sid2 = netip.MustParseAddr(sm.Status.SIDAllocations[0].SIDs[0].SID.Addr)
			return strings.HasPrefix(sid2.String(), "fd00:1:2:")
		})

		// Now the SID allocation from SIDManager should happen and old SIDMap entry should
		// be removed and a new SIDMap entry should appear.
		eventually(t, func() bool {
			vrfs := manager.GetAllVRFs()
			if len(vrfs) != 1 {
				return false
			}

			if vrfs[0].SIDInfo == nil {
				return false
			}

			info := vrfs[0].SIDInfo
			if ownerName != info.Owner ||
				vrf0.Name != info.MetaData ||
				sid2.String() != info.SID.Addr.String() ||
				srv6Types.BehaviorTypeBase != info.BehaviorType ||
				srv6Types.BehaviorEndDT4 != info.Behavior {
				return false
			}

			var val srv6map.SIDValue
			err := srv6map.SRv6SIDMap.Lookup(srv6map.SIDKey{SID: sid2.As16()}, &val)
			if err != nil {
				return false
			}

			err = srv6map.SRv6SIDMap.Lookup(srv6map.SIDKey{SID: sid1.As16()}, &val)
			if err == nil {
				return false
			}

			return errors.Is(err, ebpf.ErrKeyNotExist)
		})
	})

	t.Run("TestDeleteLocator", func(t *testing.T) {
		sidmanager := sidmanager1.DeepCopy()
		sidmanager.Spec.LocatorAllocations = []*v1alpha1.IsovalentSRv6LocatorAllocation{}
		_, err := c.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(context.TODO(), sidmanager, metav1.UpdateOptions{})
		require.NoError(t, err)

		// Now the SID deletion from SIDManager should happen and old SIDMap entry should disappear
		eventually(t, func() bool {
			vrfs := manager.GetAllVRFs()
			if len(vrfs) != 1 {
				return false
			}

			if vrfs[0].SIDInfo != nil {
				return false
			}

			var val srv6map.SIDValue
			err = srv6map.SRv6SIDMap.Lookup(srv6map.SIDKey{SID: sid2.As16()}, &val)
			if err == nil {
				return false
			}

			return errors.Is(err, ebpf.ErrKeyNotExist)
		})
	})
}

func TestSIDManagerSIDRestoration(t *testing.T) {
	testutils.PrivilegedTest(t)

	log.Logger.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name                string
		vrf                 *v1alpha1.IsovalentVRF
		existingAllocations []*sidmanager.SIDInfo
		behaviorType        srv6Types.BehaviorType
		expectedAllocation  *sidmanager.SIDInfo
	}{
		{
			name: "Valid restoration",
			vrf: &v1alpha1.IsovalentVRF{
				ObjectMeta: metav1.ObjectMeta{
					Name: "vrf0",
				},
				Spec: v1alpha1.IsovalentVRFSpec{
					VRFID:             1,
					ExportRouteTarget: "65000:1",
					LocatorPoolRef:    "pool1",
				},
			},
			existingAllocations: []*sidmanager.SIDInfo{
				{
					Owner:        ownerName,
					MetaData:     "vrf0",
					SID:          srv6Types.MustNewSID(netip.MustParseAddr("fd00:0:0:1::")),
					Structure:    srv6Types.MustNewSIDStructure(32, 16, 16, 0),
					BehaviorType: srv6Types.BehaviorTypeBase,
					Behavior:     srv6Types.BehaviorEndDT4,
				},
			},
			behaviorType: srv6Types.BehaviorTypeBase,
			expectedAllocation: &sidmanager.SIDInfo{
				Owner:        ownerName,
				MetaData:     "vrf0",
				SID:          srv6Types.MustNewSID(netip.MustParseAddr("fd00:0:0:1::")),
				Structure:    srv6Types.MustNewSIDStructure(32, 16, 16, 0),
				BehaviorType: srv6Types.BehaviorTypeBase,
				Behavior:     srv6Types.BehaviorEndDT4,
			},
		},
		{
			name: "VRF doesn't exist",
			vrf:  nil,
			existingAllocations: []*sidmanager.SIDInfo{
				{
					Owner:        ownerName,
					MetaData:     "vrf0",
					SID:          srv6Types.MustNewSID(netip.MustParseAddr("fd00:0:0:1::")),
					Structure:    srv6Types.MustNewSIDStructure(32, 16, 16, 0),
					BehaviorType: srv6Types.BehaviorTypeBase,
					Behavior:     srv6Types.BehaviorEndDT4,
				},
			},
			behaviorType:       srv6Types.BehaviorTypeBase,
			expectedAllocation: nil,
		},
		{
			name: "No ExportRouteTarget",
			vrf: &v1alpha1.IsovalentVRF{
				ObjectMeta: metav1.ObjectMeta{
					Name: "vrf0",
				},
				Spec: v1alpha1.IsovalentVRFSpec{
					VRFID: 1,
				},
			},
			existingAllocations: []*sidmanager.SIDInfo{
				{
					Owner:        ownerName,
					MetaData:     "vrf0",
					SID:          srv6Types.MustNewSID(netip.MustParseAddr("fd00:0:0:1::")),
					Structure:    srv6Types.MustNewSIDStructure(32, 16, 16, 0),
					BehaviorType: srv6Types.BehaviorTypeBase,
					Behavior:     srv6Types.BehaviorEndDT4,
				},
			},
			behaviorType:       srv6Types.BehaviorTypeBase,
			expectedAllocation: nil,
		},
		{
			name: "LocatorPoolRef changed",
			vrf: &v1alpha1.IsovalentVRF{
				ObjectMeta: metav1.ObjectMeta{
					Name: "vrf0",
				},
				Spec: v1alpha1.IsovalentVRFSpec{
					VRFID:             1,
					ExportRouteTarget: "65000:1",
					LocatorPoolRef:    "pool2",
				},
			},
			existingAllocations: []*sidmanager.SIDInfo{
				{
					Owner:        ownerName,
					MetaData:     "vrf0",
					SID:          srv6Types.MustNewSID(netip.MustParseAddr("fd00:0:0:1::")),
					Structure:    srv6Types.MustNewSIDStructure(32, 16, 16, 0),
					BehaviorType: srv6Types.BehaviorTypeBase,
					Behavior:     srv6Types.BehaviorEndDT4,
				},
			},
			behaviorType:       srv6Types.BehaviorTypeBase,
			expectedAllocation: nil,
		},
		{
			name: "Duplicated allocation",
			vrf: &v1alpha1.IsovalentVRF{
				ObjectMeta: metav1.ObjectMeta{
					Name: "vrf0",
				},
				Spec: v1alpha1.IsovalentVRFSpec{
					VRFID:             1,
					ExportRouteTarget: "65000:1",
					LocatorPoolRef:    "pool1",
				},
			},
			existingAllocations: []*sidmanager.SIDInfo{
				{
					Owner:        ownerName,
					MetaData:     "vrf0",
					SID:          srv6Types.MustNewSID(netip.MustParseAddr("fd00:0:0:1::")),
					Structure:    srv6Types.MustNewSIDStructure(32, 16, 16, 0),
					BehaviorType: srv6Types.BehaviorTypeBase,
					Behavior:     srv6Types.BehaviorEndDT4,
				},
				{
					Owner:        ownerName,
					MetaData:     "vrf0",
					SID:          srv6Types.MustNewSID(netip.MustParseAddr("fd00:0:0:2::")),
					Structure:    srv6Types.MustNewSIDStructure(32, 16, 16, 0),
					BehaviorType: srv6Types.BehaviorTypeBase,
					Behavior:     srv6Types.BehaviorEndDT4,
				},
			},
			behaviorType: srv6Types.BehaviorTypeBase,
			expectedAllocation: &sidmanager.SIDInfo{
				Owner:        ownerName,
				MetaData:     "vrf0",
				SID:          srv6Types.MustNewSID(netip.MustParseAddr("fd00:0:0:1::")),
				Structure:    srv6Types.MustNewSIDStructure(32, 16, 16, 0),
				BehaviorType: srv6Types.BehaviorTypeBase,
				Behavior:     srv6Types.BehaviorEndDT4,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv6map.CreateMaps()
			t.Cleanup(func() {
				srv6map.DeleteMaps()
			})

			var (
				m  *Manager
				cs client.Clientset
			)
			fixture := newFixture(
				t,
				false,
				func(
					manager *Manager,
					fsm *fakeSIDManager,
					clientset client.Clientset,
				) {
					m = manager
					cs = clientset

					fsm.pools["pool1"] = &fakeSIDAllocator{
						behaviorType:  test.behaviorType,
						allocatedSIDs: test.existingAllocations,
					}

					// We need to create resource before Start
					if test.vrf != nil {
						_, err := cs.IsovalentV1alpha1().IsovalentVRFs().Create(context.TODO(), test.vrf.DeepCopy(), metav1.CreateOptions{})
						require.NoError(t, err)
					}
				},
			)

			require.NoError(t, fixture.hive.Start(context.TODO()))
			t.Cleanup(func() {
				fixture.hive.Stop(context.TODO())
			})

			<-fixture.watching

			// Wait for the SIDManager sync
			require.Eventually(t, func() bool {
				return m.sidAllocatorIsSet()
			}, time.Second*3, time.Millisecond*100)

			require.Eventually(t, func() bool {
				vrfs := m.GetAllVRFs()

				if test.vrf != nil {
					if !assert.Len(t, vrfs, 1) {
						return false
					}
				} else {
					return assert.Len(t, vrfs, 0)
				}

				if test.expectedAllocation != nil {
					info := vrfs[0].SIDInfo
					expected := test.expectedAllocation
					return assert.NotNil(t, info) &&
						assert.Equal(t, expected.Owner, info.Owner) &&
						assert.Equal(t, expected.MetaData, info.MetaData) &&
						assert.Equal(t, expected.SID, info.SID) &&
						assert.Equal(t, expected.BehaviorType, info.BehaviorType) &&
						assert.Equal(t, expected.Behavior, info.Behavior)
				} else {
					return assert.Nil(t, vrfs[0].SIDInfo)
				}
			}, time.Second*3, time.Millisecond*100)
		})
	}
}
