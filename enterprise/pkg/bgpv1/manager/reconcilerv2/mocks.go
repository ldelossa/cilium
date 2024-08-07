// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"net/netip"

	"golang.org/x/exp/maps"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	srv6 "github.com/cilium/cilium/enterprise/pkg/srv6/srv6manager"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/lock"
)

type mockEGWPolicy struct {
	id        k8stypes.NamespacedName
	labels    map[string]string
	egressIPs []netip.Addr
}

func newEGWManagerMock(d []mockEGWPolicy) egwIPsProvider {
	return &egwManagerMock{
		data: d,
	}
}

// egwManagerMock is a mock implementation of egwIPsProvider ( EGWManager ). This is
// used to provide the egress IPs for the tests.
type egwManagerMock struct {
	data []mockEGWPolicy
}

func (e *egwManagerMock) AdvertisedEgressIPs(policySelector *slimv1.LabelSelector) (map[k8stypes.NamespacedName][]netip.Addr, error) {
	selector, err := slimv1.LabelSelectorAsSelector(policySelector)
	if err != nil {
		return nil, err
	}

	result := make(map[k8stypes.NamespacedName][]netip.Addr)
	for _, policy := range e.data {
		if selector.Matches(k8sLabels.Set(policy.labels)) {
			result[policy.id] = policy.egressIPs
		}
	}

	return result, nil
}

// upgraderMock is a mock implementation of paramUpgrader. This is used to provide the IsovalentBGPNodeInstance
// configuration for the tests.
type upgraderMock struct {
	bgpNodeInstance *v1alpha1.IsovalentBGPNodeInstance
}

func newUpgraderMock(n *v1alpha1.IsovalentBGPNodeInstance) paramUpgrader {
	return &upgraderMock{
		bgpNodeInstance: n,
	}
}

func (u *upgraderMock) upgrade(params reconcilerv2.ReconcileParams) (EnterpriseReconcileParams, error) {
	return EnterpriseReconcileParams{
		BGPInstance: &EnterpriseBGPInstance{
			Router:   params.BGPInstance.Router,
			Metadata: params.BGPInstance.Metadata,
		},
		DesiredConfig: u.bgpNodeInstance, // put provided isovalentBGPNodeInstance into the desired config
		CiliumNode:    params.CiliumNode,
	}, nil
}

func (u *upgraderMock) upgradeState(params reconcilerv2.StateReconcileParams) (EnterpriseStateReconcileParams, error) {
	return EnterpriseStateReconcileParams{
		DesiredConfig: u.bgpNodeInstance, // put provided isovalentBGPNodeInstance into the desired config
		UpdatedInstance: &EnterpriseBGPInstance{
			Router:   params.UpdatedInstance.Router,
			Metadata: params.UpdatedInstance.Metadata,
		},
	}, nil
}

var _ resource.Store[runtime.Object] = (*mockResourceStore[runtime.Object])(nil)

// mockResourceStore is a mock implementation of resource.Store used for testing.
type mockResourceStore[T runtime.Object] struct {
	objMu   lock.Mutex
	objects map[resource.Key]T
}

func newMockResourceStore[T runtime.Object]() *mockResourceStore[T] {
	return &mockResourceStore[T]{
		objects: make(map[resource.Key]T),
	}
}

func (mds *mockResourceStore[T]) List() []T {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()
	return maps.Values(mds.objects)
}

func (mds *mockResourceStore[T]) IterKeys() resource.KeyIter {
	return nil
}

func (mds *mockResourceStore[T]) Get(obj T) (item T, exists bool, err error) {
	return mds.GetByKey(resource.NewKey(obj))
}

func (mds *mockResourceStore[T]) GetByKey(key resource.Key) (item T, exists bool, err error) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()

	item, exists = mds.objects[key]

	return item, exists, nil
}

func (mds *mockResourceStore[T]) IndexKeys(indexName, indexedValue string) ([]string, error) {
	return nil, nil
}

func (mds *mockResourceStore[T]) ByIndex(indexName, indexedValue string) ([]T, error) {
	return nil, nil
}

func (mds *mockResourceStore[T]) CacheStore() cache.Store {
	return nil
}

func (mds *mockResourceStore[T]) Release() {}

func (mds *mockResourceStore[T]) Upsert(obj T) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()

	key := resource.NewKey(obj)
	mds.objects[key] = obj
}

func (mds *mockResourceStore[T]) Delete(key resource.Key) {
	mds.objMu.Lock()
	defer mds.objMu.Unlock()

	delete(mds.objects, key)
}

func InitMockStore[T runtime.Object](objects []T) resource.Store[T] {
	store := newMockResourceStore[T]()
	for _, obj := range objects {
		store.Upsert(obj)
	}
	return store
}

type mockSRv6Manager struct {
	lock.Mutex
	preinstalledVRFs map[k8stypes.NamespacedName]*srv6.VRF
}

func newMockSRv6Manager(vrfs map[k8stypes.NamespacedName]*srv6.VRF) *mockSRv6Manager {
	return &mockSRv6Manager{
		preinstalledVRFs: vrfs,
	}
}

func (m *mockSRv6Manager) GetVRFByName(vrfName k8stypes.NamespacedName) (*srv6.VRF, bool) {
	m.Lock()
	defer m.Unlock()

	vrf, exists := m.preinstalledVRFs[vrfName]
	if !exists {
		return nil, false
	}

	return vrf.DeepCopy(), true
}

func (m *mockSRv6Manager) GetEgressPolicies() []*srv6.EgressPolicy {
	return nil
}

func (m *mockSRv6Manager) upsertVRF(key k8stypes.NamespacedName, vrf *srv6.VRF) {
	m.Lock()
	defer m.Unlock()

	m.preinstalledVRFs[key] = vrf
}
