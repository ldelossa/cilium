//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sidmanager

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/hivetest"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	clientV1Alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/stream"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type fakeSubscriber struct {
	OnAddCount    int
	OnUpdateCount int
	OnDeleteCount int
}

func (f *fakeSubscriber) OnAddLocator(poolName string, allocator SIDAllocator) {
	f.OnAddCount++
}

func (f *fakeSubscriber) OnUpdateLocator(poolName string, oldAllocator, newAllocator SIDAllocator) {
	f.OnUpdateCount++
}

func (f *fakeSubscriber) OnDeleteLocator(poolName string, allocator SIDAllocator) {
	f.OnDeleteCount++
}

func (f *fakeSubscriber) Reset() {
	f.OnAddCount = 0
	f.OnUpdateCount = 0
	f.OnDeleteCount = 0
}

type testObserver struct {
	lock.RWMutex
	manager    SIDManager
	synced     chan any
	allocators map[string]SIDAllocator
}

type testObserverIn struct {
	cell.In

	Lifecycle      cell.Lifecycle
	Scope          cell.Scope
	Registry       job.Registry
	ManagerPromise promise.Promise[SIDManager]
}

func newTestObserver(in testObserverIn) *testObserver {
	o := &testObserver{
		synced:     make(chan any),
		allocators: make(map[string]SIDAllocator),
	}

	group := in.Registry.NewGroup(in.Scope)

	group.Add(job.OneShot("observe", func(ctx context.Context, _ cell.HealthReporter) error {
		manager, err := in.ManagerPromise.Await(ctx)
		if err != nil {
			return err
		}

		o.manager = manager

		for ev := range stream.ToChannel[Event](ctx, manager) {
			switch ev.Kind {
			case Sync:
				close(o.synced)
			case Upsert:
				o.Lock()
				o.allocators[ev.PoolName] = ev.Allocator
				o.Unlock()
			case Delete:
				o.Lock()
				delete(o.allocators, ev.PoolName)
				o.Unlock()
			}
		}
		return nil
	}))

	in.Lifecycle.Append(group)

	return o
}

func (o *testObserver) Allocator(poolName string) (SIDAllocator, bool) {
	o.RLock()
	defer o.RUnlock()
	allocator, ok := o.allocators[poolName]
	return allocator, ok
}

func (o *testObserver) Allocators() map[string]SIDAllocator {
	o.RLock()
	defer o.RUnlock()
	ret := make(map[string]SIDAllocator, len(o.allocators))
	maps.Copy(ret, o.allocators)
	return ret
}

// Fixtures
var (
	poolName1  = "pool1"
	poolName2  = "pool2"
	structure1 = types.MustNewSIDStructure(32, 16, 16, 0)
	structure2 = types.MustNewSIDStructure(32, 16, 24, 0)
	locator1   = types.MustNewLocator(netip.MustParsePrefix("fd00:1:1::/48"), structure1)
	locator2   = types.MustNewLocator(netip.MustParsePrefix("fd00:2:1::/48"), structure1)
	locator3   = types.MustNewLocator(netip.MustParsePrefix("fd00:3:1::/48"), structure1)
	locator4   = types.MustNewLocator(netip.MustParsePrefix("fd00:3:1::/48"), structure2)
	sid1       = types.MustNewSID(netip.MustParseAddr("fd00:1:1:1::"), structure1)

	resourceStructure1 = v1alpha1.IsovalentSRv6SIDStructure{
		LocatorBlockLenBits: structure1.LocatorBlockLenBits(),
		LocatorNodeLenBits:  structure1.LocatorNodeLenBits(),
		FunctionLenBits:     structure1.FunctionLenBits(),
		ArgumentLenBits:     structure1.ArgumentLenBits(),
	}

	resourceStructure2 = v1alpha1.IsovalentSRv6SIDStructure{
		LocatorBlockLenBits: structure2.LocatorBlockLenBits(),
		LocatorNodeLenBits:  structure2.LocatorNodeLenBits(),
		FunctionLenBits:     structure2.FunctionLenBits(),
		ArgumentLenBits:     structure2.ArgumentLenBits(),
	}

	resourceLocator1 = v1alpha1.IsovalentSRv6Locator{
		BehaviorType: "Base",
		Prefix:       locator1.Prefix.String(),
		Structure:    resourceStructure1,
	}

	resourceLocator2 = v1alpha1.IsovalentSRv6Locator{
		BehaviorType: "Base",
		Prefix:       locator2.Prefix.String(),
		Structure:    resourceStructure1,
	}

	resourceLocator3 = v1alpha1.IsovalentSRv6Locator{
		BehaviorType: "Base",
		Prefix:       locator3.Prefix.String(),
		Structure:    resourceStructure1,
	}

	resourceLocator4 = v1alpha1.IsovalentSRv6Locator{
		BehaviorType: "Base",
		Prefix:       locator4.Prefix.String(),
		Structure:    resourceStructure2,
	}

	resourceLocator4uSID = v1alpha1.IsovalentSRv6Locator{
		BehaviorType: "uSID",
		Prefix:       locator4.Prefix.String(),
		Structure:    resourceStructure2,
	}

	resourceLocatorAllocation1 = v1alpha1.IsovalentSRv6LocatorAllocation{
		PoolRef:  poolName1,
		Locators: []*v1alpha1.IsovalentSRv6Locator{&resourceLocator1},
	}

	resourceLocatorAllocation2 = v1alpha1.IsovalentSRv6LocatorAllocation{
		PoolRef:  poolName2,
		Locators: []*v1alpha1.IsovalentSRv6Locator{&resourceLocator2},
	}
)

func TestSIDManager(t *testing.T) {
	smLog.Logger.SetLevel(logrus.DebugLevel)

	createManager := func(t *testing.T, m *v1alpha1.IsovalentSRv6SIDManager) (SIDManager,
		resource.Store[*v1alpha1.IsovalentSRv6SIDManager], k8sclient.Clientset) {
		lc := hivetest.Lifecycle(t)

		fc, cs := k8sclient.NewFakeClientset()

		fc.CiliumFakeClientset.Tracker().Create(
			v1alpha1.SchemeGroupVersion.WithResource("isovalentsrv6sidmanagers"),
			m.DeepCopy(), "",
		)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)

		dc := &option.DaemonConfig{EnableSRv6: true}

		resource := NewLocalIsovalentSRv6SIDManagerResource(dc, lc, cs)

		store, err := resource.Store(ctx)
		require.NoError(t, err)

		sidManagerPromise := NewSIDManagerPromise(sidManagerParams{
			Lc:       lc,
			Cs:       cs,
			Dc:       dc,
			Resource: resource,
		})

		sidManager, err := sidManagerPromise.Await(ctx)
		require.NoError(t, err)

		cancel()

		return sidManager, store, cs
	}

	t.Run("TestSpecReconciliation", func(t *testing.T) {
		manager, _, cs := createManager(t, &v1alpha1.IsovalentSRv6SIDManager{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodetypes.GetName(),
			},
			Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{},
		})

		t.Run("NoLocator", func(t *testing.T) {
			require.Error(t, manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
				require.Fail(t, "ManageSID should fail against the pool doesn't exist")
				return false, nil
			}))
		})

		t.Run("AddOneLocator", func(t *testing.T) {
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: poolName1,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator1.Prefix.String(),
										Structure:    resourceStructure1,
									},
								},
							},
						},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				if err := manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
					return false, nil
				}); err != nil {
					return false
				}
				return true
			}, time.Second*3, time.Millisecond*200, "Spec recociliation didn't happen")
		})

		t.Run("ChangeLocatorPrefix", func(t *testing.T) {
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: poolName1,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator3.Prefix.String(),
										Structure:    resourceStructure1,
									},
								},
							},
						},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				if err := manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
					if allocator.Locator() == locator3 {
						return false, nil
					}
					return false, fmt.Errorf("still seeing an old locator")
				}); err != nil {
					return false
				}
				return true
			}, time.Second*3, time.Millisecond*200, "Spec recociliation didn't happen")
		})

		t.Run("ChangeLocatorStructure", func(t *testing.T) {
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: poolName1,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator4.Prefix.String(),
										Structure:    resourceStructure2,
									},
								},
							},
						},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				if err := manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
					if allocator.Locator() == locator4 {
						return false, nil
					}
					return false, fmt.Errorf("still seeing an old locator")
				}); err != nil {
					return false
				}
				return true
			}, time.Second*3, time.Millisecond*200, "Spec recociliation didn't happen")
		})

		t.Run("ChangeLocatorBehaviorType", func(t *testing.T) {
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: poolName1,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "uSID",
										Prefix:       locator4.Prefix.String(),
										Structure:    resourceStructure2,
									},
								},
							},
						},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				if err := manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
					if allocator.Locator() == locator4 && allocator.BehaviorType() == types.BehaviorTypeUSID {
						return false, nil
					}
					return false, fmt.Errorf("still seeing an old locator")
				}); err != nil {
					return false
				}
				return true
			}, time.Second*3, time.Millisecond*200, "Spec recociliation didn't happen")
		})

		t.Run("AddOneMoreLocators", func(t *testing.T) {
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: poolName1,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator1.Prefix.String(),
										Structure:    resourceStructure1,
									},
								},
							},
							{
								PoolRef: poolName2,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator2.Prefix.String(),
										Structure:    resourceStructure1,
									},
								},
							},
						},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				if err := manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) { return false, nil }); err != nil {
					return false
				}
				if err := manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) { return false, nil }); err != nil {
					return false
				}
				return true
			}, time.Second*3, time.Millisecond*200, "Spec reconciliation didn't happen")
		})

		t.Run("DeleteLocators", func(t *testing.T) {
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				if err := manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) { return false, nil }); err == nil {
					return false
				}
				if err := manager.ManageSID(poolName2, func(allocator SIDAllocator) (bool, error) { return false, nil }); err == nil {
					return false
				}
				return true
			}, time.Second*3, time.Millisecond*200, "Spec reconciliation didn't happen")
		})
	})

	t.Run("TestStatusReconciliation", func(t *testing.T) {
		manager, store, _ := createManager(t, &v1alpha1.IsovalentSRv6SIDManager{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodetypes.GetName(),
			},
			Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
				LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
					{
						PoolRef: poolName1,
						Locators: []*v1alpha1.IsovalentSRv6Locator{
							{
								BehaviorType: "Base",
								Prefix:       locator1.Prefix.String(),
								Structure:    resourceStructure1,
							},
						},
					},
				},
			},
		})

		t.Run("AllocateSIDWithManageSID", func(t *testing.T) {
			var allocatedSID *SIDInfo
			require.NoError(t, manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
				sid, err := allocator.Allocate(netip.MustParseAddr("fd00:1:1:1::"), "test", "test", types.BehaviorEndDT4)
				require.NoError(t, err)
				allocatedSID = sid
				return true, nil
			}))
			require.Eventually(t, func() bool {
				r, exists, err := store.GetByKey(resource.Key{Name: nodetypes.GetName()})
				require.NoError(t, err)
				require.True(t, exists)
				if len(r.Status.SIDAllocations) != 1 {
					return false
				}
				require.Equal(t, poolName1, r.Status.SIDAllocations[0].PoolRef, "Pool name mismatched between status and allocation")
				require.Len(t, r.Status.SIDAllocations[0].SIDs, 1, "More than one SID is on status")
				require.Equal(t, allocatedSID.SID.Addr.String(), r.Status.SIDAllocations[0].SIDs[0].SID.Addr, "SID mismatched between status and allocation")
				return true
			}, time.Second*3, time.Millisecond*200, "Status reconciliation didn't happen")
		})

		t.Run("ReleaseSIDWithManageSID", func(t *testing.T) {
			require.NoError(t, manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
				err := allocator.Release(netip.MustParseAddr("fd00:1:1:1::"))
				require.NoError(t, err)
				return true, nil
			}))
			require.Eventually(t, func() bool {
				r, exists, err := store.GetByKey(resource.Key{Name: nodetypes.GetName()})
				require.NoError(t, err)
				require.True(t, exists)
				return r.Status == nil || len(r.Status.SIDAllocations) == 0
			}, time.Second*3, time.Millisecond*200, "Status reconciliation didn't happen")
		})
	})

	t.Run("TestRestore", func(t *testing.T) {
		t.Run("ValidSID", func(t *testing.T) {
			manager, _, _ := createManager(t, &v1alpha1.IsovalentSRv6SIDManager{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodetypes.GetName(),
				},
				Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
					LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
						{
							PoolRef: poolName1,
							Locators: []*v1alpha1.IsovalentSRv6Locator{
								{
									BehaviorType: "Base",
									Prefix:       locator1.Prefix.String(),
									Structure:    resourceStructure1,
								},
							},
						},
					},
				},
				Status: &v1alpha1.IsovalentSRv6SIDManagerStatus{
					SIDAllocations: []*v1alpha1.IsovalentSRv6SIDAllocation{
						{
							PoolRef: poolName1,
							SIDs: []*v1alpha1.IsovalentSRv6SIDInfo{
								{
									SID: v1alpha1.IsovalentSRv6SID{
										Addr: "fd00:1:1:1::",
										Structure: v1alpha1.IsovalentSRv6SIDStructure{
											LocatorBlockLenBits: 32,
											LocatorNodeLenBits:  16,
											FunctionLenBits:     16,
											ArgumentLenBits:     0,
										},
									},
									Owner:        "test",
									MetaData:     "test1",
									BehaviorType: "Base",
									Behavior:     "End.DT4",
								},
							},
						},
					},
				},
			})
			manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
				sids := allocator.AllocatedSIDs("test")
				require.Len(t, sids, 1)
				require.Equal(t, netip.MustParseAddr("fd00:1:1:1::"), sids[0].SID.Addr, "Restored allocation doesn't match to status")
				require.Equal(t, "test", sids[0].Owner, "Restored owner doesn't match to status")
				require.Equal(t, "test1", sids[0].MetaData, "Restored metadata doesn't match to status")
				require.Equal(t, types.BehaviorEndDT4, sids[0].Behavior, "Restored Behavior doesn't match to status")
				return false, nil
			})
		})

		t.Run("StaleSIDStructureMismatch", func(t *testing.T) {
			manager, store, _ := createManager(t, &v1alpha1.IsovalentSRv6SIDManager{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodetypes.GetName(),
				},
				Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
					LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
						{
							PoolRef: poolName1,
							Locators: []*v1alpha1.IsovalentSRv6Locator{
								{
									BehaviorType: "Base",
									Prefix:       locator1.Prefix.String(),
									Structure:    resourceStructure1,
								},
							},
						},
					},
				},
				Status: &v1alpha1.IsovalentSRv6SIDManagerStatus{
					SIDAllocations: []*v1alpha1.IsovalentSRv6SIDAllocation{
						{
							PoolRef: poolName1,
							SIDs: []*v1alpha1.IsovalentSRv6SIDInfo{
								{
									SID: v1alpha1.IsovalentSRv6SID{
										Addr: "fd00:1:1:1::",
										Structure: v1alpha1.IsovalentSRv6SIDStructure{
											LocatorBlockLenBits: 32,
											LocatorNodeLenBits:  16,
											FunctionLenBits:     24,
											ArgumentLenBits:     0,
										},
									},
									Owner:        "test",
									MetaData:     "test1",
									BehaviorType: "Base",
									Behavior:     "End.DT4",
								},
							},
						},
					},
				},
			})
			manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
				sids := allocator.AllocatedSIDs("test")
				require.Len(t, sids, 0, "Stale allocation restored to the allocator")
				return false, nil
			})
			require.Eventually(t, func() bool {
				r, exists, err := store.GetByKey(resource.Key{Name: nodetypes.GetName()})
				require.NoError(t, err)
				require.True(t, exists)
				if r.Status == nil {
					return false
				}
				return len(r.Status.SIDAllocations) == 0
			}, time.Second*3, time.Millisecond*200, "Stale allocation restored to the status")
		})

		t.Run("StaleSIDBehaviorTypeMismatch", func(t *testing.T) {
			manager, store, _ := createManager(t, &v1alpha1.IsovalentSRv6SIDManager{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodetypes.GetName(),
				},
				Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
					LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
						{
							PoolRef: poolName1,
							Locators: []*v1alpha1.IsovalentSRv6Locator{
								{
									BehaviorType: "Base",
									Prefix:       locator1.Prefix.String(),
									Structure:    resourceStructure1,
								},
							},
						},
					},
				},
				Status: &v1alpha1.IsovalentSRv6SIDManagerStatus{
					SIDAllocations: []*v1alpha1.IsovalentSRv6SIDAllocation{
						{
							PoolRef: poolName1,
							SIDs: []*v1alpha1.IsovalentSRv6SIDInfo{
								{
									SID: v1alpha1.IsovalentSRv6SID{
										Addr: "fd00:1:1:1::",
										Structure: v1alpha1.IsovalentSRv6SIDStructure{
											LocatorBlockLenBits: 32,
											LocatorNodeLenBits:  16,
											FunctionLenBits:     16,
											ArgumentLenBits:     0,
										},
									},
									Owner:        "test",
									MetaData:     "test1",
									BehaviorType: "uSID",
									Behavior:     "uDT4",
								},
							},
						},
					},
				},
			})
			manager.ManageSID(poolName1, func(allocator SIDAllocator) (bool, error) {
				sids := allocator.AllocatedSIDs("test")
				require.Len(t, sids, 0, "Stale allocation restored to the allocator")
				return false, nil
			})
			require.Eventually(t, func() bool {
				r, exists, err := store.GetByKey(resource.Key{Name: nodetypes.GetName()})
				require.NoError(t, err)
				require.True(t, exists)
				if r.Status == nil {
					return false
				}
				return len(r.Status.SIDAllocations) == 0
			}, time.Second*3, time.Millisecond*200, "Stale allocation restored to the status")
		})
	})

	t.Run("TestSubscription", func(t *testing.T) {
		manager, _, cs := createManager(t, &v1alpha1.IsovalentSRv6SIDManager{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodetypes.GetName(),
			},
			Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
				LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
					{
						PoolRef: poolName1,
						Locators: []*v1alpha1.IsovalentSRv6Locator{
							{
								BehaviorType: "Base",
								Prefix:       locator1.Prefix.String(),
								Structure:    resourceStructure1,
							},
						},
					},
				},
			},
		})

		subscriber := fakeSubscriber{}
		manager.Subscribe("fakeSubscriber", &subscriber, func() {})

		t.Run("InitialAdd", func(t *testing.T) {
			defer subscriber.Reset()
			require.Equal(t, 1, subscriber.OnAddCount, "Subscribe didn't call initial OnAddLocator")
		})

		t.Run("OnAddLocator", func(t *testing.T) {
			defer subscriber.Reset()
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: poolName1,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator1.Prefix.String(),
										Structure:    resourceStructure1,
									},
								},
							},
							{
								PoolRef: poolName2,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator2.Prefix.String(),
										Structure:    resourceStructure1,
									},
								},
							},
						},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				return subscriber.OnAddCount == 1
			}, time.Second*3, time.Millisecond*200, "OnAddLocator didn't happen")
		})

		t.Run("OnUpdateLocator", func(t *testing.T) {
			defer subscriber.Reset()
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
							{
								PoolRef: poolName1,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator1.Prefix.String(),
										Structure:    resourceStructure1,
									},
								},
							},
							{
								PoolRef: poolName2,
								Locators: []*v1alpha1.IsovalentSRv6Locator{
									{
										BehaviorType: "Base",
										Prefix:       locator2.Prefix.String(),
										Structure:    resourceStructure2,
									},
								},
							},
						},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				return subscriber.OnUpdateCount == 1
			}, time.Second*3, time.Millisecond*200, "OnUpdateLocator didn't happen")
		})

		t.Run("OnDeleteLocator", func(t *testing.T) {
			defer subscriber.Reset()
			_, err := cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Update(
				context.TODO(),
				&v1alpha1.IsovalentSRv6SIDManager{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodetypes.GetName(),
					},
					Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
						LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{},
					},
				},
				metav1.UpdateOptions{},
			)
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				return subscriber.OnDeleteCount == 2
			}, time.Second*3, time.Millisecond*200, "OnDeleteLocator didn't happen twice")
		})
	})
}

func newHive(t *testing.T, invoke ...any) *hive.Hive {
	return hive.New(
		job.Cell,
		SIDManagerCell,
		cell.Provide(
			cell.TestScope,
			newTestObserver,
			k8sclient.NewFakeClientset,
			func() *option.DaemonConfig {
				return &option.DaemonConfig{EnableSRv6: true}
			},
		),
		cell.Invoke(invoke...),
	)
}

func eventually(t *testing.T, f func() bool) {
	require.Eventually(t, f, time.Second*3, time.Millisecond*200)
}

func TestSIDManagerSpecReconciliationWithObserver(t *testing.T) {
	var (
		o *testObserver
		c clientV1Alpha1.IsovalentSRv6SIDManagerInterface
	)

	hive := newHive(t, func(observer *testObserver, clientset k8sclient.Clientset) {
		o = observer
		c = clientset.IsovalentV1alpha1().IsovalentSRv6SIDManagers()
	})

	err := hive.Start(context.TODO())
	require.NoError(t, err)
	t.Cleanup(func() {
		hive.Stop(context.TODO())
	})

	sidmanager := v1alpha1.IsovalentSRv6SIDManager{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodetypes.GetName(),
		},
		Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
			LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{resourceLocatorAllocation1.DeepCopy()},
		},
	}

	_, err = c.Create(context.TODO(), &sidmanager, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Run("AddOneLocator", func(t *testing.T) {
		eventually(t, func() bool {
			allocator, found := o.Allocator(sidmanager.Spec.LocatorAllocations[0].PoolRef)
			return assert.True(t, found, "Allocator not found") &&
				assert.Equal(t, locator1, allocator.Locator(), "Locator mismatched") &&
				assert.Equal(t, types.BehaviorTypeBase, allocator.BehaviorType(), "BehaviorType mismatched")
		})
	})

	t.Run("ChangeLocatorPrefix", func(t *testing.T) {
		sidmanager.Spec.LocatorAllocations[0].Locators[0] = resourceLocator3.DeepCopy()

		_, err := c.Update(context.TODO(), &sidmanager, metav1.UpdateOptions{})
		require.NoError(t, err)

		eventually(t, func() bool {
			allocator, found := o.Allocator(sidmanager.Spec.LocatorAllocations[0].PoolRef)
			return assert.True(t, found, "Allocator not found") &&
				assert.Equal(t, locator3, allocator.Locator(), "Locator mismatched") &&
				assert.Equal(t, types.BehaviorTypeBase, allocator.BehaviorType(), "BehaviorType mismatched")
		})
	})

	t.Run("ChangeLocatorStructure", func(t *testing.T) {
		sidmanager.Spec.LocatorAllocations[0].Locators[0] = resourceLocator4.DeepCopy()

		_, err := c.Update(context.TODO(), &sidmanager, metav1.UpdateOptions{})
		require.NoError(t, err)

		eventually(t, func() bool {
			allocator, found := o.Allocator(sidmanager.Spec.LocatorAllocations[0].PoolRef)
			return assert.True(t, found, "Allocator not found") &&
				assert.Equal(t, locator4, allocator.Locator(), "Locator mismatched") &&
				assert.Equal(t, types.BehaviorTypeBase, allocator.BehaviorType(), "BehaviorType mismatched")
		})
	})

	t.Run("ChangeLocatorBehaviorType", func(t *testing.T) {
		sidmanager.Spec.LocatorAllocations[0].Locators[0] = resourceLocator4uSID.DeepCopy()

		_, err := c.Update(context.TODO(), &sidmanager, metav1.UpdateOptions{})
		require.NoError(t, err)

		eventually(t, func() bool {
			allocator, found := o.Allocator(sidmanager.Spec.LocatorAllocations[0].PoolRef)
			return assert.True(t, found, "Allocator not found") &&
				assert.Equal(t, locator4, allocator.Locator(), "Locator mismatched") &&
				assert.Equal(t, types.BehaviorTypeUSID, allocator.BehaviorType(), "BehaviorType mismatched")
		})
	})

	t.Run("AddOneMoreLocator", func(t *testing.T) {
		sidmanager.Spec.LocatorAllocations = append(sidmanager.Spec.LocatorAllocations, resourceLocatorAllocation2.DeepCopy())

		_, err := c.Update(context.TODO(), &sidmanager, metav1.UpdateOptions{})
		require.NoError(t, err)

		eventually(t, func() bool {
			allocator1, found1 := o.Allocator(sidmanager.Spec.LocatorAllocations[0].PoolRef)
			allocator2, found2 := o.Allocator(sidmanager.Spec.LocatorAllocations[1].PoolRef)
			return assert.True(t, found1, "Allocator1 not found") &&
				assert.Equal(t, locator4, allocator1.Locator(), "Locator1 mismatched") &&
				assert.Equal(t, types.BehaviorTypeUSID, allocator1.BehaviorType(), "BehaviorType1 mismatched") &&
				assert.True(t, found2, "Allocator2 not found") &&
				assert.Equal(t, locator2, allocator2.Locator(), "Locator2 mismatched") &&
				assert.Equal(t, types.BehaviorTypeBase, allocator2.BehaviorType(), "BehaviorType2 mismatched")
		})
	})

	t.Run("DeleteLocators", func(t *testing.T) {
		oldRef1 := sidmanager.Spec.LocatorAllocations[0].PoolRef
		oldRef2 := sidmanager.Spec.LocatorAllocations[1].PoolRef
		sidmanager.Spec.LocatorAllocations = []*v1alpha1.IsovalentSRv6LocatorAllocation{}

		_, err := c.Update(context.TODO(), &sidmanager, metav1.UpdateOptions{})
		require.NoError(t, err)

		eventually(t, func() bool {
			_, found1 := o.Allocator(oldRef1)
			_, found2 := o.Allocator(oldRef2)
			return assert.False(t, found1, "Allocator1 still exists") &&
				assert.False(t, found2, "Allocator2 still exists")
		})
	})
}

func TestSIDManagerStatusReconciliationWithObserver(t *testing.T) {
	var (
		o *testObserver
		c clientV1Alpha1.IsovalentSRv6SIDManagerInterface
	)

	hive := newHive(t, func(observer *testObserver, clientset k8sclient.Clientset) {
		o = observer
		c = clientset.IsovalentV1alpha1().IsovalentSRv6SIDManagers()
	})

	err := hive.Start(context.TODO())
	require.NoError(t, err)
	t.Cleanup(func() {
		hive.Stop(context.TODO())
	})

	nodeName := nodetypes.GetName()

	sidmanager := v1alpha1.IsovalentSRv6SIDManager{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
		Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
			LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{resourceLocatorAllocation1.DeepCopy()},
		},
	}

	_, err = c.Create(context.TODO(), &sidmanager, metav1.CreateOptions{})
	require.NoError(t, err)

	t.Run("AllocateSID", func(t *testing.T) {
		var allocator SIDAllocator

		eventually(t, func() bool {
			a, found := o.Allocator(poolName1)
			allocator = a
			return assert.True(t, found, "Allocator not found")
		})

		sidInfo, err := allocator.Allocate(sid1.Addr, "test", "test1", types.BehaviorEndDT4)
		require.NoError(t, err)

		eventually(t, func() bool {
			sm, err := c.Get(context.TODO(), sidmanager.Name, metav1.GetOptions{})
			require.NoError(t, err)

			return assert.Len(t, sm.Status.SIDAllocations, 1, "Invalid SIDAllocations length") &&
				assert.Equal(t, poolName1, sm.Status.SIDAllocations[0].PoolRef,
					"Pool name mismatched between status and allocation") &&
				assert.Len(t, sm.Status.SIDAllocations[0].SIDs, 1,
					"More than one SID is on status") &&
				assert.Equal(t, sidInfo.SID.Addr.String(), sm.Status.SIDAllocations[0].SIDs[0].SID.Addr,
					"SID mismatched between status and allocation")
		})
	})

	t.Run("ReleaseSID", func(t *testing.T) {
		allocator, found := o.Allocator(poolName1)
		require.True(t, found, "Allocator not found")

		err := allocator.Release(sid1.Addr)
		require.NoError(t, err)

		eventually(t, func() bool {
			sm, err := c.Get(context.TODO(), sidmanager.Name, metav1.GetOptions{})
			require.NoError(t, err)
			return assert.Len(t, sm.Status.SIDAllocations, 0, "SIDAllocations still exists")
		})
	})
}

func TestSIDManagerRestorationWithObserver(t *testing.T) {
	tests := []struct {
		name  string
		sid   *v1alpha1.IsovalentSRv6SIDInfo
		stale bool
	}{
		{
			name: "ValidSID",
			sid: &v1alpha1.IsovalentSRv6SIDInfo{
				SID: v1alpha1.IsovalentSRv6SID{
					Addr: sid1.Addr.String(),
					Structure: v1alpha1.IsovalentSRv6SIDStructure{
						LocatorBlockLenBits: 32,
						LocatorNodeLenBits:  16,
						FunctionLenBits:     16,
						ArgumentLenBits:     0,
					},
				},
				Owner:        "test",
				MetaData:     "test1",
				BehaviorType: "Base",
				Behavior:     "End.DT4",
			},
		},
		{
			name: "StaleSIDStructureMismatch",
			sid: &v1alpha1.IsovalentSRv6SIDInfo{
				SID: v1alpha1.IsovalentSRv6SID{
					Addr: sid1.Addr.String(),
					Structure: v1alpha1.IsovalentSRv6SIDStructure{
						LocatorBlockLenBits: 32,
						LocatorNodeLenBits:  16,
						FunctionLenBits:     24,
						ArgumentLenBits:     0,
					},
				},
				Owner:        "test",
				MetaData:     "test1",
				BehaviorType: "Base",
				Behavior:     "End.DT4",
			},
			stale: true,
		},
		{
			name: "StaleSIDBehaviorTypeMismatch",
			sid: &v1alpha1.IsovalentSRv6SIDInfo{
				SID: v1alpha1.IsovalentSRv6SID{
					Addr: sid1.Addr.String(),
					Structure: v1alpha1.IsovalentSRv6SIDStructure{
						LocatorBlockLenBits: 32,
						LocatorNodeLenBits:  16,
						FunctionLenBits:     16,
						ArgumentLenBits:     0,
					},
				},
				Owner:        "test",
				MetaData:     "test1",
				BehaviorType: "uSID",
				Behavior:     "uDT4",
			},
			stale: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var (
				o *testObserver
				c clientV1Alpha1.IsovalentSRv6SIDManagerInterface
			)

			hive := newHive(t, func(observer *testObserver, clientset k8sclient.Clientset) {
				o = observer
				c = clientset.IsovalentV1alpha1().IsovalentSRv6SIDManagers()
			})

			err := hive.Start(context.TODO())
			require.NoError(t, err)
			t.Cleanup(func() {
				hive.Stop(context.TODO())
			})

			sidmanager := &v1alpha1.IsovalentSRv6SIDManager{
				ObjectMeta: metav1.ObjectMeta{
					Name: nodetypes.GetName(),
				},
				Spec: v1alpha1.IsovalentSRv6SIDManagerSpec{
					LocatorAllocations: []*v1alpha1.IsovalentSRv6LocatorAllocation{
						resourceLocatorAllocation1.DeepCopy(),
					},
				},
				Status: &v1alpha1.IsovalentSRv6SIDManagerStatus{
					SIDAllocations: []*v1alpha1.IsovalentSRv6SIDAllocation{
						{
							PoolRef: poolName1,
							SIDs:    []*v1alpha1.IsovalentSRv6SIDInfo{test.sid},
						},
					},
				},
			}

			_, err = c.Create(context.TODO(), sidmanager, metav1.CreateOptions{})
			require.NoError(t, err)
			t.Cleanup(func() {
				err := c.Delete(context.TODO(), sidmanager.Name, metav1.DeleteOptions{})
				require.NoError(t, err)
				eventually(t, func() bool {
					return assert.Len(t, o.Allocators(), 0, "Allocators still exist")
				})
			})

			if !test.stale {
				// Valid allocation should be restored to the allocator
				var allocator SIDAllocator
				eventually(t, func() bool {
					a, found := o.Allocator(poolName1)
					allocator = a
					return assert.True(t, found, "Allocator not found")
				})
				sids := allocator.AllocatedSIDs("test")
				require.Len(t, sids, 1,
					"No SID restored to the allocator")
				require.Equal(t, sid1.Addr, sids[0].SID.Addr,
					"Restored allocation doesn't match to status")
				require.Equal(t, "test", sids[0].Owner,
					"Restored owner doesn't match to status")
				require.Equal(t, "test1", sids[0].MetaData,
					"Restored metadata doesn't match to status")
				require.Equal(t, types.BehaviorEndDT4, sids[0].Behavior,
					"Restored Behavior doesn't match to status")
			} else {
				// Stale allocation shouldn't be restored to the status
				eventually(t, func() bool {
					sm, err := c.Get(context.TODO(), sidmanager.Name, metav1.GetOptions{})
					require.NoError(t, err)
					return assert.Len(t, sm.Status.SIDAllocations, 0,
						"Stale allocation restored to the status")
				})
			}
		})
	}
}
