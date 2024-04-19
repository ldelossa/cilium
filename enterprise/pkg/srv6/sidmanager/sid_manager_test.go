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
	"maps"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	clientV1Alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/lock"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

type testObserver struct {
	lock.RWMutex
	manager    SIDManager
	synced     chan any
	allocators map[string]SIDAllocator
}

type testObserverIn struct {
	cell.In

	Group          job.Group
	ManagerPromise promise.Promise[SIDManager]
}

func newTestObserver(in testObserverIn) *testObserver {
	o := &testObserver{
		synced:     make(chan any),
		allocators: make(map[string]SIDAllocator),
	}

	in.Group.Add(job.OneShot("observe", func(ctx context.Context, _ cell.Health) error {
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
	locator1   = types.MustNewLocator(netip.MustParsePrefix("fd00:1:1::/48"))
	locator2   = types.MustNewLocator(netip.MustParsePrefix("fd00:2:1::/48"))
	locator3   = types.MustNewLocator(netip.MustParsePrefix("fd00:3:1::/48"))
	locator4   = types.MustNewLocator(netip.MustParsePrefix("fd00:3:1::/48"))
	sid1       = types.MustNewSID(netip.MustParseAddr("fd00:1:1:1::"))

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

func newHive(t *testing.T, invoke ...any) *hive.Hive {
	return hive.New(
		SIDManagerCell,
		// Test module so that newTestObserver gets a job.Group.
		cell.Module("sid-manager-test", "SID Manager test",
			cell.Provide(newTestObserver),
		),
		cell.Provide(
			k8sclient.NewFakeClientset,
			func() *option.DaemonConfig {
				return &option.DaemonConfig{EnableSRv6: true}
			},
		),
		cell.Invoke(invoke...),
	)
}

func eventually(t *testing.T, f func() bool) {
	require.Eventually(t, f, time.Second*3, time.Millisecond*10)
}

func TestSIDManagerSpecReconciliation(t *testing.T) {
	var (
		o *testObserver
		c clientV1Alpha1.IsovalentSRv6SIDManagerInterface
	)

	hive := newHive(t, func(observer *testObserver, clientset k8sclient.Clientset) {
		o = observer
		c = clientset.IsovalentV1alpha1().IsovalentSRv6SIDManagers()
	})

	log := hivetest.Logger(t)
	err := hive.Start(log, context.TODO())
	require.NoError(t, err)
	t.Cleanup(func() {
		hive.Stop(log, context.TODO())
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
				assert.Equal(t, structure1, allocator.Structure(), "Structure mismatched") &&
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
				assert.Equal(t, structure1, allocator.Structure(), "Structure mismatched") &&
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
				assert.Equal(t, structure2, allocator.Structure(), "Structure mismatched") &&
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
				assert.Equal(t, structure2, allocator.Structure(), "Structure mismatched") &&
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
				assert.Equal(t, structure2, allocator1.Structure(), "Structure1 mismatched") &&
				assert.Equal(t, types.BehaviorTypeUSID, allocator1.BehaviorType(), "BehaviorType1 mismatched") &&
				assert.True(t, found2, "Allocator2 not found") &&
				assert.Equal(t, locator2, allocator2.Locator(), "Locator2 mismatched") &&
				assert.Equal(t, structure1, allocator2.Structure(), "Structure2 mismatched") &&
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

func TestSIDManagerStatusReconciliation(t *testing.T) {
	var (
		o *testObserver
		c clientV1Alpha1.IsovalentSRv6SIDManagerInterface
	)

	hive := newHive(t, func(observer *testObserver, clientset k8sclient.Clientset) {
		o = observer
		c = clientset.IsovalentV1alpha1().IsovalentSRv6SIDManagers()
	})

	log := hivetest.Logger(t)
	err := hive.Start(log, context.TODO())
	require.NoError(t, err)
	t.Cleanup(func() {
		hive.Stop(log, context.TODO())
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

			return assert.NotNil(t, sm.Status, "Status is nil") &&
				assert.Len(t, sm.Status.SIDAllocations, 1, "Invalid SIDAllocations length") &&
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
			return assert.NotNil(t, sm.Status, "Status is nil") &&
				assert.Len(t, sm.Status.SIDAllocations, 0, "SIDAllocations still exists")
		})
	})
}

func TestSIDManagerRestoration(t *testing.T) {
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

			log := hivetest.Logger(t)
			err := hive.Start(log, context.TODO())
			require.NoError(t, err)
			t.Cleanup(func() {
				hive.Stop(log, context.TODO())
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
					return assert.NotNil(t, sm.Status, "Status is nil") &&
						assert.Len(t, sm.Status.SIDAllocations, 0,
							"Stale allocation restored to the status")
				})
			}
		})
	}
}
