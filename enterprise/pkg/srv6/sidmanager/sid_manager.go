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
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"

	"github.com/cilium/stream"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	k8sTypes "k8s.io/apimachinery/pkg/types"
)

// SID Manager is a central point of managing SRv6 SIDs. It is backed by
// per-node k8s resource that provides locators for the node as a spec and
// holds SID allocation state as a status. The locators will be allocated from
// the high-level "pool" of locators and usually, the Cilium Operator is
// responsible for allocating locators for each nodes.
//
// Internally, it manages SIDAllocator per-locator (can be a pool of locator
// prefixes) and other SRv6-related subsystems can manage SIDs with the name of
// the pool that the locator is allocated from. When the allocation state is
// changed, SID Manager takes care of reflecting the state to the k8s resource.

var (
	SRv6SIDManagerSubsys = "srv6-sid-manager"

	smLog = logging.DefaultLogger.WithField(logfields.LogSubsys, SRv6SIDManagerSubsys)
)

// SIDManager is an interface to interact with SID Manager subsystem
type SIDManager interface {
	// Implements Observable interface. This allows the external modules to
	// subscribe to the events of the create/update/delete of the locator
	// allocations. For each Upsert event, the observer gets a new
	// SIDAllocator associated with the pool. The observer should keep the
	// reference to the allocator and update it when the new Upsert event
	// is received. When the Delete event is received, the observer should
	// release the SIDAllocator and associated states.
	stream.Observable[Event]
}

type EventKind int

const (
	// A locator pool is created or updated. The PoolName is the name of
	// the created/updated pool and Allocator is the SIDAllocator
	// associated with the pool. For the initial sync, the Allocator may
	// have existing allocations from the previous agent run. The observer
	// is responsible for handling this and restore the previous running
	// state.
	Upsert EventKind = iota + 1
	// A locator pool is deleted. The PoolName is the name of the deleted
	// pool and Allocator is unset. The observer should release all
	// allocations associated with the pool.
	Delete
	// An initial series of Upsert events done. This is useful to perform
	// initial sync after the agent restart.
	Sync
)

type Event struct {
	// Kind of the event
	Kind EventKind
	// The name of the pool
	PoolName string
	// The SIDAllocator associated with the pool. This is shared with other
	// goroutines. The interface methods takes care of locking, but the
	// caller should set an unique owner string for each allocation to
	// avoid interference with others.
	Allocator SIDAllocator
}

type sidManager struct {
	// PoolName => sidAllocatorSyncer mapping. We currently assume only one
	// locator allocated from one pool.
	allocators map[string]*sidAllocatorSyncer

	// Lock to protect allocators
	allocatorsLock lock.RWMutex

	// Resource[T] of backing k8s resource
	resource LocalIsovalentSRv6SIDManagerResource

	// Clientset is a k8s clientset
	clientset client.Clientset

	// Channel that schedules k8s state synchronization. There's only 1
	// buffer and the write should be non-blocking.
	stateSyncCh chan struct{}

	// Resolver for the Promise for waiting an initial sync
	resolver promise.Resolver[SIDManager]

	// WaitGroup to wait for all goroutine's termination
	wg sync.WaitGroup

	// Function to cancel context shared with all goroutines
	cancel context.CancelFunc

	// Multicast
	mcast     stream.Observable[Event]
	next      func(Event)
	completed func(error)
}

type sidManagerParams struct {
	cell.In

	Lc       cell.Lifecycle
	Cs       client.Clientset
	Dc       *option.DaemonConfig
	Resource LocalIsovalentSRv6SIDManagerResource
}

type sidAllocatorSyncer struct {
	SIDAllocator
	shutdown atomic.Bool
	syncFn   func()
}

func (a *sidAllocatorSyncer) sync() {
	if !a.shutdown.Load() {
		a.syncFn()
	}
}

func (a *sidAllocatorSyncer) Allocate(sid netip.Addr, owner string, metadata string, behavior types.Behavior) (*SIDInfo, error) {
	sidInfo, err := a.SIDAllocator.Allocate(sid, owner, metadata, behavior)
	if err != nil {
		return nil, err
	}
	a.sync()
	return sidInfo, nil
}

func (a *sidAllocatorSyncer) AllocateNext(owner string, metadata string, behavior types.Behavior) (*SIDInfo, error) {
	sidInfo, err := a.SIDAllocator.AllocateNext(owner, metadata, behavior)
	if err != nil {
		return nil, err
	}
	a.sync()
	return sidInfo, nil
}

func (a *sidAllocatorSyncer) Release(sid netip.Addr) error {
	err := a.SIDAllocator.Release(sid)
	if err != nil {
		return err
	}
	a.sync()
	return nil
}

// Shutdown invalidates the notifier. After calling this method, Notify
// becomes a no-op.
func (a *sidAllocatorSyncer) Shutdown() {
	a.shutdown.Store(true)
}

// NewSIDManagerPromise creates a new SID manager and returns its promise. The
// promise will be resolved once the backing SIDManager resource is fetched and
// all initial allocator creation is done.
func NewSIDManagerPromise(params sidManagerParams) promise.Promise[SIDManager] {
	if !params.Dc.EnableSRv6 {
		return nil
	}

	resolver, promise := promise.New[SIDManager]()

	m := &sidManager{
		allocators:  make(map[string]*sidAllocatorSyncer),
		resource:    params.Resource,
		clientset:   params.Cs,
		stateSyncCh: make(chan struct{}, 1),
		resolver:    resolver,
	}
	m.mcast, m.next, m.completed = stream.Multicast[Event]()

	params.Lc.Append(m)

	return promise
}

func (m *sidManager) Observe(ctx context.Context, next func(Event), complete func(error)) {
	go func() {
		m.allocatorsLock.RLock()
		defer m.allocatorsLock.RUnlock()

		// Replay all existing allocators first
		for poolName, allocator := range m.allocators {
			next(Event{
				Kind:      Upsert,
				PoolName:  poolName,
				Allocator: allocator,
			})
		}

		// Initial sync done
		next(Event{Kind: Sync})

		// Then subscribe to the multicast
		m.mcast.Observe(ctx, next, complete)
	}()
}

func (m *sidManager) Start(hookCtx cell.HookContext) error {
	smLog.Info("Starting SRv6 SID Manager")

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	m.wg.Add(2)

	// This goroutine is responsible for watching SIDManager resource on
	// k8s and create SIDAllocator per locator allocations.
	go m.runSpecReconciler(ctx)

	// This goroutine is responsible for synchronizing a SID allocation
	// state to k8s resource.
	go m.runStatusReconciler(ctx)

	return nil
}

func (m *sidManager) Stop(hookCtx cell.HookContext) error {
	smLog.Info("Stopping SRv6 SID Manager")

	// This should make all goroutines cancel and yield
	m.cancel()

	// Wait for all goroutines to terminate
	ch := make(chan struct{})
	go func() {
		m.wg.Wait()
		ch <- struct{}{}
	}()

	select {
	case <-hookCtx.Done():
		return fmt.Errorf("stop timeout expired while waiting for goroutines to terminate")
	case <-ch:
		// All goroutines terminated. Go to the next stage.
		smLog.Info("All goroutines are shutdown")
	}

	// If there's an outstanding sync, try its best to do sync before shutdown
	select {
	case <-m.stateSyncCh:
		smLog.Info("Performing the last state sync before shutdown")
		_ = m.reconcileStatus(hookCtx)
	default:
	}

	return nil
}

func (m *sidManager) runSpecReconciler(ctx context.Context) {
	smLog.Info("Starting SID Manager spec reconciler")

	defer m.wg.Done()

	restorationDone := false
	for ev := range m.resource.Events(ctx) {
		switch ev.Kind {
		case resource.Sync:
			// At this point, we're ready for accepting ManageSID
			// or Subscribe call.
			m.resolver.Resolve(m)
			restorationDone = true
		case resource.Delete:
			smLog.Info("IsovalentSRv6SIDManager resource deleted")
			// Resource deleted. This shouldn't happen in practice
			// because SIDManager resource is per-node and its
			// lifecycle is aligned with the one of Node and most
			// of the time, the agent's lifecycle is aligned with
			// the node as well. So, this handler shouldn't be
			// called. The possible cases are the buggy operator or
			// the user manually deletes the resource.
			m.deleteAllAllocators(ev.Object)
		case resource.Upsert:
			// This reconciliation creates SID allocators from the
			// locator allocations on the spec. After this
			// function, state of the m.allocators is fully synced
			// with the spec on the k8s resource.
			needsSync, err := m.reconcileSpec(ev.Object)
			if err != nil {
				ev.Done(err)
				continue
			}

			if !restorationDone {
				// On the initial upsert after agent restart, we may
				// have existing allocations on k8s resource status.
				// Before schedule the initial state sync, try to
				// allocate existing SIDs from SID allocators, so that
				// we can retain same SIDs over agent restart.
				m.restoreAllocations(ctx, ev.Object)
				restorationDone = true
				needsSync = true
			}

			if needsSync {
				m.Sync()
			}
		}
		ev.Done(nil)
	}

	smLog.Info("Stopping SID Manager spec reconciler")
}

// This function synchronizes internal poolName => allocator mappings to spec on the k8s resource
func (m *sidManager) reconcileSpec(r *v1alpha1.IsovalentSRv6SIDManager) (bool, error) {
	var needsSync bool

	m.allocatorsLock.Lock()
	defer m.allocatorsLock.Unlock()

	pools := make(map[string]struct{})
	for _, la := range r.Spec.LocatorAllocations {
		// Keep the name of the pools on the spec on the map so that we
		// can search the name in O(1) in the later deletion handling.
		pools[la.PoolRef] = struct{}{}

		if len(la.Locators) != 1 {
			return false, fmt.Errorf("multiple locator from same pool is not supported yet")
		}

		locator := la.Locators[0]

		l, err := m.locatorFromResource(locator)
		if err != nil {
			return false, fmt.Errorf("failed to create locator: %w", err)
		}

		structure, err := m.structureFromResource(locator.Structure)
		if err != nil {
			return false, fmt.Errorf("failed to create SID structure: %w", err)
		}

		behaviorType := types.BehaviorTypeFromString(locator.BehaviorType)

		if oldAllocatorSyncer, ok := m.allocators[la.PoolRef]; !ok {
			newAllocator, err := NewStructuredSIDAllocator(l, structure, behaviorType)
			if err != nil {
				return false, fmt.Errorf("failed to create new SID allocator: %w", err)
			}
			newAllocatorSyncer := &sidAllocatorSyncer{
				SIDAllocator: newAllocator,
				syncFn:       m.Sync,
			}
			m.onAddLocator(la.PoolRef, newAllocatorSyncer)
			needsSync = true
		} else {
			// No change to the spec, skip update
			if oldAllocatorSyncer.Locator() == l &&
				oldAllocatorSyncer.Structure() == structure &&
				oldAllocatorSyncer.BehaviorType() == behaviorType {
				continue
			}
			newAllocator, err := NewStructuredSIDAllocator(l, structure, behaviorType)
			if err != nil {
				return false, fmt.Errorf("failed to create new SID allocator: %w", err)
			}
			newAllocatorSyncer := &sidAllocatorSyncer{
				SIDAllocator: newAllocator,
				syncFn:       m.Sync,
			}
			m.onUpdateLocator(la.PoolRef, oldAllocatorSyncer, newAllocatorSyncer)
			needsSync = true
		}
	}

	for _, poolRef := range maps.Keys(m.allocators) {
		if _, ok := pools[poolRef]; ok {
			continue
		}
		m.onDeleteLocator(poolRef, m.allocators[poolRef])
		needsSync = true
	}

	return needsSync, nil
}

// Handle locator add. Read lock for m.subscribers and write lock for
// m.allocators must be held.
func (m *sidManager) onAddLocator(poolRef string, newAllocator *sidAllocatorSyncer) {
	m.next(Event{
		Kind:      Upsert,
		PoolName:  poolRef,
		Allocator: newAllocator,
	})
	m.allocators[poolRef] = newAllocator
}

// Handle locator update. Read lock for m.subscribers and write lock for
// m.allocators must be held.
func (m *sidManager) onUpdateLocator(poolRef string, oldAllocator, newAllocator *sidAllocatorSyncer) {
	// Invalidate old allocator before emitting the event. From this point,
	// calling Sync on the old SIDAllocator will not trigger the state
	// sync.
	oldAllocator.Shutdown()

	// Now we can emit the event to the observers
	m.next(Event{
		Kind:      Upsert,
		PoolName:  poolRef,
		Allocator: newAllocator,
	})
	m.allocators[poolRef] = newAllocator
}

// Handle locator delete. Read lock for m.subscribers and write lock for
// m.allocators must be held.
func (m *sidManager) onDeleteLocator(poolRef string, oldAllocator *sidAllocatorSyncer) {
	// Invalidate old allocator before emitting the event. From this point,
	// calling Sync on the old allocator will not trigger the state sync.
	oldAllocator.Shutdown()

	// Now we can emit the event to the observers
	m.next(Event{
		Kind:     Delete,
		PoolName: poolRef,
	})
	delete(m.allocators, poolRef)
}

// Restore existing allocations from k8s resource status
func (m *sidManager) restoreAllocations(ctx context.Context, r *v1alpha1.IsovalentSRv6SIDManager) {
	var (
		restoredSIDs = 0
		staleSIDs    = 0
		errorSIDs    = 0
		errs         error
	)

	// No existing allocation
	if r.Status == nil {
		return
	}

	smLog.Info("Restoring existing SID allocations")

	m.allocatorsLock.RLock()
	defer m.allocatorsLock.RUnlock()

	for _, sa := range r.Status.SIDAllocations {
		if allocator, ok := m.allocators[sa.PoolRef]; ok {
			for _, sid := range sa.SIDs {
				addr, err := netip.ParseAddr(sid.SID.Addr)
				if err != nil {
					errorSIDs++
					errs = errors.Join(errs, fmt.Errorf("cannot parse SID on the status: %w", err))
					continue
				}

				structure, err := m.structureFromResource(sid.SID.Structure)
				if err != nil {
					errorSIDs++
					errs = errors.Join(errs, fmt.Errorf("cannot parse SID Structure on the status: %w", err))
					continue
				}

				s, err := types.NewSID(addr)
				if err != nil {
					errorSIDs++
					errs = errors.Join(errs, fmt.Errorf("cannot create SID from SID and SID Structure on the status: %w", err))
					continue
				}

				// Check locator, SID structure and behavior
				// type mismatch. If there's a mismatch, maybe
				// an old pool updated while Cilium is
				// stopping. We can ignore this here. So that
				// it will be deleted from the status in the
				// next sync.
				if !allocator.Locator().Contains(s.Addr) ||
					allocator.Structure() != structure ||
					types.BehaviorTypeFromString(sid.BehaviorType) != allocator.BehaviorType() {
					staleSIDs++
					continue
				}

				if _, err = allocator.Allocate(addr, sid.Owner, sid.MetaData, types.BehaviorFromString(sid.Behavior)); err != nil {
					errorSIDs++
					errs = errors.Join(errs, fmt.Errorf("allocation error: %w", err))
					continue
				}
				restoredSIDs++
			}
		} else {
			// Allocation exists, but there's no allocator (locator
			// pool). Maybe an old pool deleted while Cilium is
			// stopping. We can ignore this here. So that it will
			// be deleted from the status in the next sync.
			staleSIDs++
			continue
		}
	}

	smLog.Infof("Finish restoring existing SID allocations (restored: %d, stale: %d, error: %d)", restoredSIDs, staleSIDs, errorSIDs)
	if errs != nil {
		smLog.WithError(errs).Warn("Error occurred while restoring")
	}
}

// Delete all allocators. We don't have to schedule sync here since we don't
// have resource to sync anymore.
func (m *sidManager) deleteAllAllocators(r *v1alpha1.IsovalentSRv6SIDManager) {
	m.allocatorsLock.Lock()
	defer m.allocatorsLock.Unlock()

	for poolRef, allocator := range m.allocators {
		m.onDeleteLocator(poolRef, allocator)
	}

}

func (m *sidManager) runStatusReconciler(ctx context.Context) error {
	smLog.Info("Starting SID Manager status reconciler")

	defer m.wg.Done()

	// In case of the state synchronization failure, we retry with
	// exponential backoff.
	backoff := backoff.Exponential{
		// No specific reason for choosing value, but at least
		// make it predictable (by default, there is no limit).
		Max: 90 * time.Minute,
	}

	retrying := false
	for {
		select {
		case <-m.stateSyncCh:
			// We need this condition because otherwise, backoff.Wait always
			// backoffs for min time (1 second).
			if retrying {
				if err := backoff.Wait(ctx); err != nil {
					// The only possible error case here is context expiration.
					// In that case, we should return.
					return nil
				}
			}

			if err := m.reconcileStatus(ctx); err != nil {
				// Generate warning only for the first retry. Otherwise, it's too noisy.
				if !retrying {
					smLog.WithError(err).Warn("State synchronization failed. Retrying with backoff.")
					retrying = true
				} else {
					// This is for debugging
					smLog.WithError(err).Warn("State synchronization failed. Retrying with backoff.")
				}
				m.Sync()
			} else {
				// Reset backoff on success
				if retrying {
					retrying = false
					backoff.Reset()
				}
			}
		case <-ctx.Done():
			smLog.Info("Stopping SID Manager status reconciler")
			return nil
		}
	}
}

func (m *sidManager) reconcileStatus(ctx context.Context) error {
	smLog.Debug("Synchronizing allocation state to k8s resource")

	status := v1alpha1.IsovalentSRv6SIDManagerStatus{
		SIDAllocations: []*v1alpha1.IsovalentSRv6SIDAllocation{},
	}

	m.allocatorsLock.RLock()

	for poolName, allocator := range m.allocators {
		sis := allocator.AllocatedSIDs("")
		if len(sis) == 0 {
			continue
		}
		allocation := v1alpha1.IsovalentSRv6SIDAllocation{
			PoolRef: poolName,
		}
		for _, si := range sis {
			allocation.SIDs = append(allocation.SIDs, m.sidInfoToResource(si))
		}
		status.SIDAllocations = append(status.SIDAllocations, &allocation)
	}

	m.allocatorsLock.RUnlock()

	// Sort lists for the better status visibility
	slices.SortFunc(status.SIDAllocations, func(a, b *v1alpha1.IsovalentSRv6SIDAllocation) int {
		return strings.Compare(a.PoolRef, b.PoolRef)
	})
	for _, allocation := range status.SIDAllocations {
		slices.SortFunc(allocation.SIDs, func(a, b *v1alpha1.IsovalentSRv6SIDInfo) int {
			return strings.Compare(a.SID.Addr, b.SID.Addr)
		})
	}

	patch := []k8s.JSONPatch{
		{
			OP:    "replace",
			Path:  "/status",
			Value: &status,
		},
	}

	patchJSON, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("failed to marshal patch")
	}

	_, err = m.clientset.IsovalentV1alpha1().IsovalentSRv6SIDManagers().Patch(
		ctx, nodeTypes.GetName(), k8sTypes.JSONPatchType, patchJSON,
		metav1.PatchOptions{FieldManager: SRv6SIDManagerSubsys}, "status")
	if err != nil {
		return fmt.Errorf("failed to patch resource: %w", err)
	}

	smLog.Debug("Successfully synchronized the allocation state to k8s resource")

	return nil
}

// locatorFromResource converts locator on the k8s resource to internal Locator structure
func (m *sidManager) locatorFromResource(r *v1alpha1.IsovalentSRv6Locator) (types.Locator, error) {
	prefix, err := netip.ParsePrefix(r.Prefix)
	if err != nil {
		return types.Locator{}, err
	}
	return types.NewLocator(prefix)
}

func (m *sidManager) structureFromResource(r v1alpha1.IsovalentSRv6SIDStructure) (types.SIDStructure, error) {
	return types.NewSIDStructure(
		r.LocatorBlockLenBits,
		r.LocatorNodeLenBits,
		r.FunctionLenBits,
		r.ArgumentLenBits,
	)
}

// sidToResource converts internal SID structure to SID on k8s resource
func (m *sidManager) sidInfoToResource(si *SIDInfo) *v1alpha1.IsovalentSRv6SIDInfo {
	sid := v1alpha1.IsovalentSRv6SID{
		Addr: si.SID.Addr.String(),
		Structure: v1alpha1.IsovalentSRv6SIDStructure{
			LocatorBlockLenBits: si.Structure.LocatorBlockLenBits(),
			LocatorNodeLenBits:  si.Structure.LocatorNodeLenBits(),
			FunctionLenBits:     si.Structure.FunctionLenBits(),
			ArgumentLenBits:     si.Structure.ArgumentLenBits(),
		},
	}
	return &v1alpha1.IsovalentSRv6SIDInfo{
		Owner:        si.Owner,
		MetaData:     si.MetaData,
		SID:          sid,
		BehaviorType: si.BehaviorType.String(),
		Behavior:     si.Behavior.String(),
	}
}

// Sync schedules allocation state synchronization to k8s resource
func (m *sidManager) Sync() {
	select {
	case m.stateSyncCh <- struct{}{}:
		smLog.Debug("Scheduled state sync")
	default:
		smLog.Debug("State sync is already scheduled. Skipping.")
	}
}

// LocalIsovalentSRv6SIDManagerResource is a Resource[T] for the local
// SIDManager resource (SIDManager resource that its name is the same as local
// node name.
type LocalIsovalentSRv6SIDManagerResource resource.Resource[*v1alpha1.IsovalentSRv6SIDManager]

func NewLocalIsovalentSRv6SIDManagerResource(dc *option.DaemonConfig, lc cell.Lifecycle, cs client.Clientset) LocalIsovalentSRv6SIDManagerResource {
	if !dc.EnableSRv6 || !cs.IsEnabled() {
		return nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped[*v1alpha1.IsovalentSRv6SIDManagerList](cs.IsovalentV1alpha1().IsovalentSRv6SIDManagers()),
		func(opts *metav1.ListOptions) {
			// Note: FakeClientset doesn't handle this filtering
			opts.FieldSelector = fields.ParseSelectorOrDie("metadata.name=" + nodeTypes.GetName()).String()
		},
	)
	return resource.New[*v1alpha1.IsovalentSRv6SIDManager](lc, lw, resource.WithMetric("IsovalentSRv6SIDManager"))
}
