// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipam"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/srv6map"
	"github.com/cilium/cilium/pkg/option"
)

var (
	subsys = "srv6"
	log    = logging.DefaultLogger.WithField(logfields.LogSubsys, subsys)
)

// ErrSIDAlloc indicates an issue allocating a SID from the Manager's SID
// allocator.
//
// ErrSIDAlloc is capable of wrapping any errors exported by the implementation
// of a SID Allocator.
type ErrSIDAlloc struct {
	e error
}

func (e *ErrSIDAlloc) Error() string {
	return "failed to allocate SID: " + e.e.Error()
}

func (e *ErrSIDAlloc) Unwrap() error {
	return e.e
}

type k8sCacheSyncedChecker interface {
	K8sCacheIsSynced() bool
}

// BGPSignaler is an interface which exposes a method for notifying the BGP
// control plane of SRv6Manager state changes.
//
// The BGP control plane understands how to query the SRv6Mananger so no arguments
// are required.
type BGPSignaler interface {
	Signal()
}

// A bookkeeping structure for locally allocated SIDs.
// These SID allocations serve as SRV6 VRF locators.
type SIDAllocation struct {
	VRFID             uint32
	ExportRouteTarget string
	SID               net.IP
}

// The SRv6 manager stores the internal data to track SRv6 policies, VRFs,
// and SIDs. It also hooks up all the callbacks to update the BPF SRv6 maps
// accordingly.
//
// The SRv6 manager is capable of notifying the BGP Control Plane when changes
// to its internal databases occur.
type Manager struct {
	mutex lock.RWMutex

	// k8sCacheSyncedChecker is used to check if the agent has synced its
	// cache with the k8s API server
	k8sCacheSyncedChecker k8sCacheSyncedChecker

	// policies stores egress policies indexed by policyID
	policies map[policyID]*EgressPolicy

	// vrfs stores VRFs indexed by vrfID
	vrfs map[vrfID]*VRF

	// epDataStore stores endpointId to endpoint metadata mapping
	epDataStore map[endpointID]*endpointMetadata

	// identityAllocator is used to fetch identity labels for endpoint updates
	identityAllocator identityCache.IdentityAllocator

	// allocatedSIDs maps VRF ids to their allocated SID if applicable.
	//
	// When we encounter VRFs with a defined ExportRouteTarget field a SID is
	// allocated locally and stored in this map. The map is then referenced to
	// determine if SID allocation/deallocation is necessary on VRF event.
	allocatedSIDs map[uint32]*SIDAllocation

	// bgp is a handle to an instantiated BGPSignaler interface.
	// this interface informs the BGP control plane that the SRv6Manager's state
	// has changed.
	bgpMu lock.RWMutex
	bgp   BGPSignaler

	// sidAlloc is an IPv6Allocator used to allocate L3VPN service SID's on VRF
	// creation.
	sidMu    lock.RWMutex
	sidAlloc ipam.Allocator
}

// NewSRv6Manager returns a new SRv6 policy manager.
func NewSRv6Manager(k8sCacheSyncedChecker k8sCacheSyncedChecker,
	identityAllocator identityCache.IdentityAllocator) *Manager {
	manager := &Manager{
		k8sCacheSyncedChecker: k8sCacheSyncedChecker,
		policies:              make(map[policyID]*EgressPolicy),
		vrfs:                  make(map[vrfID]*VRF),
		epDataStore:           make(map[endpointID]*endpointMetadata),
		identityAllocator:     identityAllocator,
		allocatedSIDs:         make(map[uint32]*SIDAllocation),
	}

	manager.runReconciliationAfterK8sSync()

	return manager
}

func (manager *Manager) SetBGPSignaler(bgp BGPSignaler) {
	manager.bgpMu.Lock()
	manager.bgp = bgp
	manager.bgpMu.Unlock()
}

func (manager *Manager) SetSIDAllocator(a ipam.Allocator) {
	manager.sidMu.Lock()
	manager.sidAlloc = a
	manager.sidMu.Unlock()
}

// runReconciliationAfterK8sSync spawns a goroutine that waits for the agent to
// sync with k8s and then runs the first reconciliation.
func (manager *Manager) runReconciliationAfterK8sSync() {
	go func() {

		for {
			if manager.k8sCacheSyncedChecker.K8sCacheIsSynced() {
				break
			}

			time.Sleep(1 * time.Second)
		}

		manager.mutex.Lock()
		defer manager.mutex.Unlock()

		manager.reconcilePoliciesAndSIDs()
	}()
}

// GetAllVRFs returns a slice with all VRFs known to the SRv6 manager.
func (manager *Manager) GetAllVRFs() []*VRF {
	manager.mutex.RLock()
	defer manager.mutex.RUnlock()

	vrfs := make([]*VRF, 0, len(manager.vrfs))
	for _, vrf := range manager.vrfs {
		vrfs = append(vrfs, vrf)
	}
	return vrfs
}

// GetVRFs returns a slice with VRFs known to the SRv6 manager that have the
// given import route-target.
func (manager *Manager) GetVRFs(importRouteTarget string) []*VRF {
	manager.mutex.RLock()
	defer manager.mutex.RUnlock()

	vrfs := make([]*VRF, 0, len(manager.vrfs))
	for _, vrf := range manager.vrfs {
		if vrf.ImportRouteTarget == importRouteTarget {
			vrfs = append(vrfs, vrf)
		}
	}
	return vrfs
}

// GetEgressPolicies returns a slice with the SRv6 egress policies known to the
// SRv6 manager.
func (manager *Manager) GetEgressPolicies() []*EgressPolicy {
	manager.mutex.RLock()
	defer manager.mutex.RUnlock()

	policies := make([]*EgressPolicy, 0, len(manager.policies))
	for _, policy := range manager.policies {
		policies = append(policies, policy)
	}
	return policies
}

// Event handlers

// OnAddSRv6Policy and updates the manager internal state with the policy
// fields.
func (manager *Manager) OnAddSRv6Policy(policy EgressPolicy) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	logger := log.WithField(logfields.CiliumSRv6EgressPolicyName, policy.id.Name)

	if _, ok := manager.policies[policy.id]; !ok {
		logger.Info("Added CiliumSRv6EgressPolicy")
	} else {
		logger.Info("Updated CiliumSRv6EgressPolicy")
	}

	manager.policies[policy.id] = &policy

	manager.reconcilePoliciesAndSIDs()
}

// OnDeleteSRv6Policy deletes the internal state associated with the given
// policy.
func (manager *Manager) OnDeleteSRv6Policy(policyID policyID) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	logger := log.WithField(logfields.CiliumSRv6EgressPolicyName, policyID.Name)

	if manager.policies[policyID] == nil {
		logger.Warn("Can't delete CiliumSRv6EgressPolicy: policy not found")
		return
	}

	logger.Info("Deleted CiliumSRv6EgressPolicy")

	delete(manager.policies, policyID)

	manager.reconcilePoliciesAndSIDs()
}

// OnAddSRv6VRF and updates the manager internal state with the VRF
// config fields.
func (manager *Manager) OnAddSRv6VRF(vrf VRF) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	logger := log.WithField(logfields.CiliumSRv6VRFName, vrf.id.Name)

	if _, ok := manager.vrfs[vrf.id]; !ok {
		logger.Info("Added CiliumSRv6VRF")
	} else {
		logger.Info("Updated CiliumSRv6VRF")
	}

	manager.vrfs[vrf.id] = &vrf

	manager.reconcileVRFMappings()
}

// OnDeleteSRv6VRF deletes the internal state associated with the given VRF.
func (manager *Manager) OnDeleteSRv6VRF(vrfID vrfID) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	logger := log.WithField(logfields.CiliumSRv6VRFName, vrfID.Name)

	if manager.vrfs[vrfID] == nil {
		logger.Warn("Can't delete CiliumSRv6VRF: policy not found")
		return
	}

	logger.Info("Deleted CiliumSRv6VRF")

	delete(manager.vrfs, vrfID)

	manager.reconcileVRFMappings()
}

// OnUpdateEndpoint is the event handler for endpoint additions and updates.
func (manager *Manager) OnUpdateEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	var (
		identityLabels labels.Labels
		epData         *endpointMetadata
		err            error
	)

	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	logger := log.WithFields(logrus.Fields{
		logfields.K8sEndpointName: endpoint.Name,
		logfields.K8sNamespace:    endpoint.Namespace,
	})

	if len(endpoint.Networking.Addressing) == 0 {
		logger.WithError(err).
			Error("Failed to get valid endpoint IPs, skipping update of SRv6 maps.")
		return
	}

	if identityLabels, err = manager.getIdentityLabels(uint32(endpoint.Identity.ID)); err != nil {
		logger.WithError(err).
			Error("Failed to get idenity labels for endpoint, skipping update of SRv6 maps.")
		return
	}

	if epData, err = getEndpointMetadata(endpoint, identityLabels); err != nil {
		logger.WithError(err).
			Error("Failed to get valid endpoint metadata, skipping update of SRv6 maps.")
		return
	}

	manager.epDataStore[epData.id] = epData

	manager.reconcileVRFMappings()
}

// OnDeleteEndpoint is the event handler for endpoint deletions.
func (manager *Manager) OnDeleteEndpoint(endpoint *k8sTypes.CiliumEndpoint) {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()

	id := types.NamespacedName{
		Name:      endpoint.GetName(),
		Namespace: endpoint.GetNamespace(),
	}

	delete(manager.epDataStore, id)

	manager.reconcileVRFMappings()
}

// getIdentityLabels waits for the global identities to be populated to the cache,
// then looks up identity by ID from the cached identity allocator and return its labels.
func (manager *Manager) getIdentityLabels(securityIdentity uint32) (labels.Labels, error) {
	identityCtx, cancel := context.WithTimeout(context.Background(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()
	if err := manager.identityAllocator.WaitForInitialGlobalIdentities(identityCtx); err != nil {
		return nil, fmt.Errorf("failed to wait for initial global identities: %v", err)
	}

	identity := manager.identityAllocator.LookupIdentityByID(identityCtx, identity.NumericIdentity(securityIdentity))
	if identity == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return identity.Labels, nil
}

// addMissingSRv6PolicyRules is responsible for adding any missing egress SRv6
// policies stored in the manager (i.e. k8s CiliumSRv6EgressPolicies) to the
// egress policy BPF map.
func (manager *Manager) addMissingSRv6PolicyRules() {
	srv6Policies := map[srv6map.PolicyKey]srv6map.PolicyValue{}
	srv6map.SRv6PolicyMap4.IterateWithCallback4(
		func(key *srv6map.PolicyKey, val *srv6map.PolicyValue) {
			srv6Policies[*key] = *val
		})
	srv6map.SRv6PolicyMap6.IterateWithCallback6(
		func(key *srv6map.PolicyKey, val *srv6map.PolicyValue) {
			srv6Policies[*key] = *val
		})

	var err error
	for _, policy := range manager.policies {
		for _, dstCIDR := range policy.DstCIDRs {
			policyKey := srv6map.PolicyKey{
				VRFID:    policy.VRFID,
				DestCIDR: dstCIDR,
			}

			policyVal, policyPresent := srv6Policies[policyKey]
			if policyPresent && policyVal.SID == policy.SID {
				continue
			}

			err = srv6map.GetPolicyMap(policyKey).Update(policyKey, policy.SID)

			logger := log.WithFields(logrus.Fields{
				logfields.VRF:             policy.VRFID,
				logfields.DestinationCIDR: *dstCIDR,
				logfields.SID:             policy.SID,
			})
			if err != nil {
				logger.WithError(err).Error("Error applying egress SRv6 policy")
			} else {
				logger.Info("Egress SRv6 policy applied")
			}
		}
	}
}

// removeUnusedSRv6PolicyRules is responsible for removing any entry in the SRv6 policy BPF map which
// is not baked by an actual k8s CiliumSRv6EgressPolicy.
//
// The algorithm for this function can be expressed as:
//
//	nextPolicyKey:
//	for each entry in the srv6_policy map {
//	    for each policy in k8s CiliumSRv6EgressPolices {
//	        if policy matches entry {
//	            // we found one k8s policy that matches the current BPF entry, move to the next one
//	            continue nextPolicyKey
//	        }
//	    }
//
//	    // the current BPF entry is not backed by any k8s policy, delete it
//	    srv6map.RemoveSRv6Policy(entry)
//	}
func (manager *Manager) removeUnusedSRv6PolicyRules() {
	srv6Policies := map[srv6map.PolicyKey]srv6map.PolicyValue{}
	srv6map.SRv6PolicyMap4.IterateWithCallback4(
		func(key *srv6map.PolicyKey, val *srv6map.PolicyValue) {
			srv6Policies[*key] = *val
		})
	srv6map.SRv6PolicyMap6.IterateWithCallback6(
		func(key *srv6map.PolicyKey, val *srv6map.PolicyValue) {
			srv6Policies[*key] = *val
		})

nextPolicyKey:
	for policyKey := range srv6Policies {
		for _, policy := range manager.policies {
			for _, dstCIDR := range policy.DstCIDRs {
				if policyKey.Match(policy.VRFID, dstCIDR) {
					continue nextPolicyKey
				}
			}
		}

		logger := log.WithFields(logrus.Fields{
			logfields.VRF:             policyKey.VRFID,
			logfields.DestinationCIDR: policyKey.DestCIDR,
		})

		if err := srv6map.GetPolicyMap(policyKey).Delete(policyKey); err != nil {
			logger.WithError(err).Error("Error removing SRv6 egress policy")
		} else {
			logger.Info("SRv6 egress policy removed")
		}
	}
}

// addMissingSRv6SIDs implements the same as addMissingSRv6PolicyRules but for
// the SID map.
func (manager *Manager) addMissingSRv6SIDs() {
	srv6SIDs := map[srv6map.SIDKey]srv6map.SIDValue{}
	srv6map.SRv6SIDMap.IterateWithCallback(
		func(key *srv6map.SIDKey, val *srv6map.SIDValue) {
			srv6SIDs[*key] = *val
		})

	var err error
	for _, policy := range manager.policies {
		sidKey := srv6map.SIDKey{
			SID: policy.SID,
		}

		sidVal, sidPresent := srv6SIDs[sidKey]
		if sidPresent && sidVal.VRFID == policy.VRFID {
			continue
		}

		err = srv6map.SRv6SIDMap.Update(sidKey, policy.VRFID)

		logger := log.WithFields(logrus.Fields{
			logfields.SID: policy.SID,
			logfields.VRF: policy.VRFID,
		})
		if err != nil {
			logger.WithError(err).Error("Error adding SID")
		} else {
			logger.Info("SID added")
		}
	}
}

// removeUnusedSRv6SIDs implements the same as removeUnusedSRv6PolicyRules but
// for the SID map.
func (manager *Manager) removeUnusedSRv6SIDs() {
	srv6SIDs := map[srv6map.SIDKey]srv6map.SIDValue{}
	srv6map.SRv6SIDMap.IterateWithCallback(
		func(key *srv6map.SIDKey, val *srv6map.SIDValue) {
			srv6SIDs[*key] = *val
		})

nextSIDKey:
	for sidKey := range srv6SIDs {
		for _, policy := range manager.policies {
			if sidKey.SID == policy.SID {
				continue nextSIDKey
			}
		}

		logger := log.WithFields(logrus.Fields{
			logfields.SID: sidKey.SID,
		})

		if err := srv6map.SRv6SIDMap.Delete(sidKey); err != nil {
			logger.WithError(err).Error("Error removing SID")
		} else {
			logger.Info("SID removed")
		}
	}
}

// reconcilePoliciesAndSIDs is responsible for reconciling the state of the
// manager (i.e. the desired state) with the actual state of the node (SRv6
// policy map entries and SIDs).
//
// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (manager *Manager) reconcilePoliciesAndSIDs() {
	if !manager.k8sCacheSyncedChecker.K8sCacheIsSynced() {
		return
	}

	// The order of the next 2 function calls matters, as by first adding missing policies and
	// only then removing obsolete ones we make sure there will be no connectivity disruption
	manager.addMissingSRv6PolicyRules()
	manager.removeUnusedSRv6PolicyRules()

	manager.addMissingSRv6SIDs()
	manager.removeUnusedSRv6SIDs()
}

// reconcileVRFMappings is responsible for reconciling the state of the
// manager (i.e. the desired state) with the actual state of the node (SRv6
// VRF mapping maps).
//
// Reconciling VRF mappings have two distinct directions, ingress and egress.
// The ingress direction will configure the data path to receieve traffic from
// participating VPN peers.
//
// The egress path will configure the data path to encapsulate VPN traffic
// originating from the Cilium node participating in a VPN.
func (manager *Manager) reconcileVRFMappings() {

	if !manager.k8sCacheSyncedChecker.K8sCacheIsSynced() {
		return
	}

	manager.reconcileVRFMappingIngressPath()
	manager.reconcileVRFMappingEgressPath()

	manager.bgpMu.RLock()
	defer manager.bgpMu.RUnlock()
	if manager.bgp != nil {
		manager.bgp.Signal()
	}
}

// reconcileVRFMappingEgressPath will add and remove mappings from the SRv6VRF
// maps given the current Manager's VRF database.
//
// A VRF is expanded into one or more VRFKey structures which act as keys and
// map to the VRF's ID if the VRF's endpoint selector matches an endpoint's
// label.
//
// The manager keeps a database of known endpoints to compare VRF selection against.
func (m *Manager) reconcileVRFMappingEgressPath() {
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "srv6.Manager.reconcileVRFMappingEgressPath",
			},
		)
		srv6VRFs = map[srv6map.VRFKey]srv6map.VRFValue{}
	)
	log.Info("Configuring egress datapath for encapsulation.")

	// populate srv6VRFs map
	srv6map.SRv6VRFMap4.IterateWithCallback4(
		func(key *srv6map.VRFKey, val *srv6map.VRFValue) {
			srv6VRFs[*key] = *val
		})
	srv6map.SRv6VRFMap6.IterateWithCallback6(
		func(key *srv6map.VRFKey, val *srv6map.VRFValue) {
			srv6VRFs[*key] = *val
		})

	for _, vrf := range m.vrfs {
		keys := vrf.keysFromEndpoints(m.epDataStore)
		for _, key := range keys {
			vrfVal, vrfPresent := srv6VRFs[key]
			if vrfPresent && vrfVal.ID == vrf.VRFID {
				continue
			}
			logger := l.WithFields(logrus.Fields{
				logfields.SourceIP:        key.SourceIP,
				logfields.DestinationCIDR: key.DestCIDR,
				logfields.VRF:             vrf.VRFID,
			})
			if err := srv6map.GetVRFMap(key).Update(key, vrf.VRFID); err != nil {
				logger.WithError(err).Error("Error applying SRv6 VRF mapping")
			} else {
				logger.Info("SRv6 VRF mapping applied")
			}
		}
	}

	// remove any existing VRF entries
nextVRFKey:
	for vrfKey := range srv6VRFs {
		for _, vrf := range m.vrfs {
			keys := vrf.keysFromEndpoints(m.epDataStore)
			for _, key := range keys {
				if vrfKey.Match(*key.SourceIP, key.DestCIDR) {
					continue nextVRFKey
				}
			}
		}
		logger := l.WithFields(logrus.Fields{
			logfields.SourceIP:        vrfKey.SourceIP,
			logfields.DestinationCIDR: vrfKey.DestCIDR,
		})

		if err := srv6map.GetVRFMap(vrfKey).Delete(vrfKey); err != nil {
			logger.WithError(err).Error("Error removing SRv6 VRF mapping")
		} else {
			logger.Info("SRv6 VRF mapping removed")
		}
	}
}

// When a VRF has a defined "ExportRouteTarget" we must configure both the Manager
// and the eBPF datapath to process ingress traffic destined to the VRF being
// exported.
//
// This function will organize the Manager's VRFs and SID allocations and then
// create or remove both according to the Manager's state.
func (m *Manager) reconcileVRFMappingIngressPath() {
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "srv6.Manager.removeIngressPathVRFMapping",
			},
		)
		toCreate = []*VRF{}
		toRemove = []*SIDAllocation{}
	)

	// By the time we are in this method, the VRF event has been indexed into
	// the manager's VRF field.
	//
	// ATTENTION: A subtlety exists here in that VRF updates from Kubernetes know nothing
	// about locally allocated SIDs and an update event can overwrite the a VRF's
	// locally allocated SID. Therefore, this method must also repopulate the
	// SID's Allocated VRF field.
	for _, v := range m.vrfs {
		alloc, ok := m.allocatedSIDs[v.VRFID]

		// does this vrf have an ExportRouteTarget and no SID allocation?
		if v.ExportRouteTarget != "" && !ok {
			toCreate = append(toCreate, v)
			continue
		}

		// does this VRF have an existing SID allocation?
		if ok {
			// SID allocation exists, does ExportRouteTarget match it?
			if v.ExportRouteTarget != alloc.ExportRouteTarget {
				// ExportRouteTarget undefined, remove this allocation.
				if v.ExportRouteTarget == "" {
					toRemove = append(toRemove, alloc)
				}
				continue
			}
			// SID allocation exists and ExportRouteTarget is the same, re-write
			// allocated SID incase an update overwritten it. See: ATTENTION:
			v.AllocatedSID = alloc.SID

			// NOTE: is possible the ExportRouteTarget may have changed.
			// we don't specifically handle this case as the BGP Control Plane
			// will pickup this change on its reconciliation loop.
		}
	}
	// if we have any allocated SIDs which do not have associated VRF definitions
	// remove them.
	for vrfID := range m.allocatedSIDs {
		for _, vrf := range m.vrfs {
			if vrf.VRFID == vrfID {
				continue
			}
		}
		toRemove = append(toRemove, m.allocatedSIDs[vrfID])
	}
	l.WithFields(logrus.Fields{
		"toCreate": len(toCreate),
		"toRemove": len(toRemove),
	}).Debug("Configuring ingress VRF mappings for decapsulation.")
	m.createIngressPathVRFMapping(toCreate)
	m.removeIngressPathVRFMapping(toRemove)
}

// createIngressPathVRFMapping will range over the provided VRFs and configure
// the datapath for ingressing VPN traffic destined for this node's VRF.
//
// The ingress path configuration consists of the following for newly exported VRFs.
// 1. Allocating a SID for the VRF if necessary
// 2. Writing this SID and its associated VRF ID to the SRv6SIDMap //TODO: checking spelling
// 3. Store the allocated SID wihin the Manager's memory.
func (m *Manager) createIngressPathVRFMapping(vrfs []*VRF) {
	l := log.WithFields(
		logrus.Fields{
			"component": "srv6.Manager.createIngressPathVRFMapping",
		},
	)
	for _, vrf := range vrfs {
		func(vrf *VRF) {
			// ATTENTION: variables declared here so cleanup function can close
			// over them, do not redefine.
			var (
				err      error
				res      *ipam.AllocationResult
				key      *srv6map.SIDKey
				progress struct {
					alloced *net.IP
					sidmap  bool
				}
			)
			// defer a cleanup function if err != nil
			defer func() {
				if err != nil {
					if progress.alloced != nil {
						if err := m.sidAlloc.Release(res.IP); err != nil {
							l.WithError(err).Error("failed to cleanup SID Allocation " + res.IP.String())
						}
					}
					if progress.sidmap {
						if err := srv6map.SRv6SIDMap.Delete(*key); err != nil {
							l.WithError(err).Error("failed to cleanup SIDMap entry " + key.String())
						}
					}
				}
			}()
			// allocate a SID
			res, err = m.sidAlloc.AllocateNext(subsys)
			if err != nil {
				l.WithField("VRF_ID", vrf.VRFID).WithError(err).Error("Failed to allocate SID for VRF")
				return
			}
			vrf.AllocatedSID = res.IP
			progress.alloced = &res.IP
			// populate SID map
			key, err = srv6map.NewSIDKeyFromIP(&vrf.AllocatedSID)
			if err != nil {
				l.WithField("VRF_ID", vrf.VRFID).WithError(err).Error("Failed to create SID map key for VRF")
				return
			}
			err = srv6map.SRv6SIDMap.Update(*key, vrf.VRFID)
			if err != nil {
				l.WithFields(logrus.Fields{
					"vrfID": vrf.VRFID,
					"SID":   vrf.AllocatedSID,
				}).WithError(err).Error("Failed to update SID map")
			}
			progress.sidmap = true
			// store allocated SID
			m.allocatedSIDs[vrf.VRFID] = &SIDAllocation{
				VRFID:             vrf.VRFID,
				ExportRouteTarget: vrf.ExportRouteTarget,
				SID:               vrf.AllocatedSID,
			}
			l.WithFields(logrus.Fields{
				"vrfID":             vrf.VRFID,
				"SID":               vrf.AllocatedSID.String(),
				"ExportRouteTarget": vrf.ExportRouteTarget,
			}).Info("Allocated SID for VRF requesting export of routes.")
		}(vrf)
	}
}

// removeIngressPathVRFMapping ranges over the provided SIDAllocation(s) and
// removes their existence from the data path.
//
// this is essentially the opposite of createIngressPathVRFMapping.
//
// if an error occurs in any of the operations involved with removing a SID
// allocation the removal will be tried again on next reconciliation.
func (m *Manager) removeIngressPathVRFMapping(allocs []*SIDAllocation) {
	l := log.WithFields(
		logrus.Fields{
			"component": "srv6.Manager.removeIngressPathVRFMapping",
		},
	)
	for _, alloc := range allocs {
		l := l.WithFields(
			logrus.Fields{
				"SID":               alloc.SID,
				"exportRouteTarget": alloc.ExportRouteTarget,
				"vrfID":             alloc.VRFID,
			},
		)
		var shouldDelete = true
		key, err := srv6map.NewSIDKeyFromIP(&alloc.SID)
		if err != nil {
			l.WithError(err).Error("failed creating SIDMap key")
			shouldDelete = false
		}
		if err := srv6map.SRv6SIDMap.Delete(*key); err != nil {
			l.WithError(err).Error("failed deleting SIDMap entry for allocation")
			shouldDelete = false
		}
		if shouldDelete {
			delete(m.allocatedSIDs, alloc.VRFID)
			l.Info("Deleted SID allocation for VRF")
		}
	}
}
