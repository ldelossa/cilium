// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6

import (
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"
	netutils "k8s.io/utils/net"

	"github.com/cilium/cilium/pkg/ip"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/srv6map"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "srv6")
)

type k8sCacheSyncedChecker interface {
	K8sCacheIsSynced() bool
}

// The SRv6 manager stores the internal data to track SRv6 policies, VRFs,
// and SIDs. It also hooks up all the callbacks to update the BPF SRv6 maps
// accordingly.
type Manager struct {
	mutex lock.Mutex

	// k8sCacheSyncedChecker is used to check if the agent has synced its
	// cache with the k8s API server
	k8sCacheSyncedChecker k8sCacheSyncedChecker

	// policies stores egress policies indexed by policyID
	policies map[policyID]*EgressPolicy

	// vrfs stores VRFs indexed by vrfID
	vrfs map[vrfID]*VRF

	// epDataStore stores endpointId to endpoint metadata mapping
	epDataStore map[endpointID]*endpointMetadata
}

// NewSRv6Manager returns a new SRv6 policy manager.
func NewSRv6Manager(k8sCacheSyncedChecker k8sCacheSyncedChecker) *Manager {
	manager := &Manager{
		k8sCacheSyncedChecker: k8sCacheSyncedChecker,
		policies:              make(map[policyID]*EgressPolicy),
		vrfs:                  make(map[vrfID]*VRF),
		epDataStore:           make(map[endpointID]*endpointMetadata),
	}

	manager.runReconciliationAfterK8sSync()

	return manager
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
	var epData *endpointMetadata
	var err error

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

	if epData, err = getEndpointMetadata(endpoint); err != nil {
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
		for _, dstCIDR := range policy.dstCIDRs {
			policyKey := srv6map.PolicyKey{
				VRFID:    policy.vrfID,
				DestCIDR: dstCIDR,
			}

			policyVal, policyPresent := srv6Policies[policyKey]
			if policyPresent && policyVal.SID == policy.sid {
				continue
			}

			err = srv6map.GetPolicyMap(policyKey).Update(policyKey, policy.sid)

			logger := log.WithFields(logrus.Fields{
				logfields.VRF:             policy.vrfID,
				logfields.DestinationCIDR: *dstCIDR,
				logfields.SID:             policy.sid,
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
//    nextPolicyKey:
//    for each entry in the srv6_policy map {
//        for each policy in k8s CiliumSRv6EgressPolices {
//            if policy matches entry {
//                // we found one k8s policy that matches the current BPF entry, move to the next one
//                continue nextPolicyKey
//            }
//        }
//
//        // the current BPF entry is not backed by any k8s policy, delete it
//        srv6map.RemoveSRv6Policy(entry)
//    }
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
			for _, dstCIDR := range policy.dstCIDRs {
				if policyKey.Match(policy.vrfID, dstCIDR) {
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
			SID: policy.sid,
		}

		sidVal, sidPresent := srv6SIDs[sidKey]
		if sidPresent && sidVal.VRFID == policy.vrfID {
			continue
		}

		err = srv6map.SRv6SIDMap.Update(sidKey, policy.vrfID)

		logger := log.WithFields(logrus.Fields{
			logfields.SID: policy.sid,
			logfields.VRF: policy.vrfID,
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
			if sidKey.SID == policy.sid {
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

// addMissingSRv6VRFMappings implements the same as addMissingSRv6PolicyRules but
// for the vrf mapping map.
func (manager *Manager) addMissingSRv6VRFMappings() {
	srv6VRFs := map[srv6map.VRFKey]srv6map.VRFValue{}
	srv6map.SRv6VRFMap4.IterateWithCallback4(
		func(key *srv6map.VRFKey, val *srv6map.VRFValue) {
			srv6VRFs[*key] = *val
		})
	srv6map.SRv6VRFMap6.IterateWithCallback6(
		func(key *srv6map.VRFKey, val *srv6map.VRFValue) {
			srv6VRFs[*key] = *val
		})

	for _, vrf := range manager.vrfs {
		for _, vrfRule := range vrf.rules {
			for _, endpoint := range manager.epDataStore {
				if !vrfRule.selectsEndpoint(endpoint) {
					continue
				}

				for _, endpointIP := range endpoint.ips {
					for _, dstCIDR := range vrfRule.dstCIDRs {
						if ip.IsIPv6(endpointIP) != netutils.IsIPv6CIDR(dstCIDR) {
							// Endpoints can only connect to IPv6 destinations with
							// their IPv6 address.
							continue
						}

						vrfKey := srv6map.VRFKey{
							SourceIP: &endpointIP,
							DestCIDR: dstCIDR,
						}
						vrfVal, vrfPresent := srv6VRFs[vrfKey]

						if vrfPresent && vrfVal.ID == vrf.vrfID {
							continue
						}

						logger := log.WithFields(logrus.Fields{
							logfields.SourceIP:        endpointIP,
							logfields.DestinationCIDR: *dstCIDR,
							logfields.VRF:             vrf.vrfID,
						})

						if err := srv6map.GetVRFMap(vrfKey).Update(vrfKey, vrf.vrfID); err != nil {
							logger.WithError(err).Error("Error applying SRv6 VRF mapping")
						} else {
							logger.Info("SRv6 VRF mapping applied")
						}
					}
				}
			}
		}
	}
}

// removeUnusedSRv6VRFMappings implements the same as
// removeUnusedSRv6PolicyRules but for the SID map.
func (manager *Manager) removeUnusedSRv6VRFMappings() {
	srv6VRFs := map[srv6map.VRFKey]srv6map.VRFValue{}
	srv6map.SRv6VRFMap4.IterateWithCallback4(
		func(key *srv6map.VRFKey, val *srv6map.VRFValue) {
			srv6VRFs[*key] = *val
		})
	srv6map.SRv6VRFMap6.IterateWithCallback6(
		func(key *srv6map.VRFKey, val *srv6map.VRFValue) {
			srv6VRFs[*key] = *val
		})

nextVRFKey:
	for vrfKey := range srv6VRFs {
		for _, vrf := range manager.vrfs {
			for _, vrfRule := range vrf.rules {
				for _, endpoint := range manager.epDataStore {
					if !vrfRule.selectsEndpoint(endpoint) {
						continue
					}

					for _, endpointIP := range endpoint.ips {
						for _, dstCIDR := range vrfRule.dstCIDRs {
							if ip.IsIPv6(endpointIP) != netutils.IsIPv6CIDR(dstCIDR) {
								// Endpoints can only connect to IPv6 destinations
								// with their IPv6 address.
								continue
							}
							if vrfKey.Match(endpointIP, dstCIDR) {
								continue nextVRFKey
							}
						}
					}
				}
			}
		}

		logger := log.WithFields(logrus.Fields{
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
// Whenever it encounters an error, it will just log it and move to the next
// item, in order to reconcile as many states as possible.
func (manager *Manager) reconcileVRFMappings() {
	if !manager.k8sCacheSyncedChecker.K8sCacheIsSynced() {
		return
	}

	manager.addMissingSRv6VRFMappings()
	manager.removeUnusedSRv6VRFMappings()
}
