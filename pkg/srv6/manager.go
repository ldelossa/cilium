// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6

import (
	"time"

	"github.com/sirupsen/logrus"

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
}

// NewSRv6Manager returns a new SRv6 policy manager.
func NewSRv6Manager(k8sCacheSyncedChecker k8sCacheSyncedChecker) *Manager {
	manager := &Manager{
		k8sCacheSyncedChecker: k8sCacheSyncedChecker,
		policies:              make(map[policyID]*EgressPolicy),
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
	// Same note as above on the order of the next two function calls.
	manager.addMissingSRv6SIDs()
	manager.removeUnusedSRv6SIDs()
}
