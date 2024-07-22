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
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

type srv6LocatorPoolReconcilerIn struct {
	cell.In

	JobGroup     job.Group
	Logger       logrus.FieldLogger
	Signaler     *signaler.BGPCPSignaler
	DaemonConfig *option.DaemonConfig
	BGPConfig    config.Config

	Upgrader   paramUpgrader
	PeerAdvert *IsovalentAdvertisement

	SIDManagerPromise   promise.Promise[sidmanager.SIDManager]
	LocatorPoolResource resource.Resource[*v1alpha1.IsovalentSRv6LocatorPool]
}

type srv6LocatorPoolReconcilerOut struct {
	cell.Out

	Reconciler reconcilerv2.ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type LocatorPoolReconciler struct {
	initialized atomic.Bool
	logger      logrus.FieldLogger

	upgrader   paramUpgrader
	peerAdvert *IsovalentAdvertisement

	sidAllocators     map[string]sidmanager.SIDAllocator
	sidAllocatorsLock lock.RWMutex
	locatorPoolStore  resource.Store[*v1alpha1.IsovalentSRv6LocatorPool]
}

type LocatorPoolReconcilerMetadata struct {
	AFPaths       reconcilerv2.ResourceAFPathsMap
	RoutePolicies reconcilerv2.ResourceRoutePolicyMap
}

func NewSRv6LocatorPoolReconciler(params srv6LocatorPoolReconcilerIn) srv6LocatorPoolReconcilerOut {
	if !params.BGPConfig.Enabled || !params.DaemonConfig.EnableSRv6 {
		return srv6LocatorPoolReconcilerOut{}
	}

	r := &LocatorPoolReconciler{
		logger:        params.Logger,
		sidAllocators: make(map[string]sidmanager.SIDAllocator),
		upgrader:      params.Upgrader,
		peerAdvert:    params.PeerAdvert,
	}

	params.JobGroup.Add(
		job.OneShot("store-initializer", func(ctx context.Context, health cell.Health) error {
			// Wait for the initial sync of locator pool store
			lps, err := params.LocatorPoolResource.Store(ctx)
			if err != nil {
				return fmt.Errorf("failed to obtain IsovalentSRv6LocatorPool store: %w", err)
			}
			r.locatorPoolStore = lps

			// Now we can start reconciliation
			r.initialized.Store(true)

			// We may have some reconciliation missed during initialization
			params.Signaler.Event(struct{}{})

			return nil
		}),

		job.OneShot("sidmanager-subscriber", func(ctx context.Context, health cell.Health) error {
			// Wait for the initial sync of SIDManager
			sm, err := params.SIDManagerPromise.Await(ctx)
			if err != nil {
				return fmt.Errorf("failed to resolve SIDManager promise: %w", err)
			}

			for ev := range stream.ToChannel[sidmanager.Event](ctx, sm) {
				switch ev.Kind {
				case sidmanager.Sync:
				case sidmanager.Upsert:
					// We don't allocate any SIDs here, so
					// don't have to do anything on update.
					// Just update the local pool.
					r.sidAllocatorsLock.Lock()
					r.sidAllocators[ev.PoolName] = ev.Allocator
					r.sidAllocatorsLock.Unlock()
					params.Signaler.Event(struct{}{})
				case sidmanager.Delete:
					r.sidAllocatorsLock.Lock()
					delete(r.sidAllocators, ev.PoolName)
					r.sidAllocatorsLock.Unlock()
					params.Signaler.Event(struct{}{})
				}
			}

			return nil
		}),
	)

	return srv6LocatorPoolReconcilerOut{
		Reconciler: r,
	}
}

func (r *LocatorPoolReconciler) Priority() int {
	return 45
}

func (r *LocatorPoolReconciler) Name() string {
	return "LocatorPool"
}

func (r *LocatorPoolReconciler) Reconcile(ctx context.Context, p reconcilerv2.ReconcileParams) error {
	if !r.initialized.Load() {
		// Still waiting for some dependencies to be initialized. Skip this reconciliation.
		r.logger.Debug("Initialization is not done. Skipping reconciliation.")
		return nil
	}

	iParams, err := r.upgrader.upgrade(p)
	if err != nil {
		return err
	}

	// get per peer per family locator pool advertisements
	desiredPeerAdverts, err := r.peerAdvert.GetConfiguredPeerAdvertisements(iParams.DesiredConfig, v1alpha1.BGPSRv6LocatorPoolAdvert)
	if err != nil {
		return err
	}

	// reconcile route policies
	if err = r.reconcileRoutePolicies(ctx, iParams, desiredPeerAdverts); err != nil {
		return err
	}

	// reconcile paths to advertise
	return r.reconcilePaths(ctx, iParams, desiredPeerAdverts)
}

func (r *LocatorPoolReconciler) reconcilePaths(ctx context.Context, params EnterpriseReconcileParams, desiredFamilyAdverts PeerAdvertisements) error {
	desiredAFPaths, err := r.getDesiredPaths(desiredFamilyAdverts)
	if err != nil {
		return err
	}

	metadata := r.getMetadata(params.BGPInstance)

	// mark policies for deletion
	for key := range metadata.AFPaths {
		if _, exists := desiredAFPaths[key]; !exists {
			desiredAFPaths[key] = nil
		}
	}

	for key, paths := range desiredAFPaths {
		currentPaths, exists := metadata.AFPaths[key]
		if !exists && len(paths) == 0 {
			continue
		}

		updatedAFPaths, rErr := reconcilerv2.ReconcileAFPaths(&reconcilerv2.ReconcileAFPathsParams{
			Logger: r.logger.WithFields(
				logrus.Fields{
					types.InstanceLogField:       params.DesiredConfig.Name,
					entTypes.LocatorPoolLogField: key,
				}),
			Ctx:          ctx,
			Router:       params.BGPInstance.Router,
			DesiredPaths: paths,
			CurrentPaths: currentPaths,
		})
		if rErr == nil && len(paths) == 0 {
			delete(metadata.AFPaths, key)
		} else {
			metadata.AFPaths[key] = updatedAFPaths
		}
		err = errors.Join(err, rErr)
	}

	r.setMetadata(params.BGPInstance, metadata)
	return err
}

func (r *LocatorPoolReconciler) reconcileRoutePolicies(ctx context.Context, params EnterpriseReconcileParams, desiredFamilyAdverts PeerAdvertisements) error {
	desiredRoutePolicies, err := r.getDesiredRoutePolicies(params, desiredFamilyAdverts)
	if err != nil {
		return err
	}

	metadata := r.getMetadata(params.BGPInstance)

	// mark policies for deletion
	for key := range metadata.RoutePolicies {
		if _, exists := desiredRoutePolicies[key]; !exists {
			desiredRoutePolicies[key] = nil
		}
	}

	for key, policies := range desiredRoutePolicies {
		currentPolicies, exists := metadata.RoutePolicies[key]
		if !exists && len(policies) == 0 {
			continue
		}

		updatedRoutePolicies, rErr := reconcilerv2.ReconcileRoutePolicies(&reconcilerv2.ReconcileRoutePoliciesParams{
			Logger: r.logger.WithFields(
				logrus.Fields{
					types.InstanceLogField:       params.DesiredConfig.Name,
					entTypes.LocatorPoolLogField: key,
				}),
			Ctx:             ctx,
			Router:          params.BGPInstance.Router,
			DesiredPolicies: policies,
			CurrentPolicies: currentPolicies,
		})
		if rErr == nil && len(policies) == 0 {
			delete(metadata.RoutePolicies, key)
		} else {
			metadata.RoutePolicies[key] = updatedRoutePolicies
		}
		err = errors.Join(err, rErr)
	}

	r.setMetadata(params.BGPInstance, metadata)
	return err
}

// getDesiredPaths returns the desired SRv6 locator pool paths per locator pool.
// The desired paths are calculated based on the BGP advertisements of type BGPSRv6LocatorPoolAdvert
// and its selector for the locator pool.
func (r *LocatorPoolReconciler) getDesiredPaths(desiredFamilyAdverts PeerAdvertisements) (reconcilerv2.ResourceAFPathsMap, error) {
	desiredResourceAFPaths := make(reconcilerv2.ResourceAFPathsMap)

	for _, peerFamilyAdverts := range desiredFamilyAdverts {
		for family, familyAdverts := range peerFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)
			if agentFamily.Afi != types.AfiIPv6 {
				r.logger.WithFields(logrus.Fields{
					types.FamilyLogField:     agentFamily.Afi,
					types.AdvertTypeLogField: v1alpha1.BGPSRv6LocatorPoolAdvert,
				}).Warning("Invalid address family for this advertisement type, skipping")
				continue
			}
			for _, advert := range familyAdverts {
				// sanity check
				if advert.AdvertisementType != v1alpha1.BGPSRv6LocatorPoolAdvert {
					r.logger.WithField(types.AdvertTypeLogField, advert.AdvertisementType).Error("BUG: unexpected advertisement type")
					continue
				}
				if advert.Selector == nil {
					continue
				}
				selector, err := slim_metav1.LabelSelectorAsSelector(advert.Selector)
				if err != nil {
					return nil, err
				}
				for _, lp := range r.locatorPoolStore.List() {
					if !selector.Matches(labels.Set(lp.Labels)) {
						continue
					}

					r.sidAllocatorsLock.RLock()
					allocator, found := r.sidAllocators[lp.Name]
					if !found {
						// Allocator is not yet ready. Skip this locator pool.
						r.sidAllocatorsLock.RUnlock()
						continue
					}
					r.sidAllocatorsLock.RUnlock()

					desiredLPAFPaths := make(reconcilerv2.AFPathsMap)
					path := types.NewPathForPrefix(allocator.Locator().Prefix)
					path.Family = agentFamily
					reconcilerv2.AddPathToAFPathsMap(desiredLPAFPaths, agentFamily, path, path.NLRI.String())

					desiredResourceAFPaths[resource.Key{Name: lp.Name}] = desiredLPAFPaths
				}
			}
		}
	}

	return desiredResourceAFPaths, nil
}

// getDesiredRoutePolicies returns the desired BGP route policies per locator pool.
// The desired route policies are calculated based on the BGP advertisements of type BGPSRv6LocatorPoolAdvert,
// its selector for the locator pool, and the peer address.
func (r *LocatorPoolReconciler) getDesiredRoutePolicies(params EnterpriseReconcileParams, desiredFamilyAdverts PeerAdvertisements) (reconcilerv2.ResourceRoutePolicyMap, error) {
	desiredRoutePolicies := make(reconcilerv2.ResourceRoutePolicyMap)

	for peer, peerFamilyAdverts := range desiredFamilyAdverts {
		peerAddr, err := GetPeerAddressFromConfig(params.DesiredConfig, peer)
		if err != nil {
			return nil, fmt.Errorf("failed to get peer address: %w", err)
		}

		for family, familyAdverts := range peerFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)
			if agentFamily.Afi != types.AfiIPv6 {
				r.logger.WithFields(logrus.Fields{
					types.FamilyLogField:     agentFamily.Afi,
					types.AdvertTypeLogField: v1alpha1.BGPSRv6LocatorPoolAdvert,
				}).Warning("Invalid address family for this advertisement type, skipping")
				continue
			}
			for _, advert := range familyAdverts {
				// sanity check
				if advert.AdvertisementType != v1alpha1.BGPSRv6LocatorPoolAdvert {
					r.logger.WithField(types.AdvertTypeLogField, advert.AdvertisementType).Error("BUG: unexpected advertisement type")
					continue
				}
				if advert.Selector == nil {
					continue
				}
				selector, err := slim_metav1.LabelSelectorAsSelector(advert.Selector)
				if err != nil {
					return nil, err
				}
				for _, lp := range r.locatorPoolStore.List() {
					if !selector.Matches(labels.Set(lp.Labels)) {
						continue
					}

					r.sidAllocatorsLock.RLock()
					allocator, found := r.sidAllocators[lp.Name]
					if !found {
						// Allocator is not yet ready. Skip this locator pool.
						r.sidAllocatorsLock.RUnlock()
						continue
					}
					r.sidAllocatorsLock.RUnlock()

					prefixMatch := &types.RoutePolicyPrefixMatch{
						CIDR:         allocator.Locator().Prefix,
						PrefixLenMin: allocator.Locator().Prefix.Bits(),
						PrefixLenMax: allocator.Locator().Prefix.Bits(),
					}

					policyName := PolicyName(peer, agentFamily.Afi.String(), advert.AdvertisementType, lp.Name)
					policy, err := reconcilerv2.CreatePolicy(policyName, peerAddr, nil,
						types.PolicyPrefixMatchList{prefixMatch}, v2alpha1.BGPAdvertisement{
							Attributes: advert.Attributes,
						})
					if err != nil {
						return nil, fmt.Errorf("failed to create locator pool route policy: %w", err)
					}

					desiredRoutePolicies[resource.Key{Name: lp.Name}] = reconcilerv2.RoutePolicyMap{policyName: policy}
				}
			}
		}
	}

	return desiredRoutePolicies, nil
}

func (r *LocatorPoolReconciler) getMetadata(i *EnterpriseBGPInstance) LocatorPoolReconcilerMetadata {
	if _, found := i.Metadata[r.Name()]; !found {
		i.Metadata[r.Name()] = LocatorPoolReconcilerMetadata{
			AFPaths:       make(reconcilerv2.ResourceAFPathsMap),
			RoutePolicies: make(reconcilerv2.ResourceRoutePolicyMap),
		}
	}
	return i.Metadata[r.Name()].(LocatorPoolReconcilerMetadata)
}

func (r *LocatorPoolReconciler) setMetadata(i *EnterpriseBGPInstance, metadata LocatorPoolReconcilerMetadata) {
	i.Metadata[r.Name()] = metadata
}
