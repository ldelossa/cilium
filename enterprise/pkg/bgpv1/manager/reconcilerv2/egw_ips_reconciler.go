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
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	entTypes "github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
)

type egwIPsProvider interface {
	AdvertisedEgressIPs(policySelector *slimv1.LabelSelector) (map[k8stypes.NamespacedName][]netip.Addr, error)
}

type EGWIPsReconcilerIn struct {
	cell.In

	Logger       logrus.FieldLogger
	BGPConfig    config.Config
	DaemonConfig *option.DaemonConfig
	EGWManager   *egressgatewayha.Manager
	Upgrader     paramUpgrader
	PeerAdvert   *IsovalentAdvertisement
}

type EGWIPsReconcilerOut struct {
	cell.Out

	Reconciler reconcilerv2.ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

func NewEgressGatewayIPsReconciler(params EGWIPsReconcilerIn) EGWIPsReconcilerOut {
	if !params.BGPConfig.Enabled || !params.DaemonConfig.EnableIPv4EgressGatewayHA {
		return EGWIPsReconcilerOut{}
	}

	return EGWIPsReconcilerOut{
		Reconciler: &EgressGatewayIPsReconciler{
			logger:         params.Logger,
			egwIPsProvider: params.EGWManager,
			upgrader:       params.Upgrader,
			peerAdvert:     params.PeerAdvert,
		},
	}
}

type EgressGatewayIPsReconciler struct {
	logger         logrus.FieldLogger
	egwIPsProvider egwIPsProvider
	upgrader       paramUpgrader
	peerAdvert     *IsovalentAdvertisement
}

type EgressGatewayIPsMetadata struct {
	EGWAFPaths       reconcilerv2.ResourceAFPathsMap
	EGWRoutePolicies reconcilerv2.ResourceRoutePolicyMap
}

func (r *EgressGatewayIPsReconciler) Priority() int {
	return 55
}

func (r *EgressGatewayIPsReconciler) Name() string {
	return "EgressGatewayIPs"
}

func (r *EgressGatewayIPsReconciler) Reconcile(ctx context.Context, p reconcilerv2.ReconcileParams) error {
	iParams, err := r.upgrader.upgrade(p)
	if err != nil {
		return err
	}

	// get per peer per family egw advertisements
	desiredPeerAdverts, err := r.peerAdvert.GetConfiguredPeerAdvertisements(iParams.DesiredConfig, v1alpha1.BGPEGWAdvert)
	if err != nil {
		return err
	}

	// reconcile route policies
	if err = r.reconcileRoutePolicies(ctx, iParams, desiredPeerAdverts); err != nil {
		return err
	}

	return r.reconcilePaths(ctx, iParams, desiredPeerAdverts)
}

func (r *EgressGatewayIPsReconciler) reconcilePaths(ctx context.Context, params EnterpriseReconcileParams, desiredFamilyAdverts PeerAdvertisements) error {
	egwAFPaths, err := r.getDesiredEGWAFPaths(desiredFamilyAdverts)
	if err != nil {
		return err
	}

	metadata := r.getMetadata(params.BGPInstance)

	// mark policies for deletion
	for key := range metadata.EGWAFPaths {
		if _, exists := egwAFPaths[key]; !exists {
			egwAFPaths[key] = nil
		}
	}

	for key, paths := range egwAFPaths {
		currentPaths, exists := metadata.EGWAFPaths[key]
		if !exists && len(paths) == 0 {
			continue
		}

		updatedAFPaths, rErr := reconcilerv2.ReconcileAFPaths(&reconcilerv2.ReconcileAFPathsParams{
			Logger: r.logger.WithFields(
				logrus.Fields{
					types.InstanceLogField:         params.DesiredConfig.Name,
					entTypes.EgressGatewayLogField: key,
				}),
			Ctx:          ctx,
			Router:       params.BGPInstance.Router,
			DesiredPaths: paths,
			CurrentPaths: currentPaths,
		})
		if rErr == nil && len(paths) == 0 {
			delete(metadata.EGWAFPaths, key)
		} else {
			metadata.EGWAFPaths[key] = updatedAFPaths
		}
		err = errors.Join(err, rErr)
	}

	r.setMetadata(params.BGPInstance, metadata)
	return err
}

func (r *EgressGatewayIPsReconciler) reconcileRoutePolicies(ctx context.Context, params EnterpriseReconcileParams, desiredFamilyAdverts PeerAdvertisements) error {
	desiredRoutePolicies, err := r.getDesiredEGWRoutePolicies(params, desiredFamilyAdverts)
	if err != nil {
		return err
	}

	metadata := r.getMetadata(params.BGPInstance)

	// mark policies for deletion
	for key := range metadata.EGWRoutePolicies {
		if _, exists := desiredRoutePolicies[key]; !exists {
			desiredRoutePolicies[key] = nil
		}
	}

	for key, policies := range desiredRoutePolicies {
		currentPolicies, exists := metadata.EGWRoutePolicies[key]
		if !exists && len(policies) == 0 {
			continue
		}

		updatedRoutePolicies, rErr := reconcilerv2.ReconcileRoutePolicies(&reconcilerv2.ReconcileRoutePoliciesParams{
			Logger: r.logger.WithFields(
				logrus.Fields{
					types.InstanceLogField:         params.DesiredConfig.Name,
					entTypes.EgressGatewayLogField: key,
				}),
			Ctx:             ctx,
			Router:          params.BGPInstance.Router,
			DesiredPolicies: policies,
			CurrentPolicies: currentPolicies,
		})
		if rErr == nil && len(policies) == 0 {
			delete(metadata.EGWRoutePolicies, key)
		} else {
			metadata.EGWRoutePolicies[key] = updatedRoutePolicies
		}
		err = errors.Join(err, rErr)
	}

	r.setMetadata(params.BGPInstance, metadata)
	return err
}

// getDesiredEGWAFPaths returns the desired egress gateway paths per family per egress policy. The desired paths are calculated based on the
// BGP advertisements of type BGPEGWAdvert. Advertisement contains a label selector for the egress gateway policy. We
// call EGWManager with the selector field to get the egress gateway IPs present on the node. The desired paths are created
// based on the returned IPs. Exact match /32 paths are created for each IP.
func (r *EgressGatewayIPsReconciler) getDesiredEGWAFPaths(desiredFamilyAdverts PeerAdvertisements) (reconcilerv2.ResourceAFPathsMap, error) {
	desiredEGWResourceAFPaths := make(reconcilerv2.ResourceAFPathsMap)

	for _, egwFamilyAdverts := range desiredFamilyAdverts {
		for family, familyAdverts := range egwFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)

			for _, advert := range familyAdverts {
				// sanity check
				if advert.AdvertisementType != v1alpha1.BGPEGWAdvert {
					r.logger.WithField(types.AdvertTypeLogField, advert.AdvertisementType).Error("BUG: unexpected advertisement type")
					continue
				}

				egwPolicyResult, err := r.egwIPsProvider.AdvertisedEgressIPs(advert.Selector)
				if err != nil {
					r.logger.WithError(err).Error("failed to get egress gateway IPs")
					continue
				}

				for egwID, egwIPs := range egwPolicyResult {
					desiredEGWAFPaths := make(reconcilerv2.AFPathsMap)

					for _, egwIP := range egwIPs {
						switch {
						case agentFamily.Afi == types.AfiIPv4 && egwIP.Is4():
							path := types.NewPathForPrefix(netip.PrefixFrom(egwIP, egwIP.BitLen()))
							path.Family = agentFamily
							reconcilerv2.AddPathToAFPathsMap(desiredEGWAFPaths, agentFamily, path, path.NLRI.String())

						case agentFamily.Afi == types.AfiIPv6 && egwIP.Is6():
							path := types.NewPathForPrefix(netip.PrefixFrom(egwIP, egwIP.BitLen()))
							path.Family = agentFamily
							reconcilerv2.AddPathToAFPathsMap(desiredEGWAFPaths, agentFamily, path, path.NLRI.String())

						default:
							r.logger.WithField("IP", egwIP.String()).Error("invalid egress gateway IP")
							continue
						}
					}

					desiredEGWResourceAFPaths[resource.Key{
						Name:      egwID.Name,
						Namespace: egwID.Namespace,
					}] = desiredEGWAFPaths
				}
			}
		}
	}

	return desiredEGWResourceAFPaths, nil
}

// getDesiredEGWRoutePolicies returns the desired bgp route policies per egress policy. Similar to
// getDesiredEGWAFPaths, the desired route policies are calculated based on the BGP advertisements of type BGPEGWAdvert
// and selector field. Route policy is created based on BGP attributes present in BGP advertisement and peer/prefix calculated
// from advertisement and egress gateway IPs.
func (r *EgressGatewayIPsReconciler) getDesiredEGWRoutePolicies(params EnterpriseReconcileParams, desiredFamilyAdverts PeerAdvertisements) (reconcilerv2.ResourceRoutePolicyMap, error) {
	desiredRoutePolicies := make(reconcilerv2.ResourceRoutePolicyMap)

	for peer, egwFamilyAdverts := range desiredFamilyAdverts {
		peerAddr, err := GetPeerAddressFromConfig(params.DesiredConfig, peer)
		if err != nil {
			return nil, fmt.Errorf("failed to get peer address: %w", err)
		}

		for family, familyAdverts := range egwFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)

			for _, advert := range familyAdverts {
				// sanity check
				if advert.AdvertisementType != v1alpha1.BGPEGWAdvert {
					r.logger.WithField(types.AdvertTypeLogField, advert.AdvertisementType).Error("BUG: unexpected advertisement type")
					continue
				}

				egwPolicyResult, err := r.egwIPsProvider.AdvertisedEgressIPs(advert.Selector)
				if err != nil {
					r.logger.WithError(err).Error("failed to get egress gateway IPs")
					continue
				}

				for egwID, egwIPs := range egwPolicyResult {
					var v4Prefixes, v6Prefixes types.PolicyPrefixMatchList
					for _, egwIP := range egwIPs {
						switch {
						case agentFamily.Afi == types.AfiIPv4 && egwIP.Is4():
							v4Prefixes = append(v4Prefixes, &types.RoutePolicyPrefixMatch{
								CIDR:         netip.PrefixFrom(egwIP, egwIP.BitLen()),
								PrefixLenMin: egwIP.BitLen(),
								PrefixLenMax: egwIP.BitLen(),
							})

						case agentFamily.Afi == types.AfiIPv6 && egwIP.Is6():
							v6Prefixes = append(v6Prefixes, &types.RoutePolicyPrefixMatch{
								CIDR:         netip.PrefixFrom(egwIP, egwIP.BitLen()),
								PrefixLenMin: egwIP.BitLen(),
								PrefixLenMax: egwIP.BitLen(),
							})

						default:
							r.logger.WithField("IP", egwIP.String()).Error("invalid egress gateway IP")
							continue
						}
					}

					if len(v4Prefixes) == 0 && len(v6Prefixes) == 0 {
						continue
					}

					policyName := PolicyName(peer, agentFamily.Afi.String(), v1alpha1.BGPEGWAdvert, egwID.Name)
					policy, err := reconcilerv2.CreatePolicy(policyName, peerAddr, v4Prefixes, v6Prefixes, v2alpha1.BGPAdvertisement{
						Attributes: advert.Attributes,
					})
					if err != nil {
						return nil, fmt.Errorf("failed to create egress gateway route policy: %w", err)
					}

					// in this case there is 1-1 mapping between route policy and egress gateway policy
					desiredRoutePolicies[resource.Key{
						Name:      egwID.Name,
						Namespace: egwID.Namespace,
					}] = reconcilerv2.RoutePolicyMap{
						policyName: policy,
					}
				}
			}
		}
	}

	return desiredRoutePolicies, nil
}

func (r *EgressGatewayIPsReconciler) getMetadata(i *EnterpriseBGPInstance) EgressGatewayIPsMetadata {
	if _, found := i.Metadata[r.Name()]; !found {
		i.Metadata[r.Name()] = EgressGatewayIPsMetadata{
			EGWAFPaths:       make(reconcilerv2.ResourceAFPathsMap),
			EGWRoutePolicies: make(reconcilerv2.ResourceRoutePolicyMap),
		}
	}
	return i.Metadata[r.Name()].(EgressGatewayIPsMetadata)
}

func (r *EgressGatewayIPsReconciler) setMetadata(i *EnterpriseBGPInstance, metadata EgressGatewayIPsMetadata) {
	i.Metadata[r.Name()] = metadata
}
