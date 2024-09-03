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
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

type VPNRoutePolicyReconcilerOut struct {
	cell.Out

	Reconciler reconcilerv2.ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type VPNRoutePolicyReconcilerIn struct {
	cell.In

	Logger          logrus.FieldLogger
	Config          config.Config
	PeerConfigStore resource.Resource[*v2alpha1.CiliumBGPPeerConfig]
	Group           job.Group
}

// VPNRoutePolicyReconciler is a reconciler that configures VPNv4 related route policies:
//   - import route policy per peer allowing VPNv4 routes from adj-in to loc-rib.
//   - export route policy per peer allowing VPNv4 routes from loc-rib to adj-out.
type VPNRoutePolicyReconciler struct {
	initialized     atomic.Bool
	Logger          logrus.FieldLogger
	PeerConfigStore resource.Store[*v2alpha1.CiliumBGPPeerConfig]
}

type VPNRoutePolicyMetadata struct {
	VPNPolicies reconcilerv2.RoutePolicyMap
}

func NewVPNRoutePolicyReconciler(in VPNRoutePolicyReconcilerIn) VPNRoutePolicyReconcilerOut {
	if !in.Config.Enabled {
		return VPNRoutePolicyReconcilerOut{}
	}

	rp := &VPNRoutePolicyReconciler{
		Logger: in.Logger.WithField(types.ReconcilerLogField, "vpn-route-policy"),
	}

	in.Group.Add(job.OneShot("init-vpn-route-policy", func(ctx context.Context, health cell.Health) error {
		pcs, err := in.PeerConfigStore.Store(ctx)
		if err != nil {
			return err
		}

		rp.PeerConfigStore = pcs
		rp.initialized.Store(true)
		return nil
	}))

	return VPNRoutePolicyReconcilerOut{
		Reconciler: rp,
	}
}

func (r *VPNRoutePolicyReconciler) Name() string {
	return "vpn-route-policy"
}

func (r *VPNRoutePolicyReconciler) Priority() int {
	// This reconciler should run just before the OSS Neighbor reconciler,
	// so gobgp will already have desired VPN policies in place.
	return 59
}

func (r *VPNRoutePolicyReconciler) Init(_ *instance.BGPInstance) error {
	return nil
}

func (r *VPNRoutePolicyReconciler) Cleanup(_ *instance.BGPInstance) {}

func (r *VPNRoutePolicyReconciler) Reconcile(ctx context.Context, p reconcilerv2.ReconcileParams) error {
	if !r.initialized.Load() {
		r.Logger.Debug("Not initialized yet, skipping VPN route policy reconciliation")
		return nil
	}

	if p.DesiredConfig == nil {
		return fmt.Errorf("BUG: passed nil desired config to VPN route policy reconciler")
	}

	desiredPolicies, err := r.getDesiredRoutePolicies(p.DesiredConfig)
	if err != nil {
		return err
	}

	updatedPolicies, err := reconcilerv2.ReconcileRoutePolicies(&reconcilerv2.ReconcileRoutePoliciesParams{
		Logger: r.Logger.WithFields(
			logrus.Fields{
				types.InstanceLogField: p.DesiredConfig.Name,
			},
		),
		Ctx:             ctx,
		Router:          p.BGPInstance.Router,
		DesiredPolicies: desiredPolicies,
		CurrentPolicies: r.GetMetadata(p.BGPInstance).VPNPolicies,
	})

	r.SetMetadata(p.BGPInstance, VPNRoutePolicyMetadata{
		VPNPolicies: updatedPolicies,
	})

	return err
}

func (r *VPNRoutePolicyReconciler) getDesiredRoutePolicies(desiredConfig *v2alpha1.CiliumBGPNodeInstance) (reconcilerv2.RoutePolicyMap, error) {
	desiredPolicies := make(reconcilerv2.RoutePolicyMap)

	for _, peer := range desiredConfig.Peers {
		// get peer address
		peerAddr, err := reconcilerv2.GetPeerAddressFromConfig(desiredConfig, peer.Name)
		if err != nil {
			return nil, err
		}

		// get the peer config
		if peer.PeerConfigRef == nil {
			r.Logger.WithField(types.PeerLogField, peer.Name).Debug("Peer config reference not set, skipping peer for import policy inspection")
			continue
		}

		peerConfig, exists, err := r.PeerConfigStore.GetByKey(resource.Key{Name: peer.PeerConfigRef.Name})
		if err != nil {
			return nil, err
		}

		if !exists {
			r.Logger.WithField(types.PeerLogField, peer.Name).Debug("Peer config not found, skipping peer for import policy inspection")
			continue
		}

		// allow importing routes from peers which have ipv4-l3vpn family configured
		vpnPeer := false
		for _, fam := range peerConfig.Spec.Families {
			agentFamily := types.ToAgentFamily(fam.CiliumBGPFamily)
			if agentFamily.Afi == types.AfiIPv4 && agentFamily.Safi == types.SafiMplsVpn {
				vpnPeer = true
				break
			}
		}

		if vpnPeer {
			// import route policy allowing VPNv4 routes from adj-in to loc-rib
			importPolicyName := fmt.Sprintf("%s-import-%s", r.Name(), peer.Name)
			desiredPolicies[importPolicyName] = acceptRoutePolicy(types.RoutePolicyTypeImport, importPolicyName, peerAddr)

			// export route policy allowing all VPNv4 routes from  loc-rib to adj-out
			exportPolicyName := fmt.Sprintf("%s-export-%s", r.Name(), peer.Name)
			desiredPolicies[exportPolicyName] = acceptRoutePolicy(types.RoutePolicyTypeExport, exportPolicyName, peerAddr)
		}
	}

	return desiredPolicies, nil
}

func acceptRoutePolicy(policyType types.RoutePolicyType, name string, peerAddr netip.Addr) *types.RoutePolicy {
	// create /32 or /128 prefix from peer address
	peerPrefix := netip.PrefixFrom(peerAddr, peerAddr.BitLen())

	return &types.RoutePolicy{
		Name: name,
		Type: policyType,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{peerPrefix.String()},
					MatchFamilies: []types.Family{
						{
							Afi:  types.AfiIPv4,
							Safi: types.SafiMplsVpn,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				},
			},
		},
	}
}

func (r *VPNRoutePolicyReconciler) GetMetadata(i *instance.BGPInstance) VPNRoutePolicyMetadata {
	if _, found := i.Metadata[r.Name()]; !found {
		i.Metadata[r.Name()] = VPNRoutePolicyMetadata{
			VPNPolicies: make(reconcilerv2.RoutePolicyMap),
		}
	}
	return i.Metadata[r.Name()].(VPNRoutePolicyMetadata)
}

func (r *VPNRoutePolicyReconciler) SetMetadata(i *instance.BGPInstance, m VPNRoutePolicyMetadata) {
	i.Metadata[r.Name()] = m
}
