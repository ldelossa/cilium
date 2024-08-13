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

type ImportRoutePolicyReconcilerOut struct {
	cell.Out

	Reconciler reconcilerv2.ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type ImportRoutePolicyReconcilerIn struct {
	cell.In

	Logger          logrus.FieldLogger
	Config          config.Config
	PeerConfigStore resource.Resource[*v2alpha1.CiliumBGPPeerConfig]
	Group           job.Group
}

// ImportRoutePolicyReconciler is a reconciler that configures import route policies.
// This is per peer policy to allow routes from adj-in to loc-rib.
type ImportRoutePolicyReconciler struct {
	initialized     atomic.Bool
	Logger          logrus.FieldLogger
	PeerConfigStore resource.Store[*v2alpha1.CiliumBGPPeerConfig]
}

type ImportRoutePolicyMetadata struct {
	ImportPolicies reconcilerv2.RoutePolicyMap
}

func NewImportRoutePolicyReconciler(in ImportRoutePolicyReconcilerIn) ImportRoutePolicyReconcilerOut {
	if !in.Config.Enabled {
		return ImportRoutePolicyReconcilerOut{}
	}

	rp := &ImportRoutePolicyReconciler{
		Logger: in.Logger.WithField(types.ReconcilerLogField, "import-route-policy"),
	}

	in.Group.Add(job.OneShot("init-import-route-policy", func(ctx context.Context, health cell.Health) error {
		pcs, err := in.PeerConfigStore.Store(ctx)
		if err != nil {
			return err
		}

		rp.PeerConfigStore = pcs
		rp.initialized.Store(true)
		return nil
	}))

	return ImportRoutePolicyReconcilerOut{
		Reconciler: rp,
	}
}

func (r *ImportRoutePolicyReconciler) Name() string {
	return "import-route-policy"
}

func (r *ImportRoutePolicyReconciler) Priority() int {
	// This reconciler should run just before the OSS Neighbor reconciler,
	// so gobgp will already have desired import policies in place.
	return 59
}

func (r *ImportRoutePolicyReconciler) Init(_ *instance.BGPInstance) error {
	return nil
}

func (r *ImportRoutePolicyReconciler) Cleanup(_ *instance.BGPInstance) {}

func (r *ImportRoutePolicyReconciler) Reconcile(ctx context.Context, p reconcilerv2.ReconcileParams) error {
	if !r.initialized.Load() {
		r.Logger.Debug("Not initialized yet, skipping import route policy reconciliation")
		return nil
	}

	if p.DesiredConfig == nil {
		return fmt.Errorf("BUG: passed nil desired config to import route policy reconciler")
	}

	desiredPolicies, err := r.getDesiredRoutePolicies(p.DesiredConfig)
	if err != nil {
		return err
	}

	updatedImportPolicies, err := reconcilerv2.ReconcileRoutePolicies(&reconcilerv2.ReconcileRoutePoliciesParams{
		Logger: r.Logger.WithFields(
			logrus.Fields{
				types.InstanceLogField: p.DesiredConfig.Name,
			},
		),
		Ctx:             ctx,
		Router:          p.BGPInstance.Router,
		DesiredPolicies: desiredPolicies,
		CurrentPolicies: r.GetMetadata(p.BGPInstance).ImportPolicies,
	})

	r.SetMetadata(p.BGPInstance, ImportRoutePolicyMetadata{
		ImportPolicies: updatedImportPolicies,
	})

	return err
}

func (r *ImportRoutePolicyReconciler) getDesiredRoutePolicies(desiredConfig *v2alpha1.CiliumBGPNodeInstance) (reconcilerv2.RoutePolicyMap, error) {
	desiredImportPolicies := make(reconcilerv2.RoutePolicyMap)

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
			policyName := fmt.Sprintf("%s-%s", r.Name(), peer.Name) // each policy is unique per peer
			desiredImportPolicies[policyName] = CreateImportAcceptRoutePolicy(policyName, peerAddr)
		}
	}
	return desiredImportPolicies, nil
}

// TODO: Create route policy which checks AFI/SAFI of the peer.
func CreateImportAcceptRoutePolicy(name string, peerAddr netip.Addr) *types.RoutePolicy {
	// create /32 or /128 prefix from peer address
	peerPrefix := netip.PrefixFrom(peerAddr, peerAddr.BitLen())

	return &types.RoutePolicy{
		Name: name,
		Type: types.RoutePolicyTypeImport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{peerPrefix.String()},
				},
				Actions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				},
			},
		},
	}
}

func (r *ImportRoutePolicyReconciler) GetMetadata(i *instance.BGPInstance) ImportRoutePolicyMetadata {
	if _, found := i.Metadata[r.Name()]; !found {
		i.Metadata[r.Name()] = ImportRoutePolicyMetadata{
			ImportPolicies: make(reconcilerv2.RoutePolicyMap),
		}
	}
	return i.Metadata[r.Name()].(ImportRoutePolicyMetadata)
}

func (r *ImportRoutePolicyReconciler) SetMetadata(i *instance.BGPInstance, m ImportRoutePolicyMetadata) {
	i.Metadata[r.Name()] = m
}
