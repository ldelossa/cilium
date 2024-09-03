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
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

var (
	peerConfigIPv4Unicast = &v2alpha1.CiliumBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-ipv4-unicast",
		},
		Spec: v2alpha1.CiliumBGPPeerConfigSpec{
			Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "unicast",
					},
				},
			},
		},
	}

	peerConfigIPv4VPN = &v2alpha1.CiliumBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config-ipv4-mpls_vpn",
		},
		Spec: v2alpha1.CiliumBGPPeerConfigSpec{
			Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "mpls_vpn",
					},
				},
			},
		},
	}

	expectedPeerRoutePolicy = func(policyType types.RoutePolicyType, name, peerAddr string) *types.RoutePolicy {
		return &types.RoutePolicy{
			Name: name,
			Type: policyType,
			Statements: []*types.RoutePolicyStatement{
				{
					Conditions: types.RoutePolicyConditions{
						MatchNeighbors: []string{peerAddr},
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

	importPeerPolicy = expectedPeerRoutePolicy(
		types.RoutePolicyTypeImport,
		"vpn-route-policy-import-red-peer-65001",
		"192.168.0.10/32",
	)

	exportPeerPolicy = expectedPeerRoutePolicy(
		types.RoutePolicyTypeExport,
		"vpn-route-policy-export-red-peer-65001",
		"192.168.0.10/32",
	)
)

func TestVPNRoutePolicy(t *testing.T) {
	logger = logrus.WithField("unit_test", "reconcilerv2_vpn_route_policy_test")

	logrus.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name                string
		preRPs              reconcilerv2.RoutePolicyMap
		peerConfigs         []*v2alpha1.CiliumBGPPeerConfig
		testBGPNodeInstance *v2alpha1.CiliumBGPNodeInstance
		expectedRPs         reconcilerv2.RoutePolicyMap
	}{
		{
			name:        "ipv4-unicast peer, no policy",
			preRPs:      nil,
			peerConfigs: []*v2alpha1.CiliumBGPPeerConfig{peerConfigIPv4Unicast},
			testBGPNodeInstance: &v2alpha1.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2alpha1.CiliumBGPNodePeer{
					{
						Name:        "red-peer-65001",
						PeerAddress: ptr.To[string]("192.168.0.10"),
						PeerConfigRef: &v2alpha1.PeerConfigReference{
							Name: "peer-config-ipv4-unicast",
						},
					},
				},
			},
			expectedRPs: make(reconcilerv2.RoutePolicyMap),
		},
		{
			name:        "ipv4-vpn peer, policies applied",
			preRPs:      nil,
			peerConfigs: []*v2alpha1.CiliumBGPPeerConfig{peerConfigIPv4VPN},
			testBGPNodeInstance: &v2alpha1.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2alpha1.CiliumBGPNodePeer{
					{
						Name:        "red-peer-65001",
						PeerAddress: ptr.To[string]("192.168.0.10"),
						PeerConfigRef: &v2alpha1.PeerConfigReference{
							Name: "peer-config-ipv4-mpls_vpn",
						},
					},
				},
			},
			expectedRPs: reconcilerv2.RoutePolicyMap{
				importPeerPolicy.Name: importPeerPolicy,
				exportPeerPolicy.Name: exportPeerPolicy,
			},
		},
		{
			name: "ipv4-unicast peer, cleanup old policies",
			preRPs: reconcilerv2.RoutePolicyMap{
				importPeerPolicy.Name: importPeerPolicy,
				exportPeerPolicy.Name: exportPeerPolicy,
			},
			peerConfigs: []*v2alpha1.CiliumBGPPeerConfig{peerConfigIPv4Unicast},
			testBGPNodeInstance: &v2alpha1.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2alpha1.CiliumBGPNodePeer{
					{
						Name:        "red-peer-65001",
						PeerAddress: ptr.To[string]("192.168.0.10"),
						PeerConfigRef: &v2alpha1.PeerConfigReference{
							Name: "peer-config-ipv4-unicast",
						},
					},
				},
			},
			expectedRPs: make(reconcilerv2.RoutePolicyMap),
		},
		{
			name: "no peer found, cleanup old policies",
			preRPs: reconcilerv2.RoutePolicyMap{
				importPeerPolicy.Name: importPeerPolicy,
				exportPeerPolicy.Name: exportPeerPolicy,
			},
			peerConfigs: []*v2alpha1.CiliumBGPPeerConfig{peerConfigIPv4Unicast},
			testBGPNodeInstance: &v2alpha1.CiliumBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers: []v2alpha1.CiliumBGPNodePeer{
					{
						Name:        "red-peer-65001",
						PeerAddress: ptr.To[string]("192.168.0.10"),
						PeerConfigRef: &v2alpha1.PeerConfigReference{
							Name: "no_matching_peer_config",
						},
					},
				},
			},
			expectedRPs: make(reconcilerv2.RoutePolicyMap),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			testOSSBGPInstance := instance.NewFakeBGPInstance()

			reconciler := &VPNRoutePolicyReconciler{
				Logger:          logger,
				PeerConfigStore: newMockResourceStore[*v2alpha1.CiliumBGPPeerConfig](),
			}

			if len(tt.peerConfigs) > 0 {
				reconciler.PeerConfigStore = InitMockStore[*v2alpha1.CiliumBGPPeerConfig](tt.peerConfigs)
			}

			reconciler.initialized.Store(true)

			// set preconfigured route policies
			reconciler.SetMetadata(testOSSBGPInstance, VPNRoutePolicyMetadata{
				VPNPolicies: tt.preRPs,
			})

			// reconcile peer configs
			for i := 0; i < 2; i++ {
				err := reconciler.Reconcile(context.Background(), reconcilerv2.ReconcileParams{
					BGPInstance:   testOSSBGPInstance,
					DesiredConfig: tt.testBGPNodeInstance,
				})
				req.NoError(err)
			}

			req.Equal(tt.expectedRPs, reconciler.GetMetadata(testOSSBGPInstance).VPNPolicies)
		})
	}
}
