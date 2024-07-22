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
	"net/netip"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

var (
	logger = logrus.WithField("unit_test", "reconcilerv2_egw")
)

var (
	// policy 1
	egwPolicyKey = resource.Key{
		Namespace: "default",
		Name:      "egress-gateway",
	}
	egwLabels = map[string]string{
		"egress": "policy-1",
	}
	egwLabelSelector = &slimv1.LabelSelector{
		MatchLabels: egwLabels,
	}
	egwAddr   = netip.MustParseAddr("10.2.0.1")
	egwPrefix = netip.MustParsePrefix("10.2.0.1/32")

	// policy 2
	egwPolicyKey2 = resource.Key{
		Namespace: "default",
		Name:      "egress-gateway-2",
	}
	egwLabels2 = map[string]string{
		"egress": "policy-2",
	}
	egwLabelSelector2 = &slimv1.LabelSelector{
		MatchLabels: egwLabels2,
	}
	egwAddr2   = netip.MustParseAddr("10.2.0.2")
	egwPrefix2 = netip.MustParsePrefix("10.2.0.2/32")

	// peer config
	peer = v1alpha1.IsovalentBGPNodePeer{
		Name:        "peer-65001",
		PeerAddress: ptr.To[string]("10.10.10.1"),
		PeerConfigRef: &v1alpha1.PeerConfigReference{
			Group: "isovalent.com",
			Kind:  "IsovalentBGPPeerConfig",
			Name:  "peer-config",
		},
	}

	peerConfig = &v1alpha1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config",
		},
		Spec: v1alpha1.IsovalentBGPPeerConfigSpec{
			CiliumBGPPeerConfigSpec: v2alpha1.CiliumBGPPeerConfigSpec{
				Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
					{
						CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
							Afi:  "ipv4",
							Safi: "unicast",
						},
						Advertisements: &slimv1.LabelSelector{
							MatchLabels: map[string]string{
								"advertise": "bgp",
							},
						},
					},
				},
			},
		},
	}

	egwAdvert = &v1alpha1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "egw-advertisement",
			Labels: map[string]string{
				"advertise": "bgp",
			},
		},
		Spec: v1alpha1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1alpha1.BGPAdvertisement{
				{
					AdvertisementType: v1alpha1.BGPEGWAdvert,
					Selector:          egwLabelSelector,
					Attributes: &v2alpha1.BGPAttributes{
						Communities: &v2alpha1.BGPCommunities{
							Standard: []v2alpha1.BGPStandardCommunity{"65000:100"},
						},
					},
				},
				{
					AdvertisementType: v1alpha1.BGPEGWAdvert,
					Selector:          egwLabelSelector2,
					Attributes: &v2alpha1.BGPAttributes{
						Communities: &v2alpha1.BGPCommunities{
							Standard: []v2alpha1.BGPStandardCommunity{"65000:200"},
						},
					},
				},
			},
		},
	}

	egw1RPName = PolicyName("peer-65001", "ipv4", v1alpha1.BGPEGWAdvert, egwPolicyKey.Name)
	egw1RP     = &types.RoutePolicy{
		Name: egw1RPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         egwPrefix,
							PrefixLenMin: 32,
							PrefixLenMax: 32,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65000:100"},
				},
			},
		},
	}

	egw2RPName = PolicyName("peer-65001", "ipv4", v1alpha1.BGPEGWAdvert, egwPolicyKey2.Name)
	egw2RP     = &types.RoutePolicy{
		Name: egw2RPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         egwPrefix2,
							PrefixLenMin: 32,
							PrefixLenMax: 32,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65000:200"},
				},
			},
		},
	}

	egw2RPOld = &types.RoutePolicy{
		Name: egw2RPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         egwPrefix2,
							PrefixLenMin: 32,
							PrefixLenMax: 32,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction:    types.RoutePolicyActionAccept,
					AddCommunities: []string{"65000:222"},
				},
			},
		},
	}
)

func TestEgressGatewayAdvertisements(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	tests := []struct {
		name                    string
		advertisement           *v1alpha1.IsovalentBGPAdvertisement
		preconfiguredEGWAFPaths map[resource.Key]map[types.Family]map[string]struct{}
		preconfiguredRPs        reconcilerv2.ResourceRoutePolicyMap
		testEGWPolicies         []mockEGWPolicy
		testBGPInstanceConfig   *v1alpha1.IsovalentBGPNodeInstance
		expectedEGWAFPaths      map[resource.Key]map[types.Family]map[string]struct{}
		expectedRPs             reconcilerv2.ResourceRoutePolicyMap
	}{
		{
			name:             "EGW correct advertisement",
			advertisement:    egwAdvert,
			preconfiguredRPs: make(reconcilerv2.ResourceRoutePolicyMap),
			testEGWPolicies: []mockEGWPolicy{
				{
					id: k8sTypes.NamespacedName{
						Namespace: egwPolicyKey.Namespace,
						Name:      egwPolicyKey.Name,
					},
					labels:    egwLabels,
					egressIPs: []netip.Addr{egwAddr},
				},
			},
			testBGPInstanceConfig: &v1alpha1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v1alpha1.IsovalentBGPNodePeer{peer},
			},
			expectedEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				egwPolicyKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix.String(): {},
					},
				},
			},
			expectedRPs: reconcilerv2.ResourceRoutePolicyMap{
				egwPolicyKey: reconcilerv2.RoutePolicyMap{
					egw1RPName: egw1RP,
				},
			},
		},
		{
			name:          "Test update: Preconfigured path and policy, add another egw policy",
			advertisement: egwAdvert,
			preconfiguredEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				egwPolicyKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix.String(): {},
					},
				},
			},
			preconfiguredRPs: reconcilerv2.ResourceRoutePolicyMap{
				egwPolicyKey: reconcilerv2.RoutePolicyMap{
					egw1RPName: egw1RP,
				},
			},
			testEGWPolicies: []mockEGWPolicy{
				{
					id: k8sTypes.NamespacedName{
						Namespace: egwPolicyKey.Namespace,
						Name:      egwPolicyKey.Name,
					},
					labels:    egwLabels,
					egressIPs: []netip.Addr{egwAddr},
				},
				{
					id: k8sTypes.NamespacedName{
						Namespace: egwPolicyKey2.Namespace,
						Name:      egwPolicyKey2.Name,
					},
					labels:    egwLabels2,
					egressIPs: []netip.Addr{egwAddr2},
				},
			},
			testBGPInstanceConfig: &v1alpha1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v1alpha1.IsovalentBGPNodePeer{peer},
			},
			expectedEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				egwPolicyKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix.String(): {},
					},
				},
				egwPolicyKey2: { // new path added
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix2.String(): {},
					},
				},
			},
			expectedRPs: reconcilerv2.ResourceRoutePolicyMap{
				egwPolicyKey: reconcilerv2.RoutePolicyMap{
					egw1RPName: egw1RP,
				},
				egwPolicyKey2: reconcilerv2.RoutePolicyMap{ // new route policy added
					egw2RPName: egw2RP,
				},
			},
		},
		{
			name:          "Test update: Preconfigured path and policy, advert updated community",
			advertisement: egwAdvert,
			preconfiguredEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				egwPolicyKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix.String(): {},
					},
				},
				egwPolicyKey2: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix2.String(): {},
					},
				},
			},
			preconfiguredRPs: reconcilerv2.ResourceRoutePolicyMap{
				egwPolicyKey: reconcilerv2.RoutePolicyMap{
					egw1RPName: egw1RP,
				},
				egwPolicyKey2: reconcilerv2.RoutePolicyMap{ // old route policy, contains old community
					egw2RPName: egw2RPOld,
				},
			},
			testEGWPolicies: []mockEGWPolicy{
				{
					id: k8sTypes.NamespacedName{
						Namespace: egwPolicyKey.Namespace,
						Name:      egwPolicyKey.Name,
					},
					labels:    egwLabels,
					egressIPs: []netip.Addr{egwAddr},
				},
				{
					id: k8sTypes.NamespacedName{
						Namespace: egwPolicyKey2.Namespace,
						Name:      egwPolicyKey2.Name,
					},
					labels:    egwLabels2,
					egressIPs: []netip.Addr{egwAddr2},
				},
			},
			testBGPInstanceConfig: &v1alpha1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v1alpha1.IsovalentBGPNodePeer{peer},
			},
			expectedEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				egwPolicyKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix.String(): {},
					},
				},
				egwPolicyKey2: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix2.String(): {},
					},
				},
			},
			expectedRPs: reconcilerv2.ResourceRoutePolicyMap{
				egwPolicyKey: reconcilerv2.RoutePolicyMap{
					egw1RPName: egw1RP,
				},
				egwPolicyKey2: reconcilerv2.RoutePolicyMap{ // updated route policy added
					egw2RPName: egw2RP,
				},
			},
		},
		{
			name:          "Test deletion: Preconfigured path and policy, egw policy removed",
			advertisement: egwAdvert,
			preconfiguredEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				egwPolicyKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix.String(): {},
					},
				},
				egwPolicyKey2: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix2.String(): {},
					},
				},
			},
			preconfiguredRPs: reconcilerv2.ResourceRoutePolicyMap{
				egwPolicyKey: reconcilerv2.RoutePolicyMap{
					egw1RPName: egw1RP,
				},
				egwPolicyKey2: reconcilerv2.RoutePolicyMap{
					egw2RPName: egw2RP,
				},
			},
			testEGWPolicies: []mockEGWPolicy{}, // no egw policy present in EGW manager
			testBGPInstanceConfig: &v1alpha1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v1alpha1.IsovalentBGPNodePeer{peer},
			},
			expectedEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{},
			expectedRPs:        reconcilerv2.ResourceRoutePolicyMap{},
		},

		{
			name:          "Test deletion: Preconfigured path and policy, advert removed",
			advertisement: nil, // no advertisement
			preconfiguredEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				egwPolicyKey: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix.String(): {},
					},
				},
				egwPolicyKey2: {
					{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
						egwPrefix2.String(): {},
					},
				},
			},
			preconfiguredRPs: reconcilerv2.ResourceRoutePolicyMap{
				egwPolicyKey: reconcilerv2.RoutePolicyMap{
					egw1RPName: egw1RP,
				},
				egwPolicyKey2: reconcilerv2.RoutePolicyMap{
					egw2RPName: egw2RP,
				},
			},
			testEGWPolicies: []mockEGWPolicy{
				{
					id: k8sTypes.NamespacedName{
						Namespace: egwPolicyKey.Namespace,
						Name:      egwPolicyKey.Name,
					},
					labels:    egwLabels,
					egressIPs: []netip.Addr{egwAddr},
				},
				{
					id: k8sTypes.NamespacedName{
						Namespace: egwPolicyKey2.Namespace,
						Name:      egwPolicyKey2.Name,
					},
					labels:    egwLabels2,
					egressIPs: []netip.Addr{egwAddr2},
				},
			},
			testBGPInstanceConfig: &v1alpha1.IsovalentBGPNodeInstance{
				Name:     "bgp-65001",
				LocalASN: ptr.To[int64](65001),
				Peers:    []v1alpha1.IsovalentBGPNodePeer{peer},
			},
			expectedEGWAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{},
			expectedRPs:        reconcilerv2.ResourceRoutePolicyMap{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			mockPeerConfigStore := newMockResourceStore[*v1alpha1.IsovalentBGPPeerConfig]()
			mockAdvertStore := newMockResourceStore[*v1alpha1.IsovalentBGPAdvertisement]()

			reconciler := EgressGatewayIPsReconciler{
				logger:         logger,
				egwIPsProvider: newEGWManagerMock(tt.testEGWPolicies),
				upgrader:       newUpgraderMock(tt.testBGPInstanceConfig),
				peerAdvert: &IsovalentAdvertisement{
					logger:     logger,
					peerConfig: mockPeerConfigStore,
					adverts:    mockAdvertStore,
				},
			}

			// set peer advert state
			reconciler.peerAdvert.initialized.Store(true)
			mockPeerConfigStore.Upsert(peerConfig)
			if tt.advertisement != nil {
				mockAdvertStore.Upsert(tt.advertisement)
			}

			testOSSBGPInstance := instance.NewFakeBGPInstance()

			// set preconfigured data
			presetEGWAFPaths := make(reconcilerv2.ResourceAFPathsMap)
			for key, preAFPaths := range tt.preconfiguredEGWAFPaths {
				presetEGWAFPaths[key] = make(reconcilerv2.AFPathsMap)
				for fam, afPaths := range preAFPaths {
					pathSet := make(reconcilerv2.PathMap)
					for prePath := range afPaths {
						path := types.NewPathForPrefix(netip.MustParsePrefix(prePath))
						path.Family = fam
						pathSet[prePath] = path
					}
					presetEGWAFPaths[key][fam] = pathSet
				}
			}

			testOSSBGPInstance.Metadata[reconciler.Name()] = EgressGatewayIPsMetadata{
				EGWAFPaths:       presetEGWAFPaths,
				EGWRoutePolicies: tt.preconfiguredRPs,
			}

			// run podIPPoolReconciler twice to ensure idempotency
			for i := 0; i < 2; i++ {
				err := reconciler.Reconcile(context.Background(), reconcilerv2.ReconcileParams{
					BGPInstance: testOSSBGPInstance,
				})
				req.NoError(err)
			}

			// check if the advertisement is as expected
			runningEGWAFPaths := make(map[resource.Key]map[types.Family]map[string]struct{})
			for key, egwAFPaths := range testOSSBGPInstance.Metadata[reconciler.Name()].(EgressGatewayIPsMetadata).EGWAFPaths {
				runningEGWAFPaths[key] = make(map[types.Family]map[string]struct{})
				for fam, afPaths := range egwAFPaths {
					pathSet := make(map[string]struct{})
					for pathKey := range afPaths {
						pathSet[pathKey] = struct{}{}
					}
					runningEGWAFPaths[key][fam] = pathSet
				}
			}

			req.Equal(tt.expectedEGWAFPaths, runningEGWAFPaths)
			req.Equal(tt.expectedRPs, testOSSBGPInstance.Metadata[reconciler.Name()].(EgressGatewayIPsMetadata).EGWRoutePolicies)
		})
	}
}
