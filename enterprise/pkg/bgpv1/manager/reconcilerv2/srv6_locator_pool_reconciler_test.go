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

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	srv6Types "github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestExportSRv6LocatorPoolReconciler(t *testing.T) {
	locator1 := srv6Types.MustNewLocator(
		netip.MustParsePrefix("fd00:0:1::/48"),
	)
	locator2 := srv6Types.MustNewLocator(
		netip.MustParsePrefix("fd00:0:2::/48"),
	)
	locator3 := srv6Types.MustNewLocator(
		netip.MustParsePrefix("fd00:0:3::/48"),
	)
	structure := srv6Types.MustNewSIDStructure(32, 16, 16, 0)

	testInstanceConfig := &v1alpha1.IsovalentBGPNodeInstance{
		Name:     "bgp-65001",
		LocalASN: ptr.To[int64](65001),
		Peers: []v1alpha1.IsovalentBGPNodePeer{
			{
				Name:        "peer-65001",
				PeerAddress: ptr.To[string]("10.10.10.1"),
				PeerConfigRef: &v1alpha1.PeerConfigReference{
					Group: "isovalent.com",
					Kind:  "IsovalentBGPPeerConfig",
					Name:  "peer-config",
				},
			},
		},
	}

	testPeerConfig := &v1alpha1.IsovalentBGPPeerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peer-config",
		},
		Spec: v1alpha1.IsovalentBGPPeerConfigSpec{
			CiliumBGPPeerConfigSpec: v2alpha1.CiliumBGPPeerConfigSpec{
				Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
					{
						CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
							Afi:  "ipv6",
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

	testAdvertisement := &v1alpha1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name: "srv6-lp-advertisement",
			Labels: map[string]string{
				"advertise": "bgp",
			},
		},
		Spec: v1alpha1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1alpha1.BGPAdvertisement{
				{
					AdvertisementType: v1alpha1.BGPSRv6LocatorPoolAdvert,
					Selector: &slimv1.LabelSelector{
						MatchLabels: map[string]string{
							"export": "true",
						},
					},
				},
			},
		},
	}

	pool1RPName := PolicyName("peer-65001", "ipv6", v1alpha1.BGPSRv6LocatorPoolAdvert, "pool1")
	pool1Locator1RP := &types.RoutePolicy{
		Name: pool1RPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         locator1.Prefix,
							PrefixLenMin: locator1.Prefix.Bits(),
							PrefixLenMax: locator1.Prefix.Bits(),
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				},
			},
		},
	}
	pool1Locator2RP := &types.RoutePolicy{
		Name: pool1RPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         locator2.Prefix,
							PrefixLenMin: locator2.Prefix.Bits(),
							PrefixLenMax: locator2.Prefix.Bits(),
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				},
			},
		},
	}

	pool2RPName := PolicyName("peer-65001", "ipv6", v1alpha1.BGPSRv6LocatorPoolAdvert, "pool2")
	pool2Locator2RP := &types.RoutePolicy{
		Name: pool2RPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         locator2.Prefix,
							PrefixLenMin: locator2.Prefix.Bits(),
							PrefixLenMax: locator2.Prefix.Bits(),
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				},
			},
		},
	}
	pool2Locator3RP := &types.RoutePolicy{
		Name: pool2RPName,
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         locator3.Prefix,
							PrefixLenMin: locator3.Prefix.Bits(),
							PrefixLenMax: locator3.Prefix.Bits(),
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				},
			},
		},
	}

	emptyAFPathMap := func() map[resource.Key]map[types.Family]map[string]struct{} {
		return map[resource.Key]map[types.Family]map[string]struct{}{}
	}
	emptyRPMap := func() reconcilerv2.ResourceRoutePolicyMap {
		return reconcilerv2.ResourceRoutePolicyMap{}
	}

	tests := []struct {
		name                 string
		locators             map[string]srv6Types.Locator
		LocatorPools         []v1alpha1.IsovalentSRv6LocatorPool
		preconfiguredAFPaths map[resource.Key]map[types.Family]map[string]struct{}
		preconfiguredRPs     reconcilerv2.ResourceRoutePolicyMap
		expectedAFPaths      map[resource.Key]map[types.Family]map[string]struct{}
		expectedRPs          reconcilerv2.ResourceRoutePolicyMap
	}{
		{
			name: "Single Pool Create",
			locators: map[string]srv6Types.Locator{
				"pool1": locator1,
			},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			preconfiguredAFPaths: emptyAFPathMap(),
			preconfiguredRPs:     emptyRPMap(),
			expectedAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
			},
			expectedRPs: reconcilerv2.ResourceRoutePolicyMap{
				{Name: "pool1"}: reconcilerv2.RoutePolicyMap{
					pool1RPName: pool1Locator1RP,
				},
			},
		},
		{
			name: "Single Pool Locator Change",
			locators: map[string]srv6Types.Locator{
				"pool1": locator2,
			},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			preconfiguredAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
			},
			preconfiguredRPs: reconcilerv2.ResourceRoutePolicyMap{
				{Name: "pool1"}: reconcilerv2.RoutePolicyMap{
					pool1RPName: pool1Locator1RP,
				},
			},
			expectedAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator2.Prefix.String(): {},
					},
				},
			},
			expectedRPs: reconcilerv2.ResourceRoutePolicyMap{
				{Name: "pool1"}: reconcilerv2.RoutePolicyMap{
					pool1RPName: pool1Locator2RP,
				},
			},
		},
		{
			name: "Single Pool Label Change",
			locators: map[string]srv6Types.Locator{
				"pool1": locator1,
			},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "false"},
					},
				},
			},
			preconfiguredAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
			},
			preconfiguredRPs: reconcilerv2.ResourceRoutePolicyMap{
				{Name: "pool1"}: reconcilerv2.RoutePolicyMap{
					pool1RPName: pool1Locator1RP,
				},
			},
			expectedAFPaths: emptyAFPathMap(),
			expectedRPs:     emptyRPMap(),
		},
		{
			name:         "Single Pool Delete",
			locators:     map[string]srv6Types.Locator{},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{},
			preconfiguredAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
			},
			preconfiguredRPs: reconcilerv2.ResourceRoutePolicyMap{
				{Name: "pool1"}: reconcilerv2.RoutePolicyMap{
					pool1RPName: pool1Locator1RP,
				},
			},
			expectedAFPaths: emptyAFPathMap(),
			expectedRPs:     emptyRPMap(),
		},
		{
			name: "Multi Pool Create",
			locators: map[string]srv6Types.Locator{
				"pool1": locator1,
				"pool2": locator2,
			},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool2",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			preconfiguredAFPaths: emptyAFPathMap(),
			preconfiguredRPs:     emptyRPMap(),
			expectedAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
				{Name: "pool2"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator2.Prefix.String(): {},
					},
				},
			},
			expectedRPs: reconcilerv2.ResourceRoutePolicyMap{
				{Name: "pool1"}: reconcilerv2.RoutePolicyMap{
					pool1RPName: pool1Locator1RP,
				},
				{Name: "pool2"}: reconcilerv2.RoutePolicyMap{
					pool2RPName: pool2Locator2RP,
				},
			},
		},
		{
			name: "Multi Pool Locator Change",
			locators: map[string]srv6Types.Locator{
				"pool1": locator1,
				"pool2": locator3,
			},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool2",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			preconfiguredAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
				{Name: "pool2"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator2.Prefix.String(): {},
					},
				},
			},
			preconfiguredRPs: reconcilerv2.ResourceRoutePolicyMap{
				{Name: "pool1"}: reconcilerv2.RoutePolicyMap{
					pool1RPName: pool1Locator1RP,
				},
				{Name: "pool2"}: reconcilerv2.RoutePolicyMap{
					pool2RPName: pool2Locator2RP,
				},
			},
			expectedAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
				{Name: "pool2"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator3.Prefix.String(): {},
					},
				},
			},
			expectedRPs: reconcilerv2.ResourceRoutePolicyMap{
				{Name: "pool1"}: reconcilerv2.RoutePolicyMap{
					pool1RPName: pool1Locator1RP,
				},
				{Name: "pool2"}: reconcilerv2.RoutePolicyMap{
					pool2RPName: pool2Locator3RP,
				},
			},
		},
		{
			name: "Multi Pool Label Change",
			locators: map[string]srv6Types.Locator{
				"pool1": locator1,
				"pool2": locator3,
			},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool2",
						Labels: map[string]string{"export": "false"},
					},
				},
			},
			preconfiguredAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
				{Name: "pool2"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator2.Prefix.String(): {},
					},
				},
			},
			preconfiguredRPs: reconcilerv2.ResourceRoutePolicyMap{
				{Name: "pool1"}: reconcilerv2.RoutePolicyMap{
					pool1RPName: pool1Locator1RP,
				},
				{Name: "pool2"}: reconcilerv2.RoutePolicyMap{
					pool2RPName: pool2Locator2RP,
				},
			},
			expectedAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
			},
			expectedRPs: reconcilerv2.ResourceRoutePolicyMap{
				{Name: "pool1"}: reconcilerv2.RoutePolicyMap{
					pool1RPName: pool1Locator1RP,
				},
			},
		},
		{
			name: "Multi Pool Delete",
			locators: map[string]srv6Types.Locator{
				"pool1": locator1,
			},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			preconfiguredAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
				{Name: "pool2"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator2.Prefix.String(): {},
					},
				},
			},
			preconfiguredRPs: reconcilerv2.ResourceRoutePolicyMap{
				{Name: "pool1"}: reconcilerv2.RoutePolicyMap{
					pool1RPName: pool1Locator1RP,
				},
				{Name: "pool2"}: reconcilerv2.RoutePolicyMap{
					pool2RPName: pool2Locator2RP,
				},
			},
			expectedAFPaths: map[resource.Key]map[types.Family]map[string]struct{}{
				{Name: "pool1"}: {
					{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
						locator1.Prefix.String(): {},
					},
				},
			},
			expectedRPs: reconcilerv2.ResourceRoutePolicyMap{
				{Name: "pool1"}: reconcilerv2.RoutePolicyMap{
					pool1RPName: pool1Locator1RP,
				},
			},
		},
		{
			// isovalent/cilium #2609
			name:     "Missing locator is not an error",
			locators: map[string]srv6Types.Locator{},
			LocatorPools: []v1alpha1.IsovalentSRv6LocatorPool{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:   "pool1",
						Labels: map[string]string{"export": "true"},
					},
				},
			},
			preconfiguredAFPaths: emptyAFPathMap(),
			preconfiguredRPs:     emptyRPMap(),
			expectedAFPaths:      emptyAFPathMap(),
			expectedRPs:          emptyRPMap(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := require.New(t)

			mockPeerConfigStore := newMockResourceStore[*v1alpha1.IsovalentBGPPeerConfig]()
			mockAdvertStore := newMockResourceStore[*v1alpha1.IsovalentBGPAdvertisement]()
			mockLocatorPoolStore := newMockResourceStore[*v1alpha1.IsovalentSRv6LocatorPool]()

			mockPeerConfigStore.Upsert(testPeerConfig)
			mockAdvertStore.Upsert(testAdvertisement)

			allocators := make(map[string]sidmanager.SIDAllocator)
			for poolName, l := range test.locators {
				sa, err := sidmanager.NewStructuredSIDAllocator(l, structure, srv6Types.BehaviorTypeBase)
				require.NoError(t, err)
				allocators[poolName] = sa
			}
			for _, r := range test.LocatorPools {
				mockLocatorPoolStore.Upsert(&r)
			}

			reconciler := LocatorPoolReconciler{
				logger:           logger,
				upgrader:         newUpgraderMock(testInstanceConfig),
				locatorPoolStore: mockLocatorPoolStore,
				sidAllocators:    allocators,
				peerAdvert: &IsovalentPeerAdvertisement{
					logger:     logger,
					peerConfig: mockPeerConfigStore,
					adverts:    mockAdvertStore,
				},
			}

			reconciler.peerAdvert.initialized.Store(true)
			reconciler.initialized.Store(true)

			testOSSBGPInstance := instance.NewFakeBGPInstance()

			// set preconfigured data
			presetAFPaths := make(reconcilerv2.ResourceAFPathsMap)
			for key, preAFPaths := range test.preconfiguredAFPaths {
				presetAFPaths[key] = make(reconcilerv2.AFPathsMap)
				for fam, afPaths := range preAFPaths {
					pathSet := make(reconcilerv2.PathMap)
					for prePath := range afPaths {
						path := types.NewPathForPrefix(netip.MustParsePrefix(prePath))
						path.Family = fam
						pathSet[prePath] = path
					}
					presetAFPaths[key][fam] = pathSet
				}
			}

			testOSSBGPInstance.Metadata[reconciler.Name()] = LocatorPoolReconcilerMetadata{
				AFPaths:       presetAFPaths,
				RoutePolicies: test.preconfiguredRPs,
			}

			// run the reconciler twice to ensure idempotency
			for i := 0; i < 2; i++ {
				err := reconciler.Reconcile(context.Background(), reconcilerv2.ReconcileParams{
					BGPInstance: testOSSBGPInstance,
				})
				req.NoError(err)
			}

			// check if the advertisement is as expected
			runningAFPaths := make(map[resource.Key]map[types.Family]map[string]struct{})
			for key, afPaths := range testOSSBGPInstance.Metadata[reconciler.Name()].(LocatorPoolReconcilerMetadata).AFPaths {
				runningAFPaths[key] = make(map[types.Family]map[string]struct{})
				for fam, afPaths := range afPaths {
					pathSet := make(map[string]struct{})
					for pathKey := range afPaths {
						pathSet[pathKey] = struct{}{}
					}
					runningAFPaths[key][fam] = pathSet
				}
			}

			req.EqualValues(test.expectedAFPaths, runningAFPaths)
			req.EqualValues(test.expectedRPs, testOSSBGPInstance.Metadata[reconciler.Name()].(LocatorPoolReconcilerMetadata).RoutePolicies)
		})
	}
}
