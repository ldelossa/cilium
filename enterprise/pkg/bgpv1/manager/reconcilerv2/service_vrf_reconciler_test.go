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

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	srv6 "github.com/cilium/cilium/enterprise/pkg/srv6/srv6manager"
	"github.com/cilium/cilium/enterprise/pkg/srv6/types"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	bgptypes "github.com/cilium/cilium/pkg/bgpv1/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

var (
	svcVRFTestLogger = logrus.WithField("unit_test", "reconcilerv2_serviceVRF")
)

type afSimplePathsMap map[bgptypes.Family][]string // list of nlris
type resourceAFSimplePathsMap map[resource.Key]afSimplePathsMap
type vrfSimplePathsMap map[string]resourceAFSimplePathsMap // vrf -> resource -> af -> simplePath

func compareSimplePath(req *require.Assertions, vrfSimplePath vrfSimplePathsMap, vrfPaths VRFPaths) {
	req.Equal(len(vrfSimplePath), len(vrfPaths))

	for vrf, svcAFSimplePaths := range vrfSimplePath {
		svcAFPaths, exists := vrfPaths[vrf]
		req.True(exists)
		req.Equal(len(svcAFSimplePaths), len(svcAFPaths))

		for svc, simpleSvcPaths := range svcAFSimplePaths {
			afPaths, exists := svcAFPaths[svc]
			req.True(exists)
			req.Equal(len(simpleSvcPaths), len(afPaths))

			for af, simplePaths := range simpleSvcPaths {
				paths, exists := afPaths[af]
				req.True(exists)
				req.Equal(len(simplePaths), len(paths))

				for _, path := range paths {
					found := false
					for _, nlri := range simplePaths {
						if nlri == path.NLRI.String() {
							found = true
						}
					}
					req.True(found)
				}
			}
		}
	}
}

var (
	dummyLabel = bgp.MPLSLabelStack{
		Labels: []uint32{1234},
	}

	vrf1LBIngressIP = netip.MustParseAddr("192.168.100.1")
	vrf2LBIngressIP = netip.MustParseAddr("192.168.200.1")

	vrf1SvcLabel = map[string]string{"svc": "vrf1"}
	vrf1LBSvc    = &slim_corev1.Service{
		ObjectMeta: slimv1.ObjectMeta{
			Name:   "vrf1-service",
			Labels: vrf1SvcLabel,
		},
		Spec: slim_corev1.ServiceSpec{
			Type:                  slim_corev1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: slim_corev1.ServiceExternalTrafficPolicyLocal,
		},
		Status: slim_corev1.ServiceStatus{
			LoadBalancer: slim_corev1.LoadBalancerStatus{
				Ingress: []slim_corev1.LoadBalancerIngress{
					{
						IP: vrf1LBIngressIP.String(),
					},
				},
			},
		},
	}

	vrf2SvcLabel = map[string]string{"svc": "vrf2"}
	vrf2LBSvc    = &slim_corev1.Service{
		ObjectMeta: slimv1.ObjectMeta{
			Name:   "vrf2-service",
			Labels: vrf2SvcLabel,
		},
		Spec: slim_corev1.ServiceSpec{
			Type:                  slim_corev1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: slim_corev1.ServiceExternalTrafficPolicyLocal,
		},
		Status: slim_corev1.ServiceStatus{
			LoadBalancer: slim_corev1.LoadBalancerStatus{
				Ingress: []slim_corev1.LoadBalancerIngress{
					{
						IP: vrf2LBIngressIP.String(),
					},
				},
			},
		},
	}

	vrfSvcETPCluster = func(svc *slim_corev1.Service) *slim_corev1.Service {
		newSvc := svc.DeepCopy()
		newSvc.Spec.ExternalTrafficPolicy = slim_corev1.ServiceExternalTrafficPolicyCluster
		return newSvc
	}

	vrf1SvcEP1 = &k8s.Endpoints{
		ObjectMeta: slimv1.ObjectMeta{
			Name: "vrf1-svc",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      vrf1LBSvc.Name,
				Namespace: vrf1LBSvc.Namespace,
			},
			EndpointSliceName: "vrf1-svc",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("10.0.0.1"): {
				NodeName: "test-node",
			},
		},
	}

	vrf2SvcEP1 = &k8s.Endpoints{
		ObjectMeta: slimv1.ObjectMeta{
			Name: "vrf2-svc",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      vrf2LBSvc.Name,
				Namespace: vrf2LBSvc.Namespace,
			},
			EndpointSliceName: "vrf2-svc",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("10.0.0.2"): {
				NodeName: "test-node",
			},
		},
	}

	vrf1AdvertLabel = map[string]string{"vrf": "vrf1"}
	vrf2AdvertLabel = map[string]string{"vrf": "vrf2"}

	vrf1Config = &v1alpha1.IsovalentBGPVRFConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "vrf1-config",
		},
		Spec: v1alpha1.IsovalentBGPVRFConfigSpec{
			Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "mpls_vpn",
					},
					Advertisements: &slimv1.LabelSelector{
						MatchLabels: vrf1AdvertLabel,
					},
				},
			},
		},
	}

	vrf2Config = &v1alpha1.IsovalentBGPVRFConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name: "vrf2-config",
		},
		Spec: v1alpha1.IsovalentBGPVRFConfigSpec{
			Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "mpls_vpn",
					},
					Advertisements: &slimv1.LabelSelector{
						MatchLabels: vrf2AdvertLabel,
					},
				},
			},
		},
	}

	vrf1BGPAdvert = v1alpha1.BGPAdvertisement{
		AdvertisementType: "Service",
		Service: &v1alpha1.BGPServiceOptions{
			Addresses: []v2alpha1.BGPServiceAddressType{
				v2alpha1.BGPLoadBalancerIPAddr,
			},
		},
		Selector: &slimv1.LabelSelector{
			MatchLabels: vrf1SvcLabel,
		},
	}
	vrf1Advert = &v1alpha1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "vrf1-advert",
			Labels: vrf1AdvertLabel,
		},
		Spec: v1alpha1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
		},
	}

	vrf2BGPAdvert = v1alpha1.BGPAdvertisement{
		AdvertisementType: "Service",
		Service: &v1alpha1.BGPServiceOptions{
			Addresses: []v2alpha1.BGPServiceAddressType{
				v2alpha1.BGPLoadBalancerIPAddr,
			},
		},
		Selector: &slimv1.LabelSelector{
			MatchLabels: vrf2SvcLabel,
		},
	}
	vrf2Advert = &v1alpha1.IsovalentBGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "vrf2-advert",
			Labels: vrf2AdvertLabel,
		},
		Spec: v1alpha1.IsovalentBGPAdvertisementSpec{
			Advertisements: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
		},
	}

	testCiliumNodeConfig = &v2api.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
		},
	}

	vrf1RDConfig = v1alpha1.IsovalentBGPNodeVRF{
		VRFRef:    "vrf1",
		ConfigRef: ptr.To[string]("vrf1-config"),
		RD:        ptr.To[string]("65001:1"),
		ImportRTs: []string{"65001:1"},
		ExportRTs: []string{"65001:1"},
	}
	vrf1RDConfigUpdated = v1alpha1.IsovalentBGPNodeVRF{
		VRFRef:    "vrf1",
		ConfigRef: ptr.To[string]("vrf1-config"),
		RD:        ptr.To[string]("65101:1"),
		ImportRTs: []string{"65101:1"},
		ExportRTs: []string{"65101:1"},
	}

	vrf2RDConfig = v1alpha1.IsovalentBGPNodeVRF{
		VRFRef:    "vrf2",
		ConfigRef: ptr.To[string]("vrf2-config"),
		RD:        ptr.To[string]("65001:2"),
		ImportRTs: []string{"65001:2"},
		ExportRTs: []string{"65001:2"},
	}
	vrf2ConfigUpdated = v1alpha1.IsovalentBGPNodeVRF{
		VRFRef:    "vrf2",
		ConfigRef: ptr.To[string]("vrf2-config"),
		RD:        ptr.To[string]("65101:2"),
		ImportRTs: []string{"65101:2"},
		ExportRTs: []string{"65101:2"},
	}

	testBGPNodeInstance = &v1alpha1.IsovalentBGPNodeInstance{
		Name:     "bgp-65001",
		LocalASN: ptr.To[int64](65001),
		VRFs:     []v1alpha1.IsovalentBGPNodeVRF{vrf1RDConfig, vrf2RDConfig},
	}

	testBGPNodeInstanceUpdatedRD = &v1alpha1.IsovalentBGPNodeInstance{
		Name:     "bgp-65001",
		LocalASN: ptr.To[int64](65001),
		VRFs:     []v1alpha1.IsovalentBGPNodeVRF{vrf1RDConfigUpdated, vrf2ConfigUpdated},
	}

	testBGPNodeInstanceUpdatedNoVRF = &v1alpha1.IsovalentBGPNodeInstance{
		Name:     "bgp-65001",
		LocalASN: ptr.To[int64](65001),
		VRFs:     []v1alpha1.IsovalentBGPNodeVRF{},
	}

	locator = types.MustNewLocator(
		netip.MustParsePrefix("fd00::/64"),
	)
	structure = types.MustNewSIDStructure(48, 16, 16, 0)
)

func TestServiceVRFFullReconciler(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	vrf1RD, err := bgp.ParseRouteDistinguisher("65001:1")
	if err != nil {
		t.Fatalf("failed to parse RD: %v", err)
	}

	vrf1RDUpdated, err := bgp.ParseRouteDistinguisher("65101:1")
	if err != nil {
		t.Fatalf("failed to parse RD: %v", err)
	}

	vrf2RD, err := bgp.ParseRouteDistinguisher("65001:2")
	if err != nil {
		t.Fatalf("failed to parse RD: %v", err)
	}

	vrf2RDUpdated, err := bgp.ParseRouteDistinguisher("65101:2")
	if err != nil {
		t.Fatalf("failed to parse RD: %v", err)
	}

	vrf1LBIngressIPNLRI := bgp.NewLabeledVPNIPAddrPrefix(uint8(vrf1LBIngressIP.BitLen()), vrf1LBIngressIP.String(), dummyLabel, vrf1RD)
	vrf1LBIngressIPNLRIUpdated := bgp.NewLabeledVPNIPAddrPrefix(uint8(vrf1LBIngressIP.BitLen()), vrf1LBIngressIP.String(), dummyLabel, vrf1RDUpdated)
	vrf2LBIngressIPNLRI := bgp.NewLabeledVPNIPAddrPrefix(uint8(vrf2LBIngressIP.BitLen()), vrf2LBIngressIP.String(), dummyLabel, vrf2RD)
	vrf2LBIngressIPNLRIUpdated := bgp.NewLabeledVPNIPAddrPrefix(uint8(vrf2LBIngressIP.BitLen()), vrf2LBIngressIP.String(), dummyLabel, vrf2RDUpdated)

	testAllocator, err := sidmanager.NewStructuredSIDAllocator(locator, structure, types.BehaviorTypeBase)
	if err != nil {
		t.Fatalf("failed to create structured SID allocator: %v", err)
	}
	vrf1SIDInfo, err := testAllocator.Allocate(netip.MustParseAddr("fd00:0:0:0:1::"), "vrf1", "vrf1", types.BehaviorEndDT4)
	if err != nil {
		t.Fatalf("failed to allocate SID for VRF 1: %v", err)
	}
	vrf2SIDInfo, err := testAllocator.Allocate(netip.MustParseAddr("fd00:0:0:0:2::"), "vrf2", "vrf2", types.BehaviorEndDT4)
	if err != nil {
		t.Fatalf("failed to allocate SID for VRF 2: %v", err)
	}

	testSRv6VRF1 := &srv6.VRF{
		VRFID:   1,
		SIDInfo: vrf1SIDInfo,
	}
	testSRv6VRF2 := &srv6.VRF{
		VRFID:   2,
		SIDInfo: vrf2SIDInfo,
	}

	tests := []struct {
		name            string
		prevMetadata    ServiceVRFReconcilerMetadata
		vrfConfigs      []*v1alpha1.IsovalentBGPVRFConfig
		adverts         []*v1alpha1.IsovalentBGPAdvertisement
		services        []*slim_corev1.Service
		endpoints       []*k8s.Endpoints
		bgpNodeInstance *v1alpha1.IsovalentBGPNodeInstance
		expectedAdverts VRFAdvertisements
		expectedPaths   vrfSimplePathsMap // to keep tests simple, compare nlri which is RD:LBVIP
	}{
		{
			name: "pre config: none, new config: 2 VRFs, expect: 2 paths",
			prevMetadata: ServiceVRFReconcilerMetadata{ // empty metadata
				vrfPaths:   make(VRFPaths),
				vrfAdverts: make(VRFAdvertisements),
			},
			vrfConfigs:      []*v1alpha1.IsovalentBGPVRFConfig{vrf1Config, vrf2Config},
			adverts:         []*v1alpha1.IsovalentBGPAdvertisement{vrf1Advert, vrf2Advert},
			services:        []*slim_corev1.Service{vrf1LBSvc, vrf2LBSvc},
			endpoints:       []*k8s.Endpoints{vrf1SvcEP1, vrf2SvcEP1},
			bgpNodeInstance: testBGPNodeInstance,
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPaths: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRI.String()},
					},
				},
			},
		},
		{
			name: "pre config: 2 path, new config: 1 VRF, expect: 1 path removed, 1 path unchanged",
			prevMetadata: ServiceVRFReconcilerMetadata{
				vrfPaths: VRFPaths{
					"vrf1": reconcilerv2.ResourceAFPathsMap{
						resource.Key{Name: vrf1LBSvc.Name}: reconcilerv2.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconcilerv2.PathMap{
								vrf1LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf1LBIngressIPNLRI}, // dummy path
							},
						},
					},
					"vrf2": reconcilerv2.ResourceAFPathsMap{
						resource.Key{Name: vrf2LBSvc.Name}: reconcilerv2.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconcilerv2.PathMap{
								vrf2LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf2LBIngressIPNLRI}, // dummy path
							},
						},
					},
				},
				vrfAdverts: VRFAdvertisements{
					"vrf1": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
					},
					"vrf2": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
					},
				},
			},
			vrfConfigs:      []*v1alpha1.IsovalentBGPVRFConfig{vrf1Config},
			adverts:         []*v1alpha1.IsovalentBGPAdvertisement{vrf1Advert, vrf2Advert},
			services:        []*slim_corev1.Service{vrf1LBSvc, vrf2LBSvc},
			endpoints:       []*k8s.Endpoints{vrf1SvcEP1, vrf2SvcEP1},
			bgpNodeInstance: testBGPNodeInstance,
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
				},
			},
			expectedPaths: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
			},
		},
		{
			name: "pre config: 2 path, new config: no advertisement, expect: 2 paths removed",
			prevMetadata: ServiceVRFReconcilerMetadata{
				vrfPaths: VRFPaths{
					"vrf1": reconcilerv2.ResourceAFPathsMap{
						resource.Key{Name: vrf1LBSvc.Name}: reconcilerv2.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconcilerv2.PathMap{
								vrf1LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf1LBIngressIPNLRI}, // dummy path
							},
						},
					},
					"vrf2": reconcilerv2.ResourceAFPathsMap{
						resource.Key{Name: vrf2LBSvc.Name}: reconcilerv2.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconcilerv2.PathMap{
								vrf2LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf2LBIngressIPNLRI}, // dummy path
							},
						},
					},
				},
				vrfAdverts: VRFAdvertisements{
					"vrf1": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
					},
					"vrf2": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
					},
				},
			},
			vrfConfigs:      []*v1alpha1.IsovalentBGPVRFConfig{vrf1Config, vrf2Config},
			adverts:         []*v1alpha1.IsovalentBGPAdvertisement{},
			services:        []*slim_corev1.Service{vrf1LBSvc, vrf2LBSvc},
			endpoints:       []*k8s.Endpoints{vrf1SvcEP1, vrf2SvcEP1},
			bgpNodeInstance: testBGPNodeInstance,
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: nil,
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: nil,
				},
			},
			expectedPaths: vrfSimplePathsMap{},
		},
		{
			name: "pre config: 2 path, new config: no vrf config, expect: 2 paths removed",
			prevMetadata: ServiceVRFReconcilerMetadata{
				vrfPaths: VRFPaths{
					"vrf1": reconcilerv2.ResourceAFPathsMap{
						resource.Key{Name: vrf1LBSvc.Name}: reconcilerv2.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconcilerv2.PathMap{
								vrf1LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf1LBIngressIPNLRI}, // dummy path
							},
						},
					},
					"vrf2": reconcilerv2.ResourceAFPathsMap{
						resource.Key{Name: vrf2LBSvc.Name}: reconcilerv2.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconcilerv2.PathMap{
								vrf2LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf2LBIngressIPNLRI}, // dummy path
							},
						},
					},
				},
				vrfAdverts: VRFAdvertisements{
					"vrf1": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
					},
					"vrf2": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
					},
				},
			},
			vrfConfigs:      []*v1alpha1.IsovalentBGPVRFConfig{},
			adverts:         []*v1alpha1.IsovalentBGPAdvertisement{vrf1Advert, vrf2Advert},
			services:        []*slim_corev1.Service{vrf1LBSvc, vrf2LBSvc},
			endpoints:       []*k8s.Endpoints{vrf1SvcEP1, vrf2SvcEP1},
			bgpNodeInstance: testBGPNodeInstance,
			expectedAdverts: VRFAdvertisements{},
			expectedPaths:   vrfSimplePathsMap{},
		},
		{
			name: "pre config: 2 path, new config: updated RDs, expect: 2 updated paths",
			prevMetadata: ServiceVRFReconcilerMetadata{
				vrfPaths: VRFPaths{
					"vrf1": reconcilerv2.ResourceAFPathsMap{
						resource.Key{Name: vrf1LBSvc.Name}: reconcilerv2.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconcilerv2.PathMap{
								vrf1LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf1LBIngressIPNLRI}, // dummy path with old RD
							},
						},
					},
					"vrf2": reconcilerv2.ResourceAFPathsMap{
						resource.Key{Name: vrf2LBSvc.Name}: reconcilerv2.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconcilerv2.PathMap{
								vrf2LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf2LBIngressIPNLRI}, // dummy path with old RD
							},
						},
					},
				},
				vrfAdverts: VRFAdvertisements{
					"vrf1": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
					},
					"vrf2": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
					},
				},
			},
			vrfConfigs:      []*v1alpha1.IsovalentBGPVRFConfig{vrf1Config, vrf2Config},
			adverts:         []*v1alpha1.IsovalentBGPAdvertisement{vrf1Advert, vrf2Advert},
			services:        []*slim_corev1.Service{vrf1LBSvc, vrf2LBSvc},
			endpoints:       []*k8s.Endpoints{vrf1SvcEP1, vrf2SvcEP1},
			bgpNodeInstance: testBGPNodeInstanceUpdatedRD, // updated RD
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPaths: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRIUpdated.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRIUpdated.String()},
					},
				},
			},
		},
		{
			name: "pre config: 2 path, new config: delete VRFs, expect: empty paths",
			prevMetadata: ServiceVRFReconcilerMetadata{
				vrfPaths: VRFPaths{
					"vrf1": reconcilerv2.ResourceAFPathsMap{
						resource.Key{Name: vrf1LBSvc.Name}: reconcilerv2.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconcilerv2.PathMap{
								vrf1LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf1LBIngressIPNLRI},
							},
						},
					},
					"vrf2": reconcilerv2.ResourceAFPathsMap{
						resource.Key{Name: vrf2LBSvc.Name}: reconcilerv2.AFPathsMap{
							{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: reconcilerv2.PathMap{
								vrf2LBIngressIPNLRI.String(): &bgptypes.Path{NLRI: vrf2LBIngressIPNLRI},
							},
						},
					},
				},
				vrfAdverts: VRFAdvertisements{
					"vrf1": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
					},
					"vrf2": FamilyAdvertisements{
						{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
					},
				},
			},
			vrfConfigs:      []*v1alpha1.IsovalentBGPVRFConfig{vrf1Config, vrf2Config},
			adverts:         []*v1alpha1.IsovalentBGPAdvertisement{vrf1Advert, vrf2Advert},
			services:        []*slim_corev1.Service{vrf1LBSvc, vrf2LBSvc},
			endpoints:       []*k8s.Endpoints{vrf1SvcEP1, vrf2SvcEP1},
			bgpNodeInstance: testBGPNodeInstanceUpdatedNoVRF, // No VRFs
			expectedAdverts: VRFAdvertisements{},
			expectedPaths:   vrfSimplePathsMap{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			// IsovalentAdvertisement mock
			vrfConfigMockStore := store.NewMockBGPCPResourceStore[*v1alpha1.IsovalentBGPVRFConfig]()
			for _, vrfConfig := range tt.vrfConfigs {
				vrfConfigMockStore.Upsert(vrfConfig)
			}
			advertMockStore := newMockResourceStore[*v1alpha1.IsovalentBGPAdvertisement]()
			for _, advert := range tt.adverts {
				advertMockStore.Upsert(advert)
			}
			isoAdverts := &IsovalentAdvertisement{
				logger:  svcVRFTestLogger,
				adverts: advertMockStore,
				vrfs:    vrfConfigMockStore,
			}
			isoAdverts.initialized.Store(true)

			// service mocks
			svcStore := store.NewFakeDiffStore[*slim_corev1.Service]()
			for _, svc := range tt.services {
				svcStore.Upsert(svc)
			}
			epStore := store.NewFakeDiffStore[*k8s.Endpoints]()
			for _, ep := range tt.endpoints {
				epStore.Upsert(ep)
			}

			// srv6 manager mock
			srv6Manager := newMockSRv6Manager(map[k8stypes.NamespacedName]*srv6.VRF{
				{Name: "vrf1"}: testSRv6VRF1,
				{Name: "vrf2"}: testSRv6VRF2,
			})

			svcVRFReconciler := &ServiceVRFReconciler{
				logger:       svcVRFTestLogger,
				adverts:      isoAdverts,
				svcDiffStore: svcStore,
				epDiffStore:  epStore,
				upgrader:     newUpgraderMock(tt.bgpNodeInstance),
				srv6Paths: &srv6Paths{
					Logger:      svcVRFTestLogger,
					SRv6Manager: srv6Manager,
				},
				srv6Manager: srv6Manager,
			}

			// setup preconfig
			testOSSBGPInstance := instance.NewFakeBGPInstance()
			testOSSBGPInstance.Metadata[svcVRFReconciler.Name()] = tt.prevMetadata

			// reconcile twice to test idempotency
			for i := 0; i < 2; i++ {
				err := svcVRFReconciler.Reconcile(context.Background(), reconcilerv2.ReconcileParams{
					BGPInstance: testOSSBGPInstance,
					CiliumNode:  testCiliumNodeConfig,
				})
				req.NoError(err)
			}

			// check if the expected metadata is the same as the actual metadata
			runningMetadata := testOSSBGPInstance.Metadata[svcVRFReconciler.Name()].(ServiceVRFReconcilerMetadata)
			req.Equal(tt.expectedAdverts, runningMetadata.vrfAdverts)

			// check expected Paths
			compareSimplePath(req, tt.expectedPaths, runningMetadata.vrfPaths)
		})
	}
}

func TestServiceVRFPartialReconcile(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)

	vrf1RD, err := bgp.ParseRouteDistinguisher("65001:1")
	if err != nil {
		t.Fatalf("failed to parse RD: %v", err)
	}
	vrf2RD, err := bgp.ParseRouteDistinguisher("65001:2")
	if err != nil {
		t.Fatalf("failed to parse RD: %v", err)
	}

	vrf1LBIngressIPNLRI := bgp.NewLabeledVPNIPAddrPrefix(uint8(vrf1LBIngressIP.BitLen()), vrf1LBIngressIP.String(), dummyLabel, vrf1RD)
	vrf2LBIngressIPNLRI := bgp.NewLabeledVPNIPAddrPrefix(uint8(vrf2LBIngressIP.BitLen()), vrf2LBIngressIP.String(), dummyLabel, vrf2RD)

	testAllocator, err := sidmanager.NewStructuredSIDAllocator(locator, structure, types.BehaviorTypeBase)
	if err != nil {
		t.Fatalf("failed to create structured SID allocator: %v", err)
	}
	testAllocator2, err := sidmanager.NewStructuredSIDAllocator(locator, structure, types.BehaviorTypeUSID)
	if err != nil {
		t.Fatalf("failed to create structured SID allocator: %v", err)
	}
	vrf1SIDInfo, err := testAllocator.Allocate(netip.MustParseAddr("fd00:0:0:0:1::"), "vrf1", "vrf1", types.BehaviorEndDT4)
	if err != nil {
		t.Fatalf("failed to allocate SID for VRF 1: %v", err)
	}
	vrf1SIDInfoUpdated, err := testAllocator2.Allocate(netip.MustParseAddr("fd00:0:0:0:1::"), "vrf1", "vrf1", types.BehaviorUDT4)
	if err != nil {
		t.Fatalf("failed to allocate updated SID for VRF 1: %v", err)
	}
	vrf2SIDInfo, err := testAllocator.Allocate(netip.MustParseAddr("fd00:0:0:0:2::"), "vrf2", "vrf2", types.BehaviorEndDT4)
	if err != nil {
		t.Fatalf("failed to allocate SID for VRF 2: %v", err)
	}

	testSRv6VRF1 := &srv6.VRF{
		VRFID:   1,
		SIDInfo: vrf1SIDInfo,
	}
	testSRv6VRF1Updated := &srv6.VRF{
		VRFID:   1,
		SIDInfo: vrf1SIDInfoUpdated,
	}
	testSRv6VRF2 := &srv6.VRF{
		VRFID:   2,
		SIDInfo: vrf2SIDInfo,
	}

	tests := []struct {
		name                       string
		services                   []*slim_corev1.Service
		endpoints                  []*k8s.Endpoints
		expectedAdverts            VRFAdvertisements
		expectedPaths              vrfSimplePathsMap
		expectedVRFSIDs            VRFSIDInfo
		updatedServices            []*slim_corev1.Service
		updatedEPs                 []*k8s.Endpoints
		updatedSRv6VRFs            map[k8stypes.NamespacedName]*srv6.VRF
		expectedAdvertsAfterUpdate VRFAdvertisements
		expectedPathsAfterUpdate   vrfSimplePathsMap
		expectedVRFSIDsAfterUpdate VRFSIDInfo
	}{
		{
			name:      "pre config: none, new config: 2 VRFs, expect: 2 paths",
			services:  []*slim_corev1.Service{vrf1LBSvc, vrf2LBSvc},
			endpoints: []*k8s.Endpoints{vrf1SvcEP1, vrf2SvcEP1},
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPaths: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRI.String()},
					},
				},
			},
			expectedVRFSIDs: VRFSIDInfo{
				"vrf1": vrf1SIDInfo,
				"vrf2": vrf2SIDInfo,
			},
			// No update, after update should be the same as before
			expectedAdvertsAfterUpdate: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPathsAfterUpdate: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRI.String()},
					},
				},
			},
		},
		{
			name:      "pre config: 2 paths, update service to eTP=Cluster, expect 1 path removed, 1 path unchanged",
			services:  []*slim_corev1.Service{vrf1LBSvc, vrf2LBSvc},
			endpoints: []*k8s.Endpoints{vrf1SvcEP1, vrf2SvcEP1},
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPaths: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRI.String()},
					},
				},
			},
			expectedVRFSIDs: VRFSIDInfo{
				"vrf1": vrf1SIDInfo,
				"vrf2": vrf2SIDInfo,
			},
			updatedServices: []*slim_corev1.Service{vrf1LBSvc, vrfSvcETPCluster(vrf2LBSvc)}, // update 1 service to have eTP=Cluster
			expectedAdvertsAfterUpdate: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPathsAfterUpdate: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
			},
			expectedVRFSIDsAfterUpdate: VRFSIDInfo{
				"vrf1": vrf1SIDInfo,
				"vrf2": vrf2SIDInfo,
			},
		},
		{
			name:      "pre config: 1 paths, update service to eTP=Local, expect 1 path added, 1 path unchanged",
			services:  []*slim_corev1.Service{vrf1LBSvc, vrfSvcETPCluster(vrf2LBSvc)}, // start with eTP=Cluster
			endpoints: []*k8s.Endpoints{vrf1SvcEP1, vrf2SvcEP1},
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPaths: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
			},
			expectedVRFSIDs: VRFSIDInfo{
				"vrf1": vrf1SIDInfo,
				"vrf2": vrf2SIDInfo,
			},
			updatedServices: []*slim_corev1.Service{vrf1LBSvc, vrf2LBSvc}, // set eTP=Local
			expectedAdvertsAfterUpdate: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPathsAfterUpdate: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRI.String()},
					},
				},
			},
			expectedVRFSIDsAfterUpdate: VRFSIDInfo{
				"vrf1": vrf1SIDInfo,
				"vrf2": vrf2SIDInfo,
			},
		},
		{
			name:      "pre config: 0 paths, add endpoints, expect 2 path added",
			services:  []*slim_corev1.Service{vrf1LBSvc, vrf2LBSvc}, // start with 2 services
			endpoints: []*k8s.Endpoints{},                           // no endpoints
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPaths: vrfSimplePathsMap{},
			expectedVRFSIDs: VRFSIDInfo{
				"vrf1": vrf1SIDInfo,
				"vrf2": vrf2SIDInfo,
			},
			updatedEPs: []*k8s.Endpoints{vrf1SvcEP1, vrf2SvcEP1}, // add endpoints
			expectedAdvertsAfterUpdate: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPathsAfterUpdate: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRI.String()},
					},
				},
			},
			expectedVRFSIDsAfterUpdate: VRFSIDInfo{
				"vrf1": vrf1SIDInfo,
				"vrf2": vrf2SIDInfo,
			},
		},
		{
			name:      "pre config: 2 paths, update SIDInfo, expect 2 path and SIDInfo updated",
			services:  []*slim_corev1.Service{vrf1LBSvc, vrf2LBSvc}, // start with 2 services
			endpoints: []*k8s.Endpoints{vrf1SvcEP1, vrf2SvcEP1},
			expectedAdverts: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPaths: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRI.String()},
					},
				},
			},
			expectedVRFSIDs: VRFSIDInfo{
				"vrf1": vrf1SIDInfo,
				"vrf2": vrf2SIDInfo,
			},
			// Update SIDInfo
			updatedSRv6VRFs: map[k8stypes.NamespacedName]*srv6.VRF{
				{Name: "vrf1"}: testSRv6VRF1Updated,
				{Name: "vrf2"}: testSRv6VRF2,
			},
			expectedAdvertsAfterUpdate: VRFAdvertisements{
				"vrf1": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf1BGPAdvert},
				},
				"vrf2": FamilyAdvertisements{
					{Afi: "ipv4", Safi: "mpls_vpn"}: []v1alpha1.BGPAdvertisement{vrf2BGPAdvert},
				},
			},
			expectedPathsAfterUpdate: vrfSimplePathsMap{
				"vrf1": resourceAFSimplePathsMap{
					resource.Key{Name: vrf1LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf1LBIngressIPNLRI.String()},
					},
				},
				"vrf2": resourceAFSimplePathsMap{
					resource.Key{Name: vrf2LBSvc.Name}: afSimplePathsMap{
						{Afi: bgptypes.AfiIPv4, Safi: bgptypes.SafiMplsVpn}: []string{vrf2LBIngressIPNLRI.String()},
					},
				},
			},
			expectedVRFSIDsAfterUpdate: VRFSIDInfo{
				"vrf1": vrf1SIDInfoUpdated, // validate with new SID info
				"vrf2": vrf2SIDInfo,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			isoAdverts := &IsovalentAdvertisement{
				logger:  svcVRFTestLogger,
				adverts: InitMockStore[*v1alpha1.IsovalentBGPAdvertisement]([]*v1alpha1.IsovalentBGPAdvertisement{vrf1Advert, vrf2Advert}),
				vrfs:    store.InitMockStore[*v1alpha1.IsovalentBGPVRFConfig]([]*v1alpha1.IsovalentBGPVRFConfig{vrf1Config, vrf2Config}),
			}
			isoAdverts.initialized.Store(true)

			// service mocks
			svcStore := store.NewFakeDiffStore[*slim_corev1.Service]()
			for _, svc := range tt.services {
				svcStore.Upsert(svc)
			}
			epStore := store.NewFakeDiffStore[*k8s.Endpoints]()
			for _, ep := range tt.endpoints {
				epStore.Upsert(ep)
			}

			// srv6 manager mock
			srv6Manager := newMockSRv6Manager(map[k8stypes.NamespacedName]*srv6.VRF{
				{Name: "vrf1"}: testSRv6VRF1,
				{Name: "vrf2"}: testSRv6VRF2,
			})

			svcVRFReconciler := &ServiceVRFReconciler{
				logger:       svcVRFTestLogger,
				adverts:      isoAdverts,
				svcDiffStore: svcStore,
				epDiffStore:  epStore,
				upgrader:     newUpgraderMock(testBGPNodeInstance),
				srv6Paths: &srv6Paths{
					Logger:      svcVRFTestLogger,
					SRv6Manager: srv6Manager,
				},
				srv6Manager: srv6Manager,
			}

			// setup preconfig
			testOSSBGPInstance := instance.NewFakeBGPInstance()

			// reconcile to test initial state
			err := svcVRFReconciler.Reconcile(context.Background(), reconcilerv2.ReconcileParams{
				BGPInstance: testOSSBGPInstance,
				CiliumNode:  testCiliumNodeConfig,
			})
			req.NoError(err)

			// check if the expected metadata is the same as the actual metadata
			runningMetadata := testOSSBGPInstance.Metadata[svcVRFReconciler.Name()].(ServiceVRFReconcilerMetadata)
			req.Equal(tt.expectedAdverts, runningMetadata.vrfAdverts)
			req.Equal(tt.expectedVRFSIDs, runningMetadata.vrfSIDs)
			compareSimplePath(req, tt.expectedPaths, runningMetadata.vrfPaths)

			// update services and endpoints
			for _, svc := range tt.updatedServices {
				svcStore.Upsert(svc)
			}
			for _, ep := range tt.updatedEPs {
				epStore.Upsert(ep)
			}

			// update SRv6 VRFs
			for key, vrf := range tt.updatedSRv6VRFs {
				srv6Manager.upsertVRF(key, vrf)
			}

			// reconcile again to test parital reconciliation
			err = svcVRFReconciler.Reconcile(context.Background(), reconcilerv2.ReconcileParams{
				BGPInstance: testOSSBGPInstance,
				CiliumNode:  testCiliumNodeConfig,
			})
			req.NoError(err)

			// check if the expected metadata is the same as the actual metadata
			runningMetadata = testOSSBGPInstance.Metadata[svcVRFReconciler.Name()].(ServiceVRFReconcilerMetadata)
			req.Equal(tt.expectedAdvertsAfterUpdate, runningMetadata.vrfAdverts)
			// also check if SID is updated
			if len(tt.updatedSRv6VRFs) > 0 {
				req.Equal(tt.expectedVRFSIDsAfterUpdate, runningMetadata.vrfSIDs)
			}
			compareSimplePath(req, tt.expectedPathsAfterUpdate, runningMetadata.vrfPaths)
		})
	}
}
