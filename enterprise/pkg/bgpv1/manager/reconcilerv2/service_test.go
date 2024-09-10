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
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/enterprise/pkg/annotation"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/service"
)

var (
	svcTestLogger = logrus.WithField("unit_test", "reconcilerv2_service")
)

func Test_ServiceHealthChecker(t *testing.T) {
	ingressV4 := "192.168.0.1"
	ingressV4Prefix := ingressV4 + "/32"
	ingressV4Path := types.NewPathForPrefix(netip.MustParsePrefix(ingressV4Prefix))
	ingressV6 := "fd00:192:168::1"
	ingressV6Prefix := ingressV6 + "/128"
	ingressV6Path := types.NewPathForPrefix(netip.MustParsePrefix(ingressV6Prefix))

	svcSelector := slim_metav1.LabelSelector{MatchLabels: map[string]string{"advertise": "bgp"}}
	svcKey := resource.Key{Name: "test-svc", Namespace: "default"}
	ingressV4Frontend := loadbalancer.L3n4Addr{
		AddrCluster: cmtypes.MustParseAddrCluster(ingressV4),
		L4Addr:      loadbalancer.L4Addr{Protocol: loadbalancer.TCP, Port: 80},
	}
	ingressV6Frontend := loadbalancer.L3n4Addr{
		AddrCluster: cmtypes.MustParseAddrCluster(ingressV6),
		L4Addr:      loadbalancer.L4Addr{Protocol: loadbalancer.TCP, Port: 80},
	}
	fakeV4Frontend := loadbalancer.L3n4Addr{
		AddrCluster: cmtypes.MustParseAddrCluster("1.2.3.4"),
		L4Addr:      loadbalancer.L4Addr{Protocol: loadbalancer.TCP, Port: 80},
	}

	instanceConfig := &v2alpha1.CiliumBGPNodeInstance{
		Name:     "bgp-65001",
		LocalASN: ptr.To[int64](65001),
		Peers: []v2alpha1.CiliumBGPNodePeer{
			{
				Name:        "peer-65001",
				PeerAddress: ptr.To[string]("10.10.10.1"),
				PeerConfigRef: &v2alpha1.PeerConfigReference{
					Group: "cilium.io",
					Kind:  "CiliumBGPPeerConfig",
					Name:  "peer-config",
				},
			},
		},
	}

	peerConfig := &v2alpha1.CiliumBGPPeerConfig{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "peer-config",
		},
		Spec: v2alpha1.CiliumBGPPeerConfigSpec{
			Families: []v2alpha1.CiliumBGPFamilyWithAdverts{
				{
					CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
						Afi:  "ipv4",
						Safi: "unicast",
					},
					Advertisements: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"advertise": "bgp",
						},
					},
				},
				{
					CiliumBGPFamily: v2alpha1.CiliumBGPFamily{
						Afi:  "ipv6",
						Safi: "unicast",
					},
					Advertisements: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"advertise": "bgp",
						},
					},
				},
			},
		},
	}

	svcAdvertisement := &v2alpha1.CiliumBGPAdvertisement{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "svc-advertisement",
			Labels: map[string]string{
				"advertise": "bgp",
			},
		},
		Spec: v2alpha1.CiliumBGPAdvertisementSpec{
			Advertisements: []v2alpha1.BGPAdvertisement{
				{
					AdvertisementType: v2alpha1.BGPServiceAdvert,
					Service: &v2alpha1.BGPServiceOptions{
						Addresses: []v2alpha1.BGPServiceAddressType{v2alpha1.BGPLoadBalancerIPAddr},
					},
					Selector: &slim_metav1.LabelSelector{
						MatchLabels: map[string]string{
							"advertise": "bgp",
						},
					},
				},
			},
		},
	}

	peerSvcAdvertisements := reconcilerv2.PeerAdvertisements{
		"peer-65001": reconcilerv2.PeerFamilyAdvertisements{
			{Afi: "ipv4", Safi: "unicast"}: svcAdvertisement.Spec.Advertisements,
			{Afi: "ipv6", Safi: "unicast"}: svcAdvertisement.Spec.Advertisements,
		},
	}

	svcRoutePolicy := &types.RoutePolicy{
		Name: reconcilerv2.PolicyName(instanceConfig.Peers[0].Name, "ipv4", v2alpha1.BGPServiceAdvert, fmt.Sprintf("%s-%s-LoadBalancerIP", svcKey.Name, svcKey.Namespace)),
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(ingressV4Prefix),
							PrefixLenMin: 32,
							PrefixLenMax: 32,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				},
			},
		},
	}

	svcRoutePolicyV6 := &types.RoutePolicy{
		Name: reconcilerv2.PolicyName(instanceConfig.Peers[0].Name, "ipv6", v2alpha1.BGPServiceAdvert, fmt.Sprintf("%s-%s-LoadBalancerIP", svcKey.Name, svcKey.Namespace)),
		Type: types.RoutePolicyTypeExport,
		Statements: []*types.RoutePolicyStatement{
			{
				Conditions: types.RoutePolicyConditions{
					MatchNeighbors: []string{"10.10.10.1/32"},
					MatchPrefixes: []*types.RoutePolicyPrefixMatch{
						{
							CIDR:         netip.MustParsePrefix(ingressV6Prefix),
							PrefixLenMin: 128,
							PrefixLenMax: 128,
						},
					},
				},
				Actions: types.RoutePolicyActions{
					RouteAction: types.RoutePolicyActionAccept,
				},
			},
		},
	}

	testSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:        svcKey.Name,
			Namespace:   svcKey.Namespace,
			Labels:      svcSelector.MatchLabels,
			Annotations: map[string]string{annotation.ServiceHealthProbeInterval: "5s"},
		},
		Spec: slim_corev1.ServiceSpec{
			Type: slim_corev1.ServiceTypeLoadBalancer,
			Ports: []slim_corev1.ServicePort{
				{
					Port: 80,
				},
			},
		},
		Status: slim_corev1.ServiceStatus{
			LoadBalancer: slim_corev1.LoadBalancerStatus{
				Ingress: []slim_corev1.LoadBalancerIngress{
					{
						IP: ingressV4,
					},
				},
			},
		},
	}
	testSvcNoHCAnnotation := testSvc.DeepCopy()
	testSvcNoHCAnnotation.Annotations = nil

	testSvcThreshold2 := testSvc.DeepCopy()
	testSvcThreshold2.Annotations = map[string]string{
		annotation.ServiceHealthProbeInterval:         "5s",
		annotation.ServiceHealthBGPAdvertiseThreshold: "2",
	}

	testSvcNoAdvertisement := testSvc.DeepCopy()
	testSvcNoAdvertisement.Annotations = map[string]string{
		annotation.ServiceNoAdvertisement: "true",
	}

	testSvcDualStack := testSvc.DeepCopy()
	testSvcDualStack.Status.LoadBalancer.Ingress = append(testSvcDualStack.Status.LoadBalancer.Ingress, slim_corev1.LoadBalancerIngress{IP: ingressV6})

	type backendUpdate struct {
		svcName        loadbalancer.ServiceName
		frontend       loadbalancer.L3n4Addr
		activeBackends []loadbalancer.Backend
	}

	var table = []struct {
		// name of the test case
		name string
		// advertisements to be upserted in the test step
		upsertedAdverts []*v2alpha1.CiliumBGPAdvertisement
		// the services which will be upserted in the test step
		upsertedServices []*slim_corev1.Service
		// the services which will be deleted in the test step
		deletedServices []resource.Key
		// a list of backend updates applied during the test step
		backendUpdates []backendUpdate
		// the expected metadata after the reconciliation
		expectedMetadata reconcilerv2.ServiceReconcilerMetadata
	}{
		{
			name:             "advertise new service with no health updates",
			upsertedAdverts:  []*v2alpha1.CiliumBGPAdvertisement{svcAdvertisement},
			upsertedServices: []*slim_corev1.Service{testSvc},
			backendUpdates:   nil,
			expectedMetadata: reconcilerv2.ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: ingressV4Path,
						},
					},
				},
			},
		},
		{
			name: "advertise the service after healthy backend update",
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
			},
			expectedMetadata: reconcilerv2.ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: ingressV4Path,
						},
					},
				},
			},
		},
		{
			name:             "advertise the service after multiple backend updates",
			upsertedServices: []*slim_corev1.Service{testSvc},
			backendUpdates: []backendUpdate{
				// first no backends
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
				// frontend not matching the service - unrelated
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}},
				},
				// finally with healthy backends
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}, {ID: 2}}, // healthy
				},
			},
			expectedMetadata: reconcilerv2.ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: ingressV4Path,
						},
					},
				},
			},
		},
		{
			name:             "do not advertise the service after unhealthy backend update",
			upsertedServices: []*slim_corev1.Service{testSvc},
			backendUpdates: []backendUpdate{
				// no active backends
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
				// frontend not matching the service - unrelated
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       fakeV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}, {ID: 2}},
				},
			},
			expectedMetadata: reconcilerv2.ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: nil,
					},
				},
			},
		},
		{
			name:             "advertise the service even after unhealthy backend update if health-checking is disabled",
			upsertedServices: []*slim_corev1.Service{testSvcNoHCAnnotation}, // missing health-check-probe-interval annotation
			backendUpdates: []backendUpdate{
				// frontend not matching the service - unrelated
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
			},
			expectedMetadata: reconcilerv2.ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: ingressV4Path,
						},
					},
				},
			},
		},
		{
			name:             "do not advertise the service after unhealthy backend update",
			upsertedServices: []*slim_corev1.Service{testSvc},
			backendUpdates: []backendUpdate{
				// first with active backends
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}, {ID: 2}},
				},
				// then no active backends
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
			},
			expectedMetadata: reconcilerv2.ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: nil,
					},
				},
			},
		},
		{
			name:            "do not advertise deleted service even after healthy backend update",
			deletedServices: []resource.Key{svcKey},
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
			},
			expectedMetadata: reconcilerv2.ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies:  reconcilerv2.ResourceRoutePolicyMap{},
				ServicePaths:          reconcilerv2.ResourceAFPathsMap{},
			},
		},
		{
			name:             "advertise existing service with multiple frontend ports - all healthy",
			upsertedServices: []*slim_corev1.Service{testSvc},
			backendUpdates: []backendUpdate{
				{
					svcName: loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster(ingressV4),
						L4Addr:      loadbalancer.L4Addr{Protocol: loadbalancer.TCP, Port: 80},
					},
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
				{
					svcName: loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster(ingressV4),
						L4Addr:      loadbalancer.L4Addr{Protocol: loadbalancer.TCP, Port: 443},
					},
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
			},
			expectedMetadata: reconcilerv2.ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: ingressV4Path,
						},
					},
				},
			},
		},
		{
			name: "withdraw the service with multiple frontend ports - 1 unhealthy port",
			backendUpdates: []backendUpdate{
				{
					svcName: loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster(ingressV4),
						L4Addr:      loadbalancer.L4Addr{Protocol: loadbalancer.TCP, Port: 80},
					},
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
				{
					svcName: loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster(ingressV4),
						L4Addr:      loadbalancer.L4Addr{Protocol: loadbalancer.TCP, Port: 443},
					},
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
			},
			expectedMetadata: reconcilerv2.ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: nil,
					},
				},
			},
		},
		{
			name:             "advertise dual-stack service with multiple frontend IPs - all healthy",
			upsertedServices: []*slim_corev1.Service{testSvcDualStack},
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV6Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
			},
			expectedMetadata: reconcilerv2.ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name:   svcRoutePolicy,
						svcRoutePolicyV6.Name: svcRoutePolicyV6,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: ingressV4Path,
						},
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: ingressV6Path,
						},
					},
				},
			},
		},
		{
			name: "partially advertise dual-stack service with multiple frontend IPs - 1 unhealthy IP",
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV6Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
			},
			expectedMetadata: reconcilerv2.ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name:   svcRoutePolicy,
						svcRoutePolicyV6.Name: svcRoutePolicyV6,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: nil,
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: {
							ingressV6Prefix: ingressV6Path,
						},
					},
				},
			},
		},
		{
			name: "do not advertise dual-stack service with multiple frontend IPs - all unhealthy",
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV6Frontend,
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
			},
			expectedMetadata: reconcilerv2.ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name:   svcRoutePolicy,
						svcRoutePolicyV6.Name: svcRoutePolicyV6,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: nil,
						{Afi: types.AfiIPv6, Safi: types.SafiUnicast}: nil,
					},
				},
			},
		},
		{
			name:             "advertise existing service after a backend update - non-default threshold, healthy",
			upsertedServices: []*slim_corev1.Service{testSvcThreshold2},
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}, {ID: 2}}, // 2 backends - healthy
				},
			},
			expectedMetadata: reconcilerv2.ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: {
							ingressV4Prefix: ingressV4Path,
						},
					},
				},
			},
		},
		{
			name: "withdraw existing service after a backend update - non-default threshold, unhealthy",
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // 1 backend - unhealthy
				},
			},
			expectedMetadata: reconcilerv2.ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{
					svcKey: reconcilerv2.AFPathsMap{
						{Afi: types.AfiIPv4, Safi: types.SafiUnicast}: nil,
					},
				},
			},
		},
		{
			name:             "do not advertise service with no-advertisement annotation",
			upsertedServices: []*slim_corev1.Service{testSvcNoAdvertisement},
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.ServiceName{Name: svcKey.Name, Namespace: svcKey.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
			},
			expectedMetadata: reconcilerv2.ServiceReconcilerMetadata{
				ServiceAdvertisements: peerSvcAdvertisements,
				ServiceRoutePolicies: reconcilerv2.ResourceRoutePolicyMap{
					svcKey: reconcilerv2.RoutePolicyMap{
						svcRoutePolicy.Name: svcRoutePolicy,
					},
				},
				ServicePaths: reconcilerv2.ResourceAFPathsMap{},
			},
		},
	}

	logrus.SetLevel(logrus.DebugLevel)

	testBGPInstance := instance.NewFakeBGPInstance()
	peerConfigs := []*v2alpha1.CiliumBGPPeerConfig{peerConfig}

	advertStore := store.NewMockBGPCPResourceStore[*v2alpha1.CiliumBGPAdvertisement]()
	svcDiffstore := store.NewFakeDiffStore[*slim_corev1.Service]()
	epDiffStore := store.NewFakeDiffStore[*k8s.Endpoints]()

	ossParams := reconcilerv2.ServiceReconcilerIn{
		In:     cell.In{},
		Logger: svcTestLogger,
		PeerAdvert: reconcilerv2.NewCiliumPeerAdvertisement(
			reconcilerv2.PeerAdvertisementIn{
				Logger:          svcTestLogger,
				PeerConfigStore: store.InitMockStore[*v2alpha1.CiliumBGPPeerConfig](peerConfigs),
				AdvertStore:     advertStore,
			}),
		SvcDiffStore: svcDiffstore,
		EPDiffStore:  epDiffStore,
	}
	ossReconciler := reconcilerv2.NewServiceReconciler(ossParams).Reconciler.(*reconcilerv2.ServiceReconciler)

	ceeParams := ServiceReconcilerIn{
		In:        cell.In{},
		Lifecycle: &cell.DefaultLifecycle{},
		Cfg:       Config{SvcHealthCheckingEnabled: true},
		Logger:    svcTestLogger,
		Signaler:  signaler.NewBGPCPSignaler(),
	}
	ceeReconciler := NewServiceReconciler(ceeParams).Reconciler.(*ServiceReconciler)
	ceeReconciler.ossServiceReconciler = ossReconciler

	ceeReconciler.Init(testBGPInstance)
	defer ceeReconciler.Cleanup(testBGPInstance)

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			for _, advert := range tt.upsertedAdverts {
				advertStore.Upsert(advert)
			}
			for _, obj := range tt.upsertedServices {
				svcDiffstore.Upsert(obj)
			}
			for _, key := range tt.deletedServices {
				svcDiffstore.Delete(key)
			}

			// update active backends
			for _, upd := range tt.backendUpdates {
				svcInfo := service.HealthUpdateSvcInfo{
					Name:           upd.svcName,
					Addr:           upd.frontend,
					SvcType:        loadbalancer.SVCTypeLoadBalancer,
					ActiveBackends: upd.activeBackends,
				}
				ceeReconciler.ServiceHealthUpdate(svcInfo)
			}

			err := ceeReconciler.Reconcile(context.Background(), reconcilerv2.ReconcileParams{
				BGPInstance:   testBGPInstance,
				DesiredConfig: instanceConfig,
				CiliumNode: &v2.CiliumNode{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node1",
					},
				},
			})
			req.NoError(err)

			serviceMetadataEqual(req, tt.expectedMetadata, ossReconciler.GetMetadata(testBGPInstance))
		})
	}
}

func serviceMetadataEqual(req *require.Assertions, expectedMetadata, runningMetadata reconcilerv2.ServiceReconcilerMetadata) {
	req.Truef(reconcilerv2.PeerAdvertisementsEqual(expectedMetadata.ServiceAdvertisements, runningMetadata.ServiceAdvertisements),
		"ServiceAdvertisements mismatch, expected: %v, got: %v", expectedMetadata.ServiceAdvertisements, runningMetadata.ServiceAdvertisements)

	req.Equalf(len(expectedMetadata.ServicePaths), len(runningMetadata.ServicePaths),
		"ServicePaths length mismatch, expected: %v, got: %v", expectedMetadata.ServicePaths, runningMetadata.ServicePaths)

	for svc, expectedSvcPaths := range expectedMetadata.ServicePaths {
		runningSvcPaths, exists := runningMetadata.ServicePaths[svc]
		req.Truef(exists, "Service not found in running: %v", svc)

		runningFamilyPaths := make(map[types.Family]map[string]struct{})
		for family, paths := range runningSvcPaths {
			pathSet := make(map[string]struct{})

			for pathKey := range paths {
				pathSet[pathKey] = struct{}{}
			}
			runningFamilyPaths[family] = pathSet
		}

		expectedFamilyPaths := make(map[types.Family]map[string]struct{})
		for family, paths := range expectedSvcPaths {
			pathSet := make(map[string]struct{})

			for pathKey := range paths {
				pathSet[pathKey] = struct{}{}
			}
			expectedFamilyPaths[family] = pathSet
		}

		req.Equal(expectedFamilyPaths, runningFamilyPaths)
	}

	req.Equalf(expectedMetadata.ServiceRoutePolicies, runningMetadata.ServiceRoutePolicies,
		"ServiceRoutePolicies mismatch, expected: %v, got: %v", expectedMetadata.ServiceRoutePolicies, runningMetadata.ServiceRoutePolicies)
}
