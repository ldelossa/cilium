// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconciler

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/enterprise/pkg/annotation"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/service"
)

func TestLBServiceHealthChecker(t *testing.T) {
	svcSelector := slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}}
	svcName := resource.Key{Name: "test-svc", Namespace: "default"}
	ingressV4 := "192.168.0.1"
	ingressV4Prefix := ingressV4 + "/32"
	ingressV6 := "fd00:192:168::1"
	ingressV6Prefix := ingressV6 + "/128"
	ingressV4Frontend := loadbalancer.L3n4Addr{AddrCluster: cmtypes.MustParseAddrCluster(ingressV4)}
	fakeV4Frontend := loadbalancer.L3n4Addr{AddrCluster: cmtypes.MustParseAddrCluster("1.2.3.4")}

	testSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:        svcName.Name,
			Namespace:   svcName.Namespace,
			Labels:      svcSelector.MatchLabels,
			Annotations: map[string]string{annotation.ServiceHealthProbeInterval: "5s"},
		},
		Spec: slim_corev1.ServiceSpec{
			Type: slim_corev1.ServiceTypeLoadBalancer,
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

	testSvcDualStack := testSvc.DeepCopy()
	testSvcDualStack.Status.LoadBalancer.Ingress = append(testSvcDualStack.Status.LoadBalancer.Ingress,
		slim_corev1.LoadBalancerIngress{IP: ingressV6})

	type backendUpdate struct {
		svcName        loadbalancer.ServiceName
		frontend       loadbalancer.L3n4Addr
		activeBackends []loadbalancer.Backend
	}

	var table = []struct {
		// name of the test case
		name string
		// the services which will be existing in the diffstore
		existingServices []*slim_corev1.Service
		// the services which will be "upserted" in the diffstore
		upsertedServices []*slim_corev1.Service
		// the services which will be "deleted" in the diffstore
		deletedServices []resource.Key
		// a list of backend updates during the test
		backendUpdates []backendUpdate
		// the expected advertised services after the reconciliation
		advertisedAfter map[resource.Key][]string
		// error nil or not
		err error
	}{
		{
			name:             "advertise new service with no health updates",
			upsertedServices: []*slim_corev1.Service{testSvc},
			backendUpdates:   nil,
			advertisedAfter: map[resource.Key][]string{
				svcName: {
					ingressV4Prefix, // no health updates = assume the service is healthy
				},
			},
		},
		{
			name:             "advertise new service with a backend update",
			upsertedServices: []*slim_corev1.Service{testSvc},
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
			},
			advertisedAfter: map[resource.Key][]string{
				svcName: {
					ingressV4Prefix,
				},
			},
		},
		{
			name:             "advertise existing service after a backend update",
			existingServices: []*slim_corev1.Service{testSvc},
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
			},
			advertisedAfter: map[resource.Key][]string{
				svcName: {
					ingressV4Prefix,
				},
			},
		},
		{
			name:             "advertise new service with multiple backend updates",
			upsertedServices: []*slim_corev1.Service{testSvc},
			backendUpdates: []backendUpdate{
				// first no backends
				{
					svcName:        loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
				// frontend not matching the service - unrelated
				{
					svcName:        loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend:       fakeV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}},
				},
				// finally with healthy backends
				{
					svcName:        loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}, {ID: 2}}, // healthy
				},
			},
			advertisedAfter: map[resource.Key][]string{
				svcName: {
					ingressV4Prefix,
				},
			},
		},
		{
			name:             "do not advertise new service after unhealthy backend update",
			upsertedServices: []*slim_corev1.Service{testSvc},
			backendUpdates: []backendUpdate{
				// no active backends
				{
					svcName:        loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
				// frontend not matching the service - unrelated
				{
					svcName:        loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend:       fakeV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}, {ID: 2}},
				},
			},
			advertisedAfter: map[resource.Key][]string{},
		},
		{
			name:             "advertise new service even after unhealthy backend update if health-checking is disabled",
			upsertedServices: []*slim_corev1.Service{testSvcNoHCAnnotation}, // missing health-check-probe-interval annotation
			backendUpdates: []backendUpdate{
				// frontend not matching the service - unrelated
				{
					svcName:        loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
			},
			advertisedAfter: map[resource.Key][]string{
				svcName: {
					ingressV4Prefix,
				},
			},
		},
		{
			name:             "withdraw existing service after unhealthy backend update",
			existingServices: []*slim_corev1.Service{testSvc},
			backendUpdates: []backendUpdate{
				// first with active backends
				{
					svcName:        loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}, {ID: 2}},
				},
				// then no active backends
				{
					svcName:        loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
			},
			advertisedAfter: map[resource.Key][]string{},
		},
		{
			name:             "withdraw deleted service even after healthy backend update",
			existingServices: []*slim_corev1.Service{testSvc},
			deletedServices:  []resource.Key{svcName},
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
			},
			advertisedAfter: map[resource.Key][]string{},
		},
		{
			name:             "advertise existing service with multiple frontend ports - all healthy",
			existingServices: []*slim_corev1.Service{testSvc},
			backendUpdates: []backendUpdate{
				{
					svcName: loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster(ingressV4),
						L4Addr:      loadbalancer.L4Addr{Protocol: loadbalancer.TCP, Port: 80},
					},
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
				{
					svcName: loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster(ingressV4),
						L4Addr:      loadbalancer.L4Addr{Protocol: loadbalancer.TCP, Port: 443},
					},
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
			},
			advertisedAfter: map[resource.Key][]string{
				svcName: {
					ingressV4Prefix,
				},
			},
		},
		{
			name:             "withdraw existing service with multiple frontend ports - 1 unhealthy port",
			existingServices: []*slim_corev1.Service{testSvc},
			backendUpdates: []backendUpdate{
				{
					svcName: loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster(ingressV4),
						L4Addr:      loadbalancer.L4Addr{Protocol: loadbalancer.TCP, Port: 80},
					},
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
				{
					svcName: loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster(ingressV4),
						L4Addr:      loadbalancer.L4Addr{Protocol: loadbalancer.TCP, Port: 443},
					},
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
			},
			advertisedAfter: map[resource.Key][]string{},
		},
		{
			name:             "advertise existing service with multiple frontend IPs - all healthy",
			existingServices: []*slim_corev1.Service{testSvcDualStack},
			backendUpdates: []backendUpdate{
				{
					svcName: loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster(ingressV4),
					},
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
				{
					svcName: loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster(ingressV6),
					},
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
			},
			advertisedAfter: map[resource.Key][]string{
				svcName: {
					ingressV4Prefix,
					ingressV6Prefix,
				},
			},
		},
		{
			name:             "withdraw existing service with multiple frontend IPs - 1 unhealthy IP",
			existingServices: []*slim_corev1.Service{testSvcDualStack},
			backendUpdates: []backendUpdate{
				{
					svcName: loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster(ingressV4),
					},
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
				{
					svcName: loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster(ingressV6),
					},
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
			},
			advertisedAfter: map[resource.Key][]string{
				svcName: {
					ingressV6Prefix,
				},
			},
		},
		{
			name:             "withdraw existing service with multiple frontend IPs - all unhealthy",
			existingServices: []*slim_corev1.Service{testSvcDualStack},
			backendUpdates: []backendUpdate{
				{
					svcName: loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster(ingressV4),
					},
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
				{
					svcName: loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend: loadbalancer.L3n4Addr{
						AddrCluster: cmtypes.MustParseAddrCluster(ingressV6),
					},
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
			},
			advertisedAfter: map[resource.Key][]string{},
		},
		{
			name:             "advertise existing service after a backend update - non-default threshold, healthy",
			existingServices: []*slim_corev1.Service{testSvcThreshold2},
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}, {ID: 2}}, // 2 backends - healthy
				},
			},
			advertisedAfter: map[resource.Key][]string{
				svcName: {
					ingressV4Prefix,
				},
			},
		},
		{
			name:             "withdraw existing service after a backend update - non-default threshold, unhealthy",
			existingServices: []*slim_corev1.Service{testSvcThreshold2},
			backendUpdates: []backendUpdate{
				{
					svcName:        loadbalancer.ServiceName{Name: svcName.Name, Namespace: svcName.Namespace},
					frontend:       ingressV4Frontend,
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // 1 backend - unhealthy
				},
			},
			advertisedAfter: map[resource.Key][]string{},
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        64125,
					RouterID:   "127.0.0.1",
					ListenPort: -1,
				},
			}
			oldc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:              64125,
				Neighbors:             []v2alpha1api.CiliumBGPNeighbor{},
				ServiceSelector:       &svcSelector,
				ServiceAdvertisements: []v2alpha1api.BGPServiceAddressType{v2alpha1api.BGPLoadBalancerIPAddr},
			}
			testSC, err := instance.NewServerWithConfig(context.Background(), log, srvParams)
			require.NoError(t, err)
			testSC.Config = oldc

			diffstore := store.NewFakeDiffStore[*slim_corev1.Service]()
			epDiffStore := store.NewFakeDiffStore[*k8s.Endpoints]()

			ossReconciler := reconciler.NewServiceReconciler(diffstore, epDiffStore).Reconciler.(*reconciler.ServiceReconciler)
			ossReconciler.Init(testSC)
			defer ossReconciler.Cleanup(testSC)

			serviceAnnouncements := ossReconciler.GetMetadata(testSC)

			rParams := lbServiceReconcilerParams{
				In:        cell.In{},
				Lifecycle: &cell.DefaultLifecycle{},
				Cfg:       Config{SvcHealthCheckingEnabled: true},
				Signaler:  signaler.NewBGPCPSignaler(),
			}
			ceeReconciler := newLBServiceReconciler(rParams).Reconciler.(*lbServiceReconciler)

			for _, obj := range tt.existingServices {
				diffstore.Upsert(obj)
			}
			for _, obj := range tt.upsertedServices {
				diffstore.Upsert(obj)
			}
			for _, key := range tt.deletedServices {
				diffstore.Delete(key)
			}

			ceeReconciler.ossLBServiceReconciler = ossReconciler

			for _, svc := range tt.existingServices {
				svcKey := resource.NewKey(svc)
				for _, ingress := range svc.Status.LoadBalancer.Ingress {
					prefix := netip.MustParsePrefix(ingress.IP + "/32")
					advrtResp, err := testSC.Server.AdvertisePath(context.Background(), types.PathRequest{
						Path: types.NewPathForPrefix(prefix),
					})
					require.NoError(t, err)
					serviceAnnouncements[svcKey] = append(serviceAnnouncements[svcKey], advrtResp.Path)
				}
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

			newc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:              64125,
				Neighbors:             []v2alpha1api.CiliumBGPNeighbor{},
				ServiceSelector:       &svcSelector,
				ServiceAdvertisements: []v2alpha1api.BGPServiceAddressType{v2alpha1api.BGPLoadBalancerIPAddr},
			}

			err = ceeReconciler.Reconcile(context.Background(), reconciler.ReconcileParams{
				CurrentServer: testSC,
				DesiredConfig: newc,
				CiliumNode: &v2api.CiliumNode{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node1",
					},
				},
			})
			require.NoError(t, err)

			log.Printf("%+v %+v", serviceAnnouncements, tt.advertisedAfter)

			// ensure num. of advertised paths is as expected
			expectedPaths := 0
			for _, paths := range tt.advertisedAfter {
				expectedPaths += len(paths)
			}
			advertisedPaths := 0
			for _, paths := range serviceAnnouncements {
				advertisedPaths += len(paths)
			}
			require.Equal(t, expectedPaths, advertisedPaths)

			// ensure we see tt.advertisedAfter in testSC.ServiceAnnouncements
			for svcKey, cidrs := range tt.advertisedAfter {
				for _, cidr := range cidrs {
					prefix := netip.MustParsePrefix(cidr)
					var seen bool
					for _, advrt := range serviceAnnouncements[svcKey] {
						if advrt.NLRI.String() == prefix.String() {
							seen = true
						}
					}
					if !seen {
						t.Fatalf("failed to advertise %v", cidr)
					}
				}
			}
		})
	}
}

func TestNoAdvertisementAnnotation(t *testing.T) {
	vip0 := "10.0.0.1"
	vip1 := "10.0.0.2"

	baseSvc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "test",
			Namespace: "test",
			Labels: map[string]string{
				"color": "blue",
			},
		},
		Spec: slim_corev1.ServiceSpec{
			Type: slim_corev1.ServiceTypeLoadBalancer,
		},
	}

	withAnnotation := baseSvc.DeepCopy()
	withAnnotation.Annotations = map[string]string{
		annotation.ServiceNoAdvertisement: "true",
	}
	withAnnotation.Status = slim_corev1.ServiceStatus{
		LoadBalancer: slim_corev1.LoadBalancerStatus{
			Ingress: []slim_corev1.LoadBalancerIngress{
				{
					IP: vip0,
				},
			},
		},
	}

	withoutAnnotation := baseSvc.DeepCopy()
	withoutAnnotation.Status = slim_corev1.ServiceStatus{
		LoadBalancer: slim_corev1.LoadBalancerStatus{
			Ingress: []slim_corev1.LoadBalancerIngress{
				{
					IP: vip1,
				},
			},
		},
	}

	sc, err := instance.NewServerWithConfig(context.Background(), log, types.ServerParameters{
		Global: types.BGPGlobal{
			ASN:        64125,
			RouterID:   "127.0.0.1",
			ListenPort: -1,
		},
	})
	require.NoError(t, err)

	diffStore := store.NewFakeDiffStore[*slim_corev1.Service]()
	epDiffStore := store.NewFakeDiffStore[*k8s.Endpoints]()

	ossReconciler := reconciler.NewServiceReconciler(diffStore, epDiffStore).Reconciler.(*reconciler.ServiceReconciler)
	ossReconciler.Init(sc)
	defer ossReconciler.Cleanup(sc)

	rParams := lbServiceReconcilerParams{
		In:        cell.In{},
		Lifecycle: &cell.DefaultLifecycle{},
		Cfg:       Config{SvcHealthCheckingEnabled: true},
		Signaler:  signaler.NewBGPCPSignaler(),
	}

	ceeReconciler := newLBServiceReconciler(rParams).Reconciler.(*lbServiceReconciler)
	ceeReconciler.ossLBServiceReconciler = ossReconciler

	// Upsert services
	diffStore.Upsert(withAnnotation)
	diffStore.Upsert(withoutAnnotation)

	vRouter := &v2alpha1api.CiliumBGPVirtualRouter{
		LocalASN:              64125,
		Neighbors:             []v2alpha1api.CiliumBGPNeighbor{},
		ServiceSelector:       &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}},
		ServiceAdvertisements: []v2alpha1api.BGPServiceAddressType{v2alpha1api.BGPLoadBalancerIPAddr},
	}

	t.Run("with no-advertisement annotation", func(t *testing.T) {
		prefixes, err := ceeReconciler.svcDesiredRoutes(vRouter, withAnnotation, nil)
		require.NoError(t, err)
		require.Empty(t, prefixes)
	})

	t.Run("without no-advertisement annotation", func(t *testing.T) {
		prefixes, err := ceeReconciler.svcDesiredRoutes(vRouter, withoutAnnotation, nil)
		require.NoError(t, err)
		require.Contains(t, prefixes, netip.MustParsePrefix(vip1+"/32"))
	})
}
