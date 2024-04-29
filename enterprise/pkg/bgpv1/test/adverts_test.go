// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/enterprise/pkg/annotation"
	enterprisereconciler "github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/reconciler"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/bgpv1/test"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	// maxTestDuration is allowed time for test execution
	maxTestDuration = 15 * time.Second
)

type svcBackendUpdate struct {
	svcName        loadbalancer.ServiceName
	frontend       loadbalancer.L3n4Addr
	activeBackends []loadbalancer.Backend
}

// mockHealthCheckSubscriber implements the HealthCheckSubscriber interface for testing purposes.
type mockHealthCheckSubscriber struct {
	callback types.HealthUpdateCallback
}

func (s *mockHealthCheckSubscriber) Subscribe(ctx context.Context, callback types.HealthUpdateCallback) {
	s.callback = callback
}

func Test_LBServiceHealthCheckAdvertisements(t *testing.T) {
	testutils.PrivilegedTest(t)

	const (
		svcName     = "test-svc"
		ingressIPv4 = "10.100.1.1"
		ingressIPv6 = "aaaa::1"
	)

	var (
		lbSvcName         = loadbalancer.ServiceName{Name: svcName}
		lbSvcFrontendIPv4 = loadbalancer.L3n4Addr{AddrCluster: cmtypes.MustParseAddrCluster(ingressIPv4)}
		lbSvcFrontendIPv6 = loadbalancer.L3n4Addr{AddrCluster: cmtypes.MustParseAddrCluster(ingressIPv6)}
	)

	var steps = []struct {
		description         string
		ingressIPs          []string
		annotations         map[string]string
		op                  string // "add" / "update" / "none"
		backendUpdates      []svcBackendUpdate
		expectedRouteEvents []test.RouteEvent
	}{
		{
			description: "advertise service IP with unknown backend health",
			ingressIPs:  []string{ingressIPv4},
			annotations: map[string]string{annotation.ServiceHealthProbeInterval: "5s"},
			op:          "add",
			expectedRouteEvents: []test.RouteEvent{
				{
					SourceASN:   test.CiliumASN,
					Prefix:      ingressIPv4,
					PrefixLen:   32,
					IsWithdrawn: false,
				},
			},
		},
		{
			description: "withdraw service IP with unhealthy backends",
			ingressIPs:  []string{ingressIPv4},
			annotations: map[string]string{annotation.ServiceHealthProbeInterval: "5s"},
			op:          "none",
			backendUpdates: []svcBackendUpdate{
				{
					svcName:        lbSvcName,
					frontend:       lbSvcFrontendIPv4,
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
			},
			expectedRouteEvents: []test.RouteEvent{
				{
					SourceASN:   test.CiliumASN,
					Prefix:      ingressIPv4,
					PrefixLen:   32,
					IsWithdrawn: true,
				},
			},
		},
		{
			description: "advertise service IP with 1 healthy backend",
			ingressIPs:  []string{ingressIPv4},
			annotations: map[string]string{annotation.ServiceHealthProbeInterval: "5s"},
			op:          "none",
			backendUpdates: []svcBackendUpdate{
				{
					svcName:        lbSvcName,
					frontend:       lbSvcFrontendIPv4,
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
			},
			expectedRouteEvents: []test.RouteEvent{
				{
					SourceASN:   test.CiliumASN,
					Prefix:      ingressIPv4,
					PrefixLen:   32,
					IsWithdrawn: false,
				},
			},
		},
		{
			description:    "withdraw service IP with 1 healthy backend, threshold 2",
			ingressIPs:     []string{ingressIPv4},
			annotations:    map[string]string{annotation.ServiceHealthProbeInterval: "5s", annotation.ServiceHealthBGPAdvertiseThreshold: "2"},
			op:             "update",
			backendUpdates: nil,
			expectedRouteEvents: []test.RouteEvent{
				{
					SourceASN:   test.CiliumASN,
					Prefix:      ingressIPv4,
					PrefixLen:   32,
					IsWithdrawn: true,
				},
			},
		},
		{
			description: "advertise service IP with 2 healthy backends, threshold 2",
			ingressIPs:  []string{ingressIPv4},
			annotations: map[string]string{annotation.ServiceHealthProbeInterval: "5s", annotation.ServiceHealthBGPAdvertiseThreshold: "2"},
			op:          "update",
			backendUpdates: []svcBackendUpdate{
				{
					svcName:        lbSvcName,
					frontend:       lbSvcFrontendIPv4,
					activeBackends: []loadbalancer.Backend{{ID: 1}, {ID: 2}}, // healthy
				},
			},
			expectedRouteEvents: []test.RouteEvent{
				{
					SourceASN:   test.CiliumASN,
					Prefix:      ingressIPv4,
					PrefixLen:   32,
					IsWithdrawn: false,
				},
			},
		},
		{
			description: "withdraw service IP with 1 healthy backends, threshold 2",
			ingressIPs:  []string{ingressIPv4},
			annotations: map[string]string{annotation.ServiceHealthProbeInterval: "5s", annotation.ServiceHealthBGPAdvertiseThreshold: "2"},
			op:          "update",
			backendUpdates: []svcBackendUpdate{
				{
					svcName:        lbSvcName,
					frontend:       lbSvcFrontendIPv4,
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
			},
			expectedRouteEvents: []test.RouteEvent{
				{
					SourceASN:   test.CiliumASN,
					Prefix:      ingressIPv4,
					PrefixLen:   32,
					IsWithdrawn: true,
				},
			},
		},
		{
			description:    "advertise service IP without health-check-probe-interval annotation (hc disabled)",
			ingressIPs:     []string{ingressIPv4},
			annotations:    map[string]string{annotation.ServiceHealthBGPAdvertiseThreshold: "2"},
			op:             "update",
			backendUpdates: nil,
			expectedRouteEvents: []test.RouteEvent{
				{
					SourceASN:   test.CiliumASN,
					Prefix:      ingressIPv4,
					PrefixLen:   32,
					IsWithdrawn: false,
				},
			},
		},
		{
			description:    "dualstack - advertise new IPv6 address, unknown backend health",
			ingressIPs:     []string{ingressIPv4, ingressIPv6},
			annotations:    map[string]string{annotation.ServiceHealthProbeInterval: "5s"},
			op:             "update",
			backendUpdates: nil,
			expectedRouteEvents: []test.RouteEvent{
				{
					SourceASN:   test.CiliumASN,
					Prefix:      ingressIPv6,
					PrefixLen:   128,
					IsWithdrawn: false,
				},
			},
		},
		{
			description: "dualstack - withdraw IPv4 - unhealthy backend",
			ingressIPs:  []string{ingressIPv4, ingressIPv6},
			annotations: map[string]string{annotation.ServiceHealthProbeInterval: "5s"},
			op:          "none",
			backendUpdates: []svcBackendUpdate{
				{
					svcName:        lbSvcName,
					frontend:       lbSvcFrontendIPv4,
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
			},
			expectedRouteEvents: []test.RouteEvent{
				{
					SourceASN:   test.CiliumASN,
					Prefix:      ingressIPv4,
					PrefixLen:   32,
					IsWithdrawn: true,
				},
			},
		},
		{
			description: "dualstack - withdraw IPv6 - unhealthy backend",
			ingressIPs:  []string{ingressIPv4, ingressIPv6},
			annotations: map[string]string{annotation.ServiceHealthProbeInterval: "5s"},
			op:          "none",
			backendUpdates: []svcBackendUpdate{
				{
					svcName:        lbSvcName,
					frontend:       lbSvcFrontendIPv6,
					activeBackends: []loadbalancer.Backend{}, // unhealthy
				},
			},
			expectedRouteEvents: []test.RouteEvent{
				{
					SourceASN:   test.CiliumASN,
					Prefix:      ingressIPv6,
					PrefixLen:   128,
					IsWithdrawn: true,
				},
			},
		},
		{
			description: "dualstack - advertise both - both healthy backends",
			ingressIPs:  []string{ingressIPv4, ingressIPv6},
			annotations: map[string]string{annotation.ServiceHealthProbeInterval: "5s"},
			op:          "none",
			backendUpdates: []svcBackendUpdate{
				{
					svcName:        lbSvcName,
					frontend:       lbSvcFrontendIPv4,
					activeBackends: []loadbalancer.Backend{{ID: 1}}, // healthy
				},
				{
					svcName:        lbSvcName,
					frontend:       lbSvcFrontendIPv6,
					activeBackends: []loadbalancer.Backend{{ID: 2}}, // healthy
				},
			},
			expectedRouteEvents: []test.RouteEvent{
				{
					SourceASN:   test.CiliumASN,
					Prefix:      ingressIPv4,
					PrefixLen:   32,
					IsWithdrawn: false,
				},
				{
					SourceASN:   test.CiliumASN,
					Prefix:      ingressIPv6,
					PrefixLen:   128,
					IsWithdrawn: false,
				},
			},
		},
	}

	testCtx, testDone := context.WithTimeout(context.Background(), maxTestDuration)
	defer testDone()

	// setup topology
	healthCheckSubscriber := &mockHealthCheckSubscriber{}
	fixConfig := &test.EnterpriseFixtureConfig{
		ReconcilerConfig: &enterprisereconciler.Config{
			SvcHealthCheckingEnabled: true,
		},
		SvcHealthCheckSubscriber: healthCheckSubscriber,
	}
	gobgpPeers, fixture, cleanup, err := test.EnterpriseSetup(t, testCtx, fixConfig)
	require.NoError(t, err)
	require.Len(t, gobgpPeers, 1)
	defer cleanup()

	// setup neighbor
	err = test.SetupSingleNeighbor(testCtx, fixture)
	require.NoError(t, err)

	// wait for peering to come up
	err = gobgpPeers[0].WaitForSessionState(testCtx, []string{"ESTABLISHED"})
	require.NoError(t, err)

	// setup bgp policy with service selection
	fixture.ConfigPolicy().Spec.VirtualRouters[0].ServiceSelector = &slim_metav1.LabelSelector{
		MatchExpressions: []slim_metav1.LabelSelectorRequirement{
			// always true match
			{
				Key:      "somekey",
				Operator: "NotIn",
				Values:   []string{"not-somekey"},
			},
		},
	}
	_, err = fixture.PolicyClient().Update(testCtx, fixture.ConfigPolicy(), meta_v1.UpdateOptions{})
	require.NoError(t, err)

	tracker := fixture.FakeClientSet().SlimFakeClientset.Tracker()

	for _, step := range steps {
		t.Run(step.description, func(t *testing.T) {
			svcObj := newLBServiceObj(svcName, step.ingressIPs, step.annotations)

			if step.op == "add" {
				err = tracker.Add(&svcObj)
			} else if step.op == "update" {
				err = tracker.Update(slim_metav1.Unversioned.WithResource("services"), &svcObj, "")
			}
			require.NoError(t, err, step.description)

			// update svc backends
			for _, upd := range step.backendUpdates {
				svcInfo := types.HealthUpdateSvcInfo{
					Name:    upd.svcName,
					Addr:    upd.frontend,
					SvcType: loadbalancer.SVCTypeLoadBalancer,
				}
				healthCheckSubscriber.callback(svcInfo, upd.activeBackends)
			}

			// validate expected result
			receivedEvents, err := gobgpPeers[0].GetRouteEvents(testCtx, len(step.expectedRouteEvents))
			require.NoError(t, err, step.description)

			// match events in any order
			require.ElementsMatch(t, step.expectedRouteEvents, receivedEvents, step.description)
		})
	}
}

func newLBServiceObj(name string, ingressIPs []string, annotations map[string]string) slim_core_v1.Service {
	svc := slim_core_v1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:        name,
			Annotations: annotations,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
		},
	}
	for _, ip := range ingressIPs {
		svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, slim_core_v1.LoadBalancerIngress{IP: ip})
	}
	return svc
}
