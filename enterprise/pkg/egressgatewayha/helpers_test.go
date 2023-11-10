//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/policy/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

type fakeResource[T runtime.Object] chan resource.Event[T]

func (fr fakeResource[T]) sync(tb testing.TB) {
	var sync resource.Event[T]
	sync.Kind = resource.Sync
	fr.process(tb, sync)
}

func (fr fakeResource[T]) process(tb testing.TB, ev resource.Event[T]) {
	tb.Helper()
	if err := fr.processWithError(ev); err != nil {
		tb.Fatal("Failed to process event:", err)
	}
}

func (fr fakeResource[T]) processWithError(ev resource.Event[T]) error {
	errs := make(chan error)
	ev.Done = func(err error) {
		errs <- err
	}
	fr <- ev
	return <-errs
}

func (fr fakeResource[T]) Observe(ctx context.Context, next func(event resource.Event[T]), complete func(error)) {
	complete(errors.New("not implemented"))
}

func (fr fakeResource[T]) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[T] {
	if len(opts) > 1 {
		// Ideally we'd only ignore resource.WithRateLimit here, but that
		// isn't possible.
		panic("more than one option is not supported")
	}
	return fr
}

func (fr fakeResource[T]) Store(context.Context) (resource.Store[T], error) {
	return nil, errors.New("not implemented")
}

func addPolicy(tb testing.TB, policies fakeResource[*Policy], params *policyParams) {
	tb.Helper()

	policy, _ := newIEGP(params)
	policies.process(tb, resource.Event[*Policy]{
		Kind:   resource.Upsert,
		Object: policy,
	})
}

type policyParams struct {
	name            string
	endpointLabels  map[string]string
	destinationCIDR string
	excludedCIDRs   []string
	nodeLabels      map[string]string
	iface           string
	egressIP        string
	maxGatewayNodes int
}

func newIEGP(params *policyParams) (*Policy, *PolicyConfig) {
	// Note we avoid 'MustParse*()' varieties here to allow testing how
	// poor input is handed to ParseIEGP().
	parsedDestinationCIDR, _ := netip.ParsePrefix(params.destinationCIDR)

	parsedExcludedCIDRs := []netip.Prefix{}
	for _, excludedCIDR := range params.excludedCIDRs {
		parsedExcludedCIDR, _ := netip.ParsePrefix(excludedCIDR)
		parsedExcludedCIDRs = append(parsedExcludedCIDRs, parsedExcludedCIDR)
	}

	policy := &PolicyConfig{
		id: types.NamespacedName{
			Name: params.name,
		},
		dstCIDRs:      []netip.Prefix{parsedDestinationCIDR},
		excludedCIDRs: parsedExcludedCIDRs,
		endpointSelectors: []api.EndpointSelector{
			{
				LabelSelector: &slimv1.LabelSelector{
					MatchLabels: params.endpointLabels,
				},
			},
		},
		groupConfigs: []groupConfig{
			{
				nodeSelector: api.EndpointSelector{
					LabelSelector: &slimv1.LabelSelector{
						MatchLabels: params.endpointLabels,
					},
				},
				iface:           params.iface,
				maxGatewayNodes: params.maxGatewayNodes,
			},
		},
	}

	if len(params.endpointLabels) != 0 {
		policy.endpointSelectors = []api.EndpointSelector{
			{
				LabelSelector: &slimv1.LabelSelector{
					MatchLabels: params.endpointLabels,
				},
			},
		}
	}

	excludedCIDRs := []v1.IPv4CIDR{}
	for _, excludedCIDR := range params.excludedCIDRs {
		excludedCIDRs = append(excludedCIDRs, v1.IPv4CIDR(excludedCIDR))
	}

	iegp := &Policy{
		ObjectMeta: metav1.ObjectMeta{
			Name: params.name,
		},
		Spec: v1.IsovalentEgressGatewayPolicySpec{
			Selectors: []v1.EgressRule{
				{
					PodSelector: &slimv1.LabelSelector{
						MatchLabels: params.endpointLabels,
					},
				},
			},
			DestinationCIDRs: []v1.IPv4CIDR{
				v1.IPv4CIDR(params.destinationCIDR),
			},
			ExcludedCIDRs: excludedCIDRs,
			EgressGroups: []v1.EgressGroup{
				{
					NodeSelector: &slimv1.LabelSelector{
						MatchLabels: params.nodeLabels,
					},
					Interface:       params.iface,
					EgressIP:        params.egressIP,
					MaxGatewayNodes: params.maxGatewayNodes,
				},
			},
		},
	}

	return iegp, policy
}

func addEndpoint(tb testing.TB, endpoints fakeResource[*k8sTypes.CiliumEndpoint], ep *k8sTypes.CiliumEndpoint) {
	endpoints.process(tb, resource.Event[*k8sTypes.CiliumEndpoint]{
		Kind:   resource.Upsert,
		Object: ep,
	})
}

func deleteEndpoint(tb testing.TB, endpoints fakeResource[*k8sTypes.CiliumEndpoint], ep *k8sTypes.CiliumEndpoint) {
	endpoints.process(tb, resource.Event[*k8sTypes.CiliumEndpoint]{
		Kind:   resource.Delete,
		Object: ep,
	})
}

func addNode(tb testing.TB, nodes fakeResource[*cilium_api_v2.CiliumNode], node nodeTypes.Node) {
	nodes.process(tb, resource.Event[*cilium_api_v2.CiliumNode]{
		Kind:   resource.Upsert,
		Object: node.ToCiliumNode(),
	})
}
