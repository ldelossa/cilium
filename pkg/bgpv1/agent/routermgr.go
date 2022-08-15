// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"

	"github.com/cilium/cilium/api/v1/models"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	srv6 "github.com/cilium/cilium/pkg/srv6"
)

// BGPRouterManager provides a declarative API for defining
// BGP peers and interacting with lower level BGP server details.
type BGPRouterManager interface {
	// ConfigurePeers evaluates the provided CiliumBGPPeeringPolicy
	// and the implementation will configure itself to apply this policy.
	//
	// A ControllerState structure is provided which captures Cilium's runtime
	// state at the time of this method's invocation. It must remain read-only.
	//
	// ConfigurePeers should block until it can ensure a subsequent call
	// to ConfigurePeers can occur without conflict.
	//
	// ConfigurePeers should not be called concurrently and expects invocations
	// to be serialized contingent to the method's completion.
	//
	// An error is returned only when the implementation can determine a
	// critical flaw with the peering policy, not when network connectivity
	// is an issue.
	//
	// Providing a nil policy to ConfigurePeers will withdrawal all routes
	// and disconnect from the peers.
	ConfigurePeers(ctx context.Context, policy *v2alpha1api.CiliumBGPPeeringPolicy, state *ControlPlaneState) error
	// GetPeers fetches BGP peering state from underlying routing daemon.
	//
	// List of all peers will be returned and if there are multiple instances of
	// BGP daemon running locally, then peers can be differentiated based on
	// local AS number.
	GetPeers(ctx context.Context) ([]*models.BgpPeer, error)
	// MapSRv6EgressPolicy will map VPNv4 routes present in any virtual routers with
	// the "MapSRv6VRFs" set to true into SRv6PolicyConfig.
	//
	// The BGPRouterManager must convert these VPNv4 routes which match a Route Target
	// in the provided SRv6VRFs into SRv6PolicyConfig and return these to the caller.
	MapSRv6EgressPolicy(ctx context.Context, vrfs []*srv6.VRF) ([]*srv6.EgressPolicy, error)
}
