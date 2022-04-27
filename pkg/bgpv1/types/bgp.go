// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"net/netip"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/srv6"
)

// BGPGlobal contains high level BGP configuration for given instance.
type BGPGlobal struct {
	ASN                   uint32
	RouterID              string
	ListenPort            int32 // When -1 gobgp won't listen on tcp:179
	RouteSelectionOptions *RouteSelectionOptions
}

// RouteSelectionOptions contains generic BGP route selection tuning parameters
type RouteSelectionOptions struct {
	// AdvertiseInactiveRoutes when set will advertise route even if it is not present in RIB
	AdvertiseInactiveRoutes bool
}

// Advertisement is a container object which associates a netip.Prefix
//
// The `Prefix` field makes comparing this Advertisement with another Prefix encoded
// prefixes simple.
//
// The `GoBGPPathUUID` field is a gobgp.AddPathResponse.Uuid object which can be forwarded to gobgp's
// WithdrawPath method, making withdrawing an advertised route simple.
type Advertisement struct {
	Prefix        netip.Prefix
	GoBGPPathUUID []byte // path identifier in underlying implementation
}

// NeighborRequest contains neighbor parameters used when enabling or disabling peer
type NeighborRequest struct {
	Neighbor *v2alpha1api.CiliumBGPNeighbor
	VR       *v2alpha1api.CiliumBGPVirtualRouter
}

// PathRequest contains parameters for advertising or withdrawing routes
type PathRequest struct {
	Advert Advertisement
}

// PathResponse contains response after advertising the route, underlying implementation will set UUID
type PathResponse struct {
	Advert Advertisement
}

// GetPeerStateResponse contains state of peers configured in given instance
type GetPeerStateResponse struct {
	Peers []*models.BgpPeer
}

// GetBGPResponse contains BGP global parameters
type GetBGPResponse struct {
	Global BGPGlobal
}

// ServerParameters contains information for underlying bgp implementation layer to initializing BGP process.
type ServerParameters struct {
	Global BGPGlobal
	CState *agent.ControlPlaneState
}

// Router is vendor-agnostic cilium bgp configuration layer. Parameters of this layer
// are standard BGP RFC complaint and not specific to any underlying implementation.
type Router interface {
	Stop()

	// AddNeighbor configures BGP peer
	AddNeighbor(ctx context.Context, n NeighborRequest) error

	// RemoveNeighbor removes BGP peer
	RemoveNeighbor(ctx context.Context, n NeighborRequest) error

	// AdvertisePath advertises BGP route to all configured peers
	AdvertisePath(ctx context.Context, p PathRequest) (PathResponse, error)

	// WithdrawPath  removes BGP route from all peers
	WithdrawPath(ctx context.Context, p PathRequest) error

	// GetPeerState returns status of BGP peers
	GetPeerState(ctx context.Context) (GetPeerStateResponse, error)

	// GetBGP returns configured BGP global parameters
	GetBGP(ctx context.Context) (GetBGPResponse, error)

	// Map VRFs into CiliumSRv6EgressPolicies
	MapSRv6EgressPolicy(ctx context.Context, vrfs []*srv6.VRF) ([]*srv6.EgressPolicy, error)
}
