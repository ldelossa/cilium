// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"net"
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

	// SRv6 related methods

	// MapSRv6EgressPolicy translates local VPN routes to SRv6 policies
	MapSRv6EgressPolicy(ctx context.Context, vrfs []*srv6.VRF) ([]*srv6.EgressPolicy, error)

	// AdvertiseVPNv4Path advertise VPNv4 route to peers
	AdvertiseVPNv4Path(ctx context.Context, p VPNv4PathRequest) (VPNv4PathResponse, error)

	// WithdrawVPNv4Path removes VPNv4 route from peers
	WithdrawVPNv4Path(ctx context.Context, p VPNv4PathRequest) error
}

// VPNv4Advertisement is a container object which associates a VRF information and VPNv4 Prefixes
//
// The `PathUuid` field is a gobgp.PathUuid object which can be forwarded to gobgp's
// WithdrawPath method, making withdrawing an advertised route simple.
type VPNv4Advertisement struct {
	VRF           *srv6.VRF
	IPv4Nets      []*net.IPNet
	GoBGPPathUUID []byte // path identifier in underlying implementation
}

// VPNv4PathRequest contains parameters for advertising or withdrawing vpn v4 routes
type VPNv4PathRequest struct {
	Advert VPNv4Advertisement
}

// VPNv4PathResponse contains response after advertising the route, underlying implementation will set UUID
type VPNv4PathResponse struct {
	Advert VPNv4Advertisement
}
