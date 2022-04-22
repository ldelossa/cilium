package srv6

import (
	"context"
	"net"

	"github.com/cilium/cilium/pkg/policy/api"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
	"k8s.io/apimachinery/pkg/types"
)

// SRv6Manager is an interface for querying aspects of Cilium's SRv6 control
// plane.
type SRv6Manager interface {
	ListVRFs(ctx context.Context) ([]VRF, error)
	GetAllEgressPolicies(ctx context.Context) ([]PolicyConfig, error)
	GetAllVRFs(ctx context.Context) ([]VRF, error)
}

// VRF is the internal representation of CiliumSRv6VRF.
//
// TODO(Louis) - these will actually come from SRv6 Manager's package,
// mocking out for now
type VRF struct {
	// id is the parsed config name and namespace
	id types.NamespacedName

	VRFID             uint32
	ImportRouteTarget string
	rules             []vrfRule
}

// VRFRule is the internal representation of rules from CiliumSRv6VRF.
//
// TODO(Louis) - these will actually come from SRv6 Manager's package,
// mocking out for now
type vrfRule struct {
	EndpointSelectors []api.EndpointSelector
	DstCIDRs          []*net.IPNet
}

// PolicyConfig is the internal representation of CiliumSRv6EgressPolicy.
type PolicyConfig struct {
	// id is the parsed config name and namespace
	id types.NamespacedName

	VRFID    uint32
	DstCIDRs []*net.IPNet
	SID      ciliumTypes.IPv6
}

// PolicyID includes policy name and namespace
type PolicyID = types.NamespacedName
