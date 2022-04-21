//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by main. DO NOT EDIT.

package v2alpha1

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPLoadBalancerIPPool) DeepEqual(other *CiliumBGPLoadBalancerIPPool) bool {
	if other == nil {
		return false
	}

	if !in.Spec.DeepEqual(&other.Spec) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPLoadBalancerIPPoolSpec) DeepEqual(other *CiliumBGPLoadBalancerIPPoolSpec) bool {
	if other == nil {
		return false
	}

	if (in.NodeSelector == nil) != (other.NodeSelector == nil) {
		return false
	} else if in.NodeSelector != nil {
		if !in.NodeSelector.DeepEqual(other.NodeSelector) {
			return false
		}
	}

	if in.Prefix != other.Prefix {
		return false
	}
	if (in.LBSelector == nil) != (other.LBSelector == nil) {
		return false
	} else if in.LBSelector != nil {
		if !in.LBSelector.DeepEqual(other.LBSelector) {
			return false
		}
	}

	if in.Default != other.Default {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPNeighbor) DeepEqual(other *CiliumBGPNeighbor) bool {
	if other == nil {
		return false
	}

	if in.PeerAddress != other.PeerAddress {
		return false
	}
	if in.PeerASN != other.PeerASN {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPPeeringPolicy) DeepEqual(other *CiliumBGPPeeringPolicy) bool {
	if other == nil {
		return false
	}

	if !in.Spec.DeepEqual(&other.Spec) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPPeeringPolicySpec) DeepEqual(other *CiliumBGPPeeringPolicySpec) bool {
	if other == nil {
		return false
	}

	if (in.NodeSelector == nil) != (other.NodeSelector == nil) {
		return false
	} else if in.NodeSelector != nil {
		if !in.NodeSelector.DeepEqual(other.NodeSelector) {
			return false
		}
	}

	if ((in.VirtualRouters != nil) && (other.VirtualRouters != nil)) || ((in.VirtualRouters == nil) != (other.VirtualRouters == nil)) {
		in, other := &in.VirtualRouters, &other.VirtualRouters
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumBGPVirtualRouter) DeepEqual(other *CiliumBGPVirtualRouter) bool {
	if other == nil {
		return false
	}

	if in.LocalASN != other.LocalASN {
		return false
	}
	if in.ExportPodCIDR != other.ExportPodCIDR {
		return false
	}
	if in.MapSRv6VRFs != other.MapSRv6VRFs {
		return false
	}
	if ((in.Neighbors != nil) && (other.Neighbors != nil)) || ((in.Neighbors == nil) != (other.Neighbors == nil)) {
		in, other := &in.Neighbors, &other.Neighbors
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumEgressNATPolicy) DeepEqual(other *CiliumEgressNATPolicy) bool {
	if other == nil {
		return false
	}

	if !in.Spec.DeepEqual(&other.Spec) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumEgressNATPolicySpec) DeepEqual(other *CiliumEgressNATPolicySpec) bool {
	if other == nil {
		return false
	}

	if ((in.Egress != nil) && (other.Egress != nil)) || ((in.Egress == nil) != (other.Egress == nil)) {
		in, other := &in.Egress, &other.Egress
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	if ((in.DestinationCIDRs != nil) && (other.DestinationCIDRs != nil)) || ((in.DestinationCIDRs == nil) != (other.DestinationCIDRs == nil)) {
		in, other := &in.DestinationCIDRs, &other.DestinationCIDRs
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if inElement != (*other)[i] {
					return false
				}
			}
		}
	}

	if in.EgressSourceIP != other.EgressSourceIP {
		return false
	}
	if ((in.EgressGroups != nil) && (other.EgressGroups != nil)) || ((in.EgressGroups == nil) != (other.EgressGroups == nil)) {
		in, other := &in.EgressGroups, &other.EgressGroups
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumEndpointSlice) DeepEqual(other *CiliumEndpointSlice) bool {
	if other == nil {
		return false
	}

	if in.Namespace != other.Namespace {
		return false
	}
	if ((in.Endpoints != nil) && (other.Endpoints != nil)) || ((in.Endpoints == nil) != (other.Endpoints == nil)) {
		in, other := &in.Endpoints, &other.Endpoints
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumSRv6EgressPolicy) DeepEqual(other *CiliumSRv6EgressPolicy) bool {
	if other == nil {
		return false
	}

	if !in.Spec.DeepEqual(&other.Spec) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumSRv6EgressPolicySpec) DeepEqual(other *CiliumSRv6EgressPolicySpec) bool {
	if other == nil {
		return false
	}

	if in.VRFID != other.VRFID {
		return false
	}
	if ((in.DestinationCIDRs != nil) && (other.DestinationCIDRs != nil)) || ((in.DestinationCIDRs == nil) != (other.DestinationCIDRs == nil)) {
		in, other := &in.DestinationCIDRs, &other.DestinationCIDRs
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if inElement != (*other)[i] {
					return false
				}
			}
		}
	}

	if in.DestinationSID != other.DestinationSID {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumSRv6VRF) DeepEqual(other *CiliumSRv6VRF) bool {
	if other == nil {
		return false
	}

	if !in.Spec.DeepEqual(&other.Spec) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CiliumSRv6VRFSpec) DeepEqual(other *CiliumSRv6VRFSpec) bool {
	if other == nil {
		return false
	}

	if in.VRFID != other.VRFID {
		return false
	}
	if in.ImportRouteTarget != other.ImportRouteTarget {
		return false
	}
	if ((in.Rules != nil) && (other.Rules != nil)) || ((in.Rules == nil) != (other.Rules == nil)) {
		in, other := &in.Rules, &other.Rules
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *CoreCiliumEndpoint) DeepEqual(other *CoreCiliumEndpoint) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if in.IdentityID != other.IdentityID {
		return false
	}
	if (in.Networking == nil) != (other.Networking == nil) {
		return false
	} else if in.Networking != nil {
		if !in.Networking.DeepEqual(other.Networking) {
			return false
		}
	}

	if in.Encryption != other.Encryption {
		return false
	}

	if ((in.NamedPorts != nil) && (other.NamedPorts != nil)) || ((in.NamedPorts == nil) != (other.NamedPorts == nil)) {
		in, other := &in.NamedPorts, &other.NamedPorts
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual((*other)[i]) {
					return false
				}
			}
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *EgressGroup) DeepEqual(other *EgressGroup) bool {
	if other == nil {
		return false
	}

	if (in.NodeSelector == nil) != (other.NodeSelector == nil) {
		return false
	} else if in.NodeSelector != nil {
		if !in.NodeSelector.DeepEqual(other.NodeSelector) {
			return false
		}
	}

	if in.Interface != other.Interface {
		return false
	}
	if in.EgressIP != other.EgressIP {
		return false
	}
	if in.MaxGatewayNodes != other.MaxGatewayNodes {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *EgressRule) DeepEqual(other *EgressRule) bool {
	if other == nil {
		return false
	}

	if (in.NamespaceSelector == nil) != (other.NamespaceSelector == nil) {
		return false
	} else if in.NamespaceSelector != nil {
		if !in.NamespaceSelector.DeepEqual(other.NamespaceSelector) {
			return false
		}
	}

	if (in.PodSelector == nil) != (other.PodSelector == nil) {
		return false
	} else if in.PodSelector != nil {
		if !in.PodSelector.DeepEqual(other.PodSelector) {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *VRFRule) DeepEqual(other *VRFRule) bool {
	if other == nil {
		return false
	}

	if ((in.Selectors != nil) && (other.Selectors != nil)) || ((in.Selectors == nil) != (other.Selectors == nil)) {
		in, other := &in.Selectors, &other.Selectors
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if !inElement.DeepEqual(&(*other)[i]) {
					return false
				}
			}
		}
	}

	if ((in.DestinationCIDRs != nil) && (other.DestinationCIDRs != nil)) || ((in.DestinationCIDRs == nil) != (other.DestinationCIDRs == nil)) {
		in, other := &in.DestinationCIDRs, &other.DestinationCIDRs
		if other == nil {
			return false
		}

		if len(*in) != len(*other) {
			return false
		} else {
			for i, inElement := range *in {
				if inElement != (*other)[i] {
					return false
				}
			}
		}
	}

	return true
}
