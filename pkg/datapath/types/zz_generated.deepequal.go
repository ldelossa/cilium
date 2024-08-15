//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by deepequal-gen. DO NOT EDIT.

package types

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *LocalNodeConfiguration) DeepEqual(other *LocalNodeConfiguration) bool {
	if other == nil {
		return false
	}

	if ((in.NodeIPv4 != nil) && (other.NodeIPv4 != nil)) || ((in.NodeIPv4 == nil) != (other.NodeIPv4 == nil)) {
		in, other := &in.NodeIPv4, &other.NodeIPv4
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

	if ((in.NodeIPv6 != nil) && (other.NodeIPv6 != nil)) || ((in.NodeIPv6 == nil) != (other.NodeIPv6 == nil)) {
		in, other := &in.NodeIPv6, &other.NodeIPv6
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

	if ((in.CiliumInternalIPv4 != nil) && (other.CiliumInternalIPv4 != nil)) || ((in.CiliumInternalIPv4 == nil) != (other.CiliumInternalIPv4 == nil)) {
		in, other := &in.CiliumInternalIPv4, &other.CiliumInternalIPv4
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

	if ((in.CiliumInternalIPv6 != nil) && (other.CiliumInternalIPv6 != nil)) || ((in.CiliumInternalIPv6 == nil) != (other.CiliumInternalIPv6 == nil)) {
		in, other := &in.CiliumInternalIPv6, &other.CiliumInternalIPv6
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

	if (in.AllocCIDRIPv4 == nil) != (other.AllocCIDRIPv4 == nil) {
		return false
	} else if in.AllocCIDRIPv4 != nil {
		if !in.AllocCIDRIPv4.DeepEqual(other.AllocCIDRIPv4) {
			return false
		}
	}

	if (in.AllocCIDRIPv6 == nil) != (other.AllocCIDRIPv6 == nil) {
		return false
	} else if in.AllocCIDRIPv6 != nil {
		if !in.AllocCIDRIPv6.DeepEqual(other.AllocCIDRIPv6) {
			return false
		}
	}

	if ((in.LoopbackIPv4 != nil) && (other.LoopbackIPv4 != nil)) || ((in.LoopbackIPv4 == nil) != (other.LoopbackIPv4 == nil)) {
		in, other := &in.LoopbackIPv4, &other.LoopbackIPv4
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

	if ((in.Devices != nil) && (other.Devices != nil)) || ((in.Devices == nil) != (other.Devices == nil)) {
		in, other := &in.Devices, &other.Devices
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

	if (in.DirectRoutingDevice == nil) != (other.DirectRoutingDevice == nil) {
		return false
	} else if in.DirectRoutingDevice != nil {
		if !in.DirectRoutingDevice.DeepEqual(other.DirectRoutingDevice) {
			return false
		}
	}

	if ((in.NodeAddresses != nil) && (other.NodeAddresses != nil)) || ((in.NodeAddresses == nil) != (other.NodeAddresses == nil)) {
		in, other := &in.NodeAddresses, &other.NodeAddresses
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

	if in.HostEndpointID != other.HostEndpointID {
		return false
	}
	if in.DeviceMTU != other.DeviceMTU {
		return false
	}
	if in.RouteMTU != other.RouteMTU {
		return false
	}
	if in.RoutePostEncryptMTU != other.RoutePostEncryptMTU {
		return false
	}
	if ((in.AuxiliaryPrefixes != nil) && (other.AuxiliaryPrefixes != nil)) || ((in.AuxiliaryPrefixes == nil) != (other.AuxiliaryPrefixes == nil)) {
		in, other := &in.AuxiliaryPrefixes, &other.AuxiliaryPrefixes
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

	if in.EnableIPv4 != other.EnableIPv4 {
		return false
	}
	if in.EnableIPv6 != other.EnableIPv6 {
		return false
	}
	if in.EnableEncapsulation != other.EnableEncapsulation {
		return false
	}
	if in.EnableAutoDirectRouting != other.EnableAutoDirectRouting {
		return false
	}
	if in.DirectRoutingSkipUnreachable != other.DirectRoutingSkipUnreachable {
		return false
	}
	if in.EnableLocalNodeRoute != other.EnableLocalNodeRoute {
		return false
	}
	if in.EnableIPSec != other.EnableIPSec {
		return false
	}
	if in.EnableIPSecEncryptedOverlay != other.EnableIPSecEncryptedOverlay {
		return false
	}
	if in.EncryptNode != other.EncryptNode {
		return false
	}
	if ((in.IPv4PodSubnets != nil) && (other.IPv4PodSubnets != nil)) || ((in.IPv4PodSubnets == nil) != (other.IPv4PodSubnets == nil)) {
		in, other := &in.IPv4PodSubnets, &other.IPv4PodSubnets
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

	if ((in.IPv6PodSubnets != nil) && (other.IPv6PodSubnets != nil)) || ((in.IPv6PodSubnets == nil) != (other.IPv6PodSubnets == nil)) {
		in, other := &in.IPv6PodSubnets, &other.IPv6PodSubnets
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
