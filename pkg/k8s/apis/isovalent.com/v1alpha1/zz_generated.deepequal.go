//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by deepequal-gen. DO NOT EDIT.

package v1alpha1

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *BFDEchoFunctionConfig) DeepEqual(other *BFDEchoFunctionConfig) bool {
	if other == nil {
		return false
	}

	if ((in.Directions != nil) && (other.Directions != nil)) || ((in.Directions == nil) != (other.Directions == nil)) {
		in, other := &in.Directions, &other.Directions
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

	if (in.ReceiveIntervalMilliseconds == nil) != (other.ReceiveIntervalMilliseconds == nil) {
		return false
	} else if in.ReceiveIntervalMilliseconds != nil {
		if *in.ReceiveIntervalMilliseconds != *other.ReceiveIntervalMilliseconds {
			return false
		}
	}

	if (in.TransmitIntervalMilliseconds == nil) != (other.TransmitIntervalMilliseconds == nil) {
		return false
	} else if in.TransmitIntervalMilliseconds != nil {
		if *in.TransmitIntervalMilliseconds != *other.TransmitIntervalMilliseconds {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *BFDNodeConfigOverridePeer) DeepEqual(other *BFDNodeConfigOverridePeer) bool {
	if other == nil {
		return false
	}

	if in.PeerAddress != other.PeerAddress {
		return false
	}
	if (in.Interface == nil) != (other.Interface == nil) {
		return false
	} else if in.Interface != nil {
		if *in.Interface != *other.Interface {
			return false
		}
	}

	if (in.LocalAddress == nil) != (other.LocalAddress == nil) {
		return false
	} else if in.LocalAddress != nil {
		if *in.LocalAddress != *other.LocalAddress {
			return false
		}
	}

	if (in.EchoSourceAddress == nil) != (other.EchoSourceAddress == nil) {
		return false
	} else if in.EchoSourceAddress != nil {
		if *in.EchoSourceAddress != *other.EchoSourceAddress {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *BFDNodeConfigOverrideSpec) DeepEqual(other *BFDNodeConfigOverrideSpec) bool {
	if other == nil {
		return false
	}

	if ((in.Peers != nil) && (other.Peers != nil)) || ((in.Peers == nil) != (other.Peers == nil)) {
		in, other := &in.Peers, &other.Peers
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
func (in *BFDNodeConfigSpec) DeepEqual(other *BFDNodeConfigSpec) bool {
	if other == nil {
		return false
	}

	if in.NodeRef != other.NodeRef {
		return false
	}
	if ((in.Peers != nil) && (other.Peers != nil)) || ((in.Peers == nil) != (other.Peers == nil)) {
		in, other := &in.Peers, &other.Peers
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
func (in *BFDNodePeerConfig) DeepEqual(other *BFDNodePeerConfig) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if in.PeerAddress != other.PeerAddress {
		return false
	}
	if in.BFDProfileRef != other.BFDProfileRef {
		return false
	}
	if (in.Interface == nil) != (other.Interface == nil) {
		return false
	} else if in.Interface != nil {
		if *in.Interface != *other.Interface {
			return false
		}
	}

	if (in.LocalAddress == nil) != (other.LocalAddress == nil) {
		return false
	} else if in.LocalAddress != nil {
		if *in.LocalAddress != *other.LocalAddress {
			return false
		}
	}

	if (in.EchoSourceAddress == nil) != (other.EchoSourceAddress == nil) {
		return false
	} else if in.EchoSourceAddress != nil {
		if *in.EchoSourceAddress != *other.EchoSourceAddress {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *BFDProfileSpec) DeepEqual(other *BFDProfileSpec) bool {
	if other == nil {
		return false
	}

	if (in.ReceiveIntervalMilliseconds == nil) != (other.ReceiveIntervalMilliseconds == nil) {
		return false
	} else if in.ReceiveIntervalMilliseconds != nil {
		if *in.ReceiveIntervalMilliseconds != *other.ReceiveIntervalMilliseconds {
			return false
		}
	}

	if (in.TransmitIntervalMilliseconds == nil) != (other.TransmitIntervalMilliseconds == nil) {
		return false
	} else if in.TransmitIntervalMilliseconds != nil {
		if *in.TransmitIntervalMilliseconds != *other.TransmitIntervalMilliseconds {
			return false
		}
	}

	if (in.DetectMultiplier == nil) != (other.DetectMultiplier == nil) {
		return false
	} else if in.DetectMultiplier != nil {
		if *in.DetectMultiplier != *other.DetectMultiplier {
			return false
		}
	}

	if (in.MinimumTTL == nil) != (other.MinimumTTL == nil) {
		return false
	} else if in.MinimumTTL != nil {
		if *in.MinimumTTL != *other.MinimumTTL {
			return false
		}
	}

	if (in.EchoFunction == nil) != (other.EchoFunction == nil) {
		return false
	} else if in.EchoFunction != nil {
		if !in.EchoFunction.DeepEqual(other.EchoFunction) {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *BGPAdvertisement) DeepEqual(other *BGPAdvertisement) bool {
	if other == nil {
		return false
	}

	if in.AdvertisementType != other.AdvertisementType {
		return false
	}
	if (in.Service == nil) != (other.Service == nil) {
		return false
	} else if in.Service != nil {
		if !in.Service.DeepEqual(other.Service) {
			return false
		}
	}

	if (in.Selector == nil) != (other.Selector == nil) {
		return false
	} else if in.Selector != nil {
		if !in.Selector.DeepEqual(other.Selector) {
			return false
		}
	}

	if (in.Attributes == nil) != (other.Attributes == nil) {
		return false
	} else if in.Attributes != nil {
		if !in.Attributes.DeepEqual(other.Attributes) {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *BGPVRF) DeepEqual(other *BGPVRF) bool {
	if other == nil {
		return false
	}

	if in.VRFRef != other.VRFRef {
		return false
	}
	if (in.ConfigRef == nil) != (other.ConfigRef == nil) {
		return false
	} else if in.ConfigRef != nil {
		if *in.ConfigRef != *other.ConfigRef {
			return false
		}
	}

	if (in.RD == nil) != (other.RD == nil) {
		return false
	} else if in.RD != nil {
		if *in.RD != *other.RD {
			return false
		}
	}

	if ((in.ImportRTs != nil) && (other.ImportRTs != nil)) || ((in.ImportRTs == nil) != (other.ImportRTs == nil)) {
		in, other := &in.ImportRTs, &other.ImportRTs
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

	if ((in.ExportRTs != nil) && (other.ExportRTs != nil)) || ((in.ExportRTs == nil) != (other.ExportRTs == nil)) {
		in, other := &in.ExportRTs, &other.ExportRTs
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

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IPAMPoolSpec) DeepEqual(other *IPAMPoolSpec) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IPAMSpec) DeepEqual(other *IPAMSpec) bool {
	if other == nil {
		return false
	}

	if in.Mode != other.Mode {
		return false
	}
	if in.Pool != other.Pool {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentBFDNodeConfig) DeepEqual(other *IsovalentBFDNodeConfig) bool {
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
func (in *IsovalentBFDNodeConfigOverride) DeepEqual(other *IsovalentBFDNodeConfigOverride) bool {
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
func (in *IsovalentBFDProfile) DeepEqual(other *IsovalentBFDProfile) bool {
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
func (in *IsovalentBGPAdvertisement) DeepEqual(other *IsovalentBGPAdvertisement) bool {
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
func (in *IsovalentBGPAdvertisementSpec) DeepEqual(other *IsovalentBGPAdvertisementSpec) bool {
	if other == nil {
		return false
	}

	if ((in.Advertisements != nil) && (other.Advertisements != nil)) || ((in.Advertisements == nil) != (other.Advertisements == nil)) {
		in, other := &in.Advertisements, &other.Advertisements
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
func (in *IsovalentBGPClusterConfig) DeepEqual(other *IsovalentBGPClusterConfig) bool {
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
func (in *IsovalentBGPClusterConfigSpec) DeepEqual(other *IsovalentBGPClusterConfigSpec) bool {
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

	if ((in.BGPInstances != nil) && (other.BGPInstances != nil)) || ((in.BGPInstances == nil) != (other.BGPInstances == nil)) {
		in, other := &in.BGPInstances, &other.BGPInstances
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
func (in *IsovalentBGPInstance) DeepEqual(other *IsovalentBGPInstance) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if (in.LocalASN == nil) != (other.LocalASN == nil) {
		return false
	} else if in.LocalASN != nil {
		if *in.LocalASN != *other.LocalASN {
			return false
		}
	}

	if ((in.Peers != nil) && (other.Peers != nil)) || ((in.Peers == nil) != (other.Peers == nil)) {
		in, other := &in.Peers, &other.Peers
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

	if ((in.VRFs != nil) && (other.VRFs != nil)) || ((in.VRFs == nil) != (other.VRFs == nil)) {
		in, other := &in.VRFs, &other.VRFs
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
func (in *IsovalentBGPNodeConfig) DeepEqual(other *IsovalentBGPNodeConfig) bool {
	if other == nil {
		return false
	}

	if !in.Spec.DeepEqual(&other.Spec) {
		return false
	}

	if !in.Status.DeepEqual(&other.Status) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentBGPNodeConfigInstanceOverride) DeepEqual(other *IsovalentBGPNodeConfigInstanceOverride) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if (in.RouterID == nil) != (other.RouterID == nil) {
		return false
	} else if in.RouterID != nil {
		if *in.RouterID != *other.RouterID {
			return false
		}
	}

	if (in.LocalPort == nil) != (other.LocalPort == nil) {
		return false
	} else if in.LocalPort != nil {
		if *in.LocalPort != *other.LocalPort {
			return false
		}
	}

	if (in.SRv6Responder == nil) != (other.SRv6Responder == nil) {
		return false
	} else if in.SRv6Responder != nil {
		if *in.SRv6Responder != *other.SRv6Responder {
			return false
		}
	}

	if ((in.Peers != nil) && (other.Peers != nil)) || ((in.Peers == nil) != (other.Peers == nil)) {
		in, other := &in.Peers, &other.Peers
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
func (in *IsovalentBGPNodeConfigOverride) DeepEqual(other *IsovalentBGPNodeConfigOverride) bool {
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
func (in *IsovalentBGPNodeConfigOverrideSpec) DeepEqual(other *IsovalentBGPNodeConfigOverrideSpec) bool {
	if other == nil {
		return false
	}

	if ((in.BGPInstances != nil) && (other.BGPInstances != nil)) || ((in.BGPInstances == nil) != (other.BGPInstances == nil)) {
		in, other := &in.BGPInstances, &other.BGPInstances
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
func (in *IsovalentBGPNodeConfigPeerOverride) DeepEqual(other *IsovalentBGPNodeConfigPeerOverride) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if (in.LocalAddress == nil) != (other.LocalAddress == nil) {
		return false
	} else if in.LocalAddress != nil {
		if *in.LocalAddress != *other.LocalAddress {
			return false
		}
	}

	if (in.LocalPort == nil) != (other.LocalPort == nil) {
		return false
	} else if in.LocalPort != nil {
		if *in.LocalPort != *other.LocalPort {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentBGPNodeInstance) DeepEqual(other *IsovalentBGPNodeInstance) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if (in.LocalASN == nil) != (other.LocalASN == nil) {
		return false
	} else if in.LocalASN != nil {
		if *in.LocalASN != *other.LocalASN {
			return false
		}
	}

	if (in.RouterID == nil) != (other.RouterID == nil) {
		return false
	} else if in.RouterID != nil {
		if *in.RouterID != *other.RouterID {
			return false
		}
	}

	if (in.LocalPort == nil) != (other.LocalPort == nil) {
		return false
	} else if in.LocalPort != nil {
		if *in.LocalPort != *other.LocalPort {
			return false
		}
	}

	if (in.SRv6Responder == nil) != (other.SRv6Responder == nil) {
		return false
	} else if in.SRv6Responder != nil {
		if *in.SRv6Responder != *other.SRv6Responder {
			return false
		}
	}

	if ((in.Peers != nil) && (other.Peers != nil)) || ((in.Peers == nil) != (other.Peers == nil)) {
		in, other := &in.Peers, &other.Peers
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

	if ((in.VRFs != nil) && (other.VRFs != nil)) || ((in.VRFs == nil) != (other.VRFs == nil)) {
		in, other := &in.VRFs, &other.VRFs
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
func (in *IsovalentBGPNodeInstanceStatus) DeepEqual(other *IsovalentBGPNodeInstanceStatus) bool {
	if other == nil {
		return false
	}

	if !in.CiliumBGPNodeInstanceStatus.DeepEqual(&other.CiliumBGPNodeInstanceStatus) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentBGPNodePeer) DeepEqual(other *IsovalentBGPNodePeer) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if (in.PeerAddress == nil) != (other.PeerAddress == nil) {
		return false
	} else if in.PeerAddress != nil {
		if *in.PeerAddress != *other.PeerAddress {
			return false
		}
	}

	if (in.PeerASN == nil) != (other.PeerASN == nil) {
		return false
	} else if in.PeerASN != nil {
		if *in.PeerASN != *other.PeerASN {
			return false
		}
	}

	if (in.LocalAddress == nil) != (other.LocalAddress == nil) {
		return false
	} else if in.LocalAddress != nil {
		if *in.LocalAddress != *other.LocalAddress {
			return false
		}
	}

	if (in.PeerConfigRef == nil) != (other.PeerConfigRef == nil) {
		return false
	} else if in.PeerConfigRef != nil {
		if !in.PeerConfigRef.DeepEqual(other.PeerConfigRef) {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentBGPNodeSpec) DeepEqual(other *IsovalentBGPNodeSpec) bool {
	if other == nil {
		return false
	}

	if ((in.BGPInstances != nil) && (other.BGPInstances != nil)) || ((in.BGPInstances == nil) != (other.BGPInstances == nil)) {
		in, other := &in.BGPInstances, &other.BGPInstances
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
func (in *IsovalentBGPNodeStatus) DeepEqual(other *IsovalentBGPNodeStatus) bool {
	if other == nil {
		return false
	}

	if ((in.BGPInstances != nil) && (other.BGPInstances != nil)) || ((in.BGPInstances == nil) != (other.BGPInstances == nil)) {
		in, other := &in.BGPInstances, &other.BGPInstances
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
func (in *IsovalentBGPNodeVRF) DeepEqual(other *IsovalentBGPNodeVRF) bool {
	if other == nil {
		return false
	}

	if in.VRFRef != other.VRFRef {
		return false
	}
	if (in.ConfigRef == nil) != (other.ConfigRef == nil) {
		return false
	} else if in.ConfigRef != nil {
		if *in.ConfigRef != *other.ConfigRef {
			return false
		}
	}

	if (in.RD == nil) != (other.RD == nil) {
		return false
	} else if in.RD != nil {
		if *in.RD != *other.RD {
			return false
		}
	}

	if ((in.ImportRTs != nil) && (other.ImportRTs != nil)) || ((in.ImportRTs == nil) != (other.ImportRTs == nil)) {
		in, other := &in.ImportRTs, &other.ImportRTs
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

	if ((in.ExportRTs != nil) && (other.ExportRTs != nil)) || ((in.ExportRTs == nil) != (other.ExportRTs == nil)) {
		in, other := &in.ExportRTs, &other.ExportRTs
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

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentBGPPeer) DeepEqual(other *IsovalentBGPPeer) bool {
	if other == nil {
		return false
	}

	if in.Name != other.Name {
		return false
	}
	if (in.PeerAddress == nil) != (other.PeerAddress == nil) {
		return false
	} else if in.PeerAddress != nil {
		if *in.PeerAddress != *other.PeerAddress {
			return false
		}
	}

	if (in.PeerASN == nil) != (other.PeerASN == nil) {
		return false
	} else if in.PeerASN != nil {
		if *in.PeerASN != *other.PeerASN {
			return false
		}
	}

	if (in.PeerConfigRef == nil) != (other.PeerConfigRef == nil) {
		return false
	} else if in.PeerConfigRef != nil {
		if !in.PeerConfigRef.DeepEqual(other.PeerConfigRef) {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentBGPPeerConfig) DeepEqual(other *IsovalentBGPPeerConfig) bool {
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
func (in *IsovalentBGPPeerConfigSpec) DeepEqual(other *IsovalentBGPPeerConfigSpec) bool {
	if other == nil {
		return false
	}

	if !in.CiliumBGPPeerConfigSpec.DeepEqual(&other.CiliumBGPPeerConfigSpec) {
		return false
	}

	if (in.BFDProfileRef == nil) != (other.BFDProfileRef == nil) {
		return false
	} else if in.BFDProfileRef != nil {
		if *in.BFDProfileRef != *other.BFDProfileRef {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentBGPVRFConfig) DeepEqual(other *IsovalentBGPVRFConfig) bool {
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
func (in *IsovalentBGPVRFConfigSpec) DeepEqual(other *IsovalentBGPVRFConfigSpec) bool {
	if other == nil {
		return false
	}

	if ((in.Families != nil) && (other.Families != nil)) || ((in.Families == nil) != (other.Families == nil)) {
		in, other := &in.Families, &other.Families
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
func (in *IsovalentFQDNGroupSpec) DeepEqual(other *IsovalentFQDNGroupSpec) bool {
	if other == nil {
		return false
	}

	if ((in.FQDNs != nil) && (other.FQDNs != nil)) || ((in.FQDNs == nil) != (other.FQDNs == nil)) {
		in, other := &in.FQDNs, &other.FQDNs
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

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentMeshEndpoint) DeepEqual(other *IsovalentMeshEndpoint) bool {
	if other == nil {
		return false
	}

	if in.Spec != other.Spec {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentMeshEndpointSpec) DeepEqual(other *IsovalentMeshEndpointSpec) bool {
	if other == nil {
		return false
	}

	if in.IP != other.IP {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentMulticastGroup) DeepEqual(other *IsovalentMulticastGroup) bool {
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
func (in *IsovalentMulticastGroupSpec) DeepEqual(other *IsovalentMulticastGroupSpec) bool {
	if other == nil {
		return false
	}

	if ((in.GroupAddrs != nil) && (other.GroupAddrs != nil)) || ((in.GroupAddrs == nil) != (other.GroupAddrs == nil)) {
		in, other := &in.GroupAddrs, &other.GroupAddrs
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

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentMulticastNode) DeepEqual(other *IsovalentMulticastNode) bool {
	if other == nil {
		return false
	}

	if in.Spec != other.Spec {
		return false
	}

	if !in.Status.DeepEqual(&other.Status) {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentMulticastNodeSpec) DeepEqual(other *IsovalentMulticastNodeSpec) bool {
	if other == nil {
		return false
	}

	if in.NodeIP != other.NodeIP {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentMulticastNodeStatus) DeepEqual(other *IsovalentMulticastNodeStatus) bool {
	if other == nil {
		return false
	}

	if ((in.MulticastSubscribers != nil) && (other.MulticastSubscribers != nil)) || ((in.MulticastSubscribers == nil) != (other.MulticastSubscribers == nil)) {
		in, other := &in.MulticastSubscribers, &other.MulticastSubscribers
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
func (in *IsovalentSRv6EgressPolicy) DeepEqual(other *IsovalentSRv6EgressPolicy) bool {
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
func (in *IsovalentSRv6EgressPolicySpec) DeepEqual(other *IsovalentSRv6EgressPolicySpec) bool {
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
func (in *IsovalentSRv6Locator) DeepEqual(other *IsovalentSRv6Locator) bool {
	if other == nil {
		return false
	}

	if in.Prefix != other.Prefix {
		return false
	}
	if in.Structure != other.Structure {
		return false
	}

	if in.BehaviorType != other.BehaviorType {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentSRv6LocatorAllocation) DeepEqual(other *IsovalentSRv6LocatorAllocation) bool {
	if other == nil {
		return false
	}

	if in.PoolRef != other.PoolRef {
		return false
	}
	if ((in.Locators != nil) && (other.Locators != nil)) || ((in.Locators == nil) != (other.Locators == nil)) {
		in, other := &in.Locators, &other.Locators
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
func (in *IsovalentSRv6LocatorPool) DeepEqual(other *IsovalentSRv6LocatorPool) bool {
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
func (in *IsovalentSRv6LocatorPoolSpec) DeepEqual(other *IsovalentSRv6LocatorPoolSpec) bool {
	if other == nil {
		return false
	}

	if in.Prefix != other.Prefix {
		return false
	}
	if (in.LocatorLenBits == nil) != (other.LocatorLenBits == nil) {
		return false
	} else if in.LocatorLenBits != nil {
		if *in.LocatorLenBits != *other.LocatorLenBits {
			return false
		}
	}

	if in.Structure != other.Structure {
		return false
	}

	if in.BehaviorType != other.BehaviorType {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentSRv6SID) DeepEqual(other *IsovalentSRv6SID) bool {
	if other == nil {
		return false
	}

	if in.Addr != other.Addr {
		return false
	}
	if in.Structure != other.Structure {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentSRv6SIDAllocation) DeepEqual(other *IsovalentSRv6SIDAllocation) bool {
	if other == nil {
		return false
	}

	if in.PoolRef != other.PoolRef {
		return false
	}
	if ((in.SIDs != nil) && (other.SIDs != nil)) || ((in.SIDs == nil) != (other.SIDs == nil)) {
		in, other := &in.SIDs, &other.SIDs
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
func (in *IsovalentSRv6SIDInfo) DeepEqual(other *IsovalentSRv6SIDInfo) bool {
	if other == nil {
		return false
	}

	if in.SID != other.SID {
		return false
	}

	if in.Owner != other.Owner {
		return false
	}
	if in.MetaData != other.MetaData {
		return false
	}
	if in.BehaviorType != other.BehaviorType {
		return false
	}
	if in.Behavior != other.Behavior {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentSRv6SIDManager) DeepEqual(other *IsovalentSRv6SIDManager) bool {
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
func (in *IsovalentSRv6SIDManagerSpec) DeepEqual(other *IsovalentSRv6SIDManagerSpec) bool {
	if other == nil {
		return false
	}

	if ((in.LocatorAllocations != nil) && (other.LocatorAllocations != nil)) || ((in.LocatorAllocations == nil) != (other.LocatorAllocations == nil)) {
		in, other := &in.LocatorAllocations, &other.LocatorAllocations
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
func (in *IsovalentSRv6SIDManagerStatus) DeepEqual(other *IsovalentSRv6SIDManagerStatus) bool {
	if other == nil {
		return false
	}

	if ((in.SIDAllocations != nil) && (other.SIDAllocations != nil)) || ((in.SIDAllocations == nil) != (other.SIDAllocations == nil)) {
		in, other := &in.SIDAllocations, &other.SIDAllocations
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
func (in *IsovalentSRv6SIDStructure) DeepEqual(other *IsovalentSRv6SIDStructure) bool {
	if other == nil {
		return false
	}

	if in.LocatorBlockLenBits != other.LocatorBlockLenBits {
		return false
	}
	if in.LocatorNodeLenBits != other.LocatorNodeLenBits {
		return false
	}
	if in.FunctionLenBits != other.FunctionLenBits {
		return false
	}
	if in.ArgumentLenBits != other.ArgumentLenBits {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentVRF) DeepEqual(other *IsovalentVRF) bool {
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
func (in *IsovalentVRFEgressRule) DeepEqual(other *IsovalentVRFEgressRule) bool {
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

	if (in.EndpointSelector == nil) != (other.EndpointSelector == nil) {
		return false
	} else if in.EndpointSelector != nil {
		if !in.EndpointSelector.DeepEqual(other.EndpointSelector) {
			return false
		}
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentVRFRule) DeepEqual(other *IsovalentVRFRule) bool {
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

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *IsovalentVRFSpec) DeepEqual(other *IsovalentVRFSpec) bool {
	if other == nil {
		return false
	}

	if in.VRFID != other.VRFID {
		return false
	}
	if in.ImportRouteTarget != other.ImportRouteTarget {
		return false
	}
	if in.ExportRouteTarget != other.ExportRouteTarget {
		return false
	}
	if in.LocatorPoolRef != other.LocatorPoolRef {
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
func (in *MulticastNodeSubscriberData) DeepEqual(other *MulticastNodeSubscriberData) bool {
	if other == nil {
		return false
	}

	if in.GroupAddr != other.GroupAddr {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *PeerConfigReference) DeepEqual(other *PeerConfigReference) bool {
	if other == nil {
		return false
	}

	if in.Group != other.Group {
		return false
	}
	if in.Kind != other.Kind {
		return false
	}
	if in.Name != other.Name {
		return false
	}

	return true
}

// DeepEqual is an autogenerated deepequal function, deeply comparing the
// receiver with other. in must be non-nil.
func (in *PodNetworkSpec) DeepEqual(other *PodNetworkSpec) bool {
	if other == nil {
		return false
	}

	if in.IPAM != other.IPAM {
		return false
	}

	if ((in.Routes != nil) && (other.Routes != nil)) || ((in.Routes == nil) != (other.Routes == nil)) {
		in, other := &in.Routes, &other.Routes
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
func (in *RouteSpec) DeepEqual(other *RouteSpec) bool {
	if other == nil {
		return false
	}

	if in.Destination != other.Destination {
		return false
	}
	if in.Gateway != other.Gateway {
		return false
	}

	return true
}
