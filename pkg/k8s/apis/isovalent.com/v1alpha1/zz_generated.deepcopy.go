//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BFDEchoFunctionConfig) DeepCopyInto(out *BFDEchoFunctionConfig) {
	*out = *in
	if in.Directions != nil {
		in, out := &in.Directions, &out.Directions
		*out = make([]BFDEchoFunctionDirection, len(*in))
		copy(*out, *in)
	}
	if in.ReceiveIntervalMilliseconds != nil {
		in, out := &in.ReceiveIntervalMilliseconds, &out.ReceiveIntervalMilliseconds
		*out = new(int32)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BFDEchoFunctionConfig.
func (in *BFDEchoFunctionConfig) DeepCopy() *BFDEchoFunctionConfig {
	if in == nil {
		return nil
	}
	out := new(BFDEchoFunctionConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BFDNodeConfigSpec) DeepCopyInto(out *BFDNodeConfigSpec) {
	*out = *in
	if in.Peers != nil {
		in, out := &in.Peers, &out.Peers
		*out = make([]*BFDNodePeerConfig, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(BFDNodePeerConfig)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BFDNodeConfigSpec.
func (in *BFDNodeConfigSpec) DeepCopy() *BFDNodeConfigSpec {
	if in == nil {
		return nil
	}
	out := new(BFDNodeConfigSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BFDNodeConfigStatus) DeepCopyInto(out *BFDNodeConfigStatus) {
	*out = *in
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]v1.Condition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BFDNodeConfigStatus.
func (in *BFDNodeConfigStatus) DeepCopy() *BFDNodeConfigStatus {
	if in == nil {
		return nil
	}
	out := new(BFDNodeConfigStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BFDNodePeerConfig) DeepCopyInto(out *BFDNodePeerConfig) {
	*out = *in
	if in.Interface != nil {
		in, out := &in.Interface, &out.Interface
		*out = new(string)
		**out = **in
	}
	if in.LocalAddress != nil {
		in, out := &in.LocalAddress, &out.LocalAddress
		*out = new(string)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BFDNodePeerConfig.
func (in *BFDNodePeerConfig) DeepCopy() *BFDNodePeerConfig {
	if in == nil {
		return nil
	}
	out := new(BFDNodePeerConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *BFDProfileSpec) DeepCopyInto(out *BFDProfileSpec) {
	*out = *in
	if in.ReceiveIntervalMilliseconds != nil {
		in, out := &in.ReceiveIntervalMilliseconds, &out.ReceiveIntervalMilliseconds
		*out = new(int32)
		**out = **in
	}
	if in.TransmitIntervalMilliseconds != nil {
		in, out := &in.TransmitIntervalMilliseconds, &out.TransmitIntervalMilliseconds
		*out = new(int32)
		**out = **in
	}
	if in.DetectMultiplier != nil {
		in, out := &in.DetectMultiplier, &out.DetectMultiplier
		*out = new(int32)
		**out = **in
	}
	if in.MinimumTTL != nil {
		in, out := &in.MinimumTTL, &out.MinimumTTL
		*out = new(int32)
		**out = **in
	}
	if in.EchoFunction != nil {
		in, out := &in.EchoFunction, &out.EchoFunction
		*out = new(BFDEchoFunctionConfig)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new BFDProfileSpec.
func (in *BFDProfileSpec) DeepCopy() *BFDProfileSpec {
	if in == nil {
		return nil
	}
	out := new(BFDProfileSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPAMPoolSpec) DeepCopyInto(out *IPAMPoolSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPAMPoolSpec.
func (in *IPAMPoolSpec) DeepCopy() *IPAMPoolSpec {
	if in == nil {
		return nil
	}
	out := new(IPAMPoolSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IPAMSpec) DeepCopyInto(out *IPAMSpec) {
	*out = *in
	out.Pool = in.Pool
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IPAMSpec.
func (in *IPAMSpec) DeepCopy() *IPAMSpec {
	if in == nil {
		return nil
	}
	out := new(IPAMSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentBFDNodeConfig) DeepCopyInto(out *IsovalentBFDNodeConfig) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(BFDNodeConfigStatus)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentBFDNodeConfig.
func (in *IsovalentBFDNodeConfig) DeepCopy() *IsovalentBFDNodeConfig {
	if in == nil {
		return nil
	}
	out := new(IsovalentBFDNodeConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentBFDNodeConfig) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentBFDNodeConfigList) DeepCopyInto(out *IsovalentBFDNodeConfigList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IsovalentBFDNodeConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentBFDNodeConfigList.
func (in *IsovalentBFDNodeConfigList) DeepCopy() *IsovalentBFDNodeConfigList {
	if in == nil {
		return nil
	}
	out := new(IsovalentBFDNodeConfigList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentBFDNodeConfigList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentBFDProfile) DeepCopyInto(out *IsovalentBFDProfile) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentBFDProfile.
func (in *IsovalentBFDProfile) DeepCopy() *IsovalentBFDProfile {
	if in == nil {
		return nil
	}
	out := new(IsovalentBFDProfile)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentBFDProfile) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentBFDProfileList) DeepCopyInto(out *IsovalentBFDProfileList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IsovalentBFDProfile, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentBFDProfileList.
func (in *IsovalentBFDProfileList) DeepCopy() *IsovalentBFDProfileList {
	if in == nil {
		return nil
	}
	out := new(IsovalentBFDProfileList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentBFDProfileList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentFQDNGroup) DeepCopyInto(out *IsovalentFQDNGroup) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentFQDNGroup.
func (in *IsovalentFQDNGroup) DeepCopy() *IsovalentFQDNGroup {
	if in == nil {
		return nil
	}
	out := new(IsovalentFQDNGroup)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentFQDNGroup) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentFQDNGroupList) DeepCopyInto(out *IsovalentFQDNGroupList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IsovalentFQDNGroup, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentFQDNGroupList.
func (in *IsovalentFQDNGroupList) DeepCopy() *IsovalentFQDNGroupList {
	if in == nil {
		return nil
	}
	out := new(IsovalentFQDNGroupList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentFQDNGroupList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentFQDNGroupSpec) DeepCopyInto(out *IsovalentFQDNGroupSpec) {
	*out = *in
	if in.FQDNs != nil {
		in, out := &in.FQDNs, &out.FQDNs
		*out = make([]FQDN, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentFQDNGroupSpec.
func (in *IsovalentFQDNGroupSpec) DeepCopy() *IsovalentFQDNGroupSpec {
	if in == nil {
		return nil
	}
	out := new(IsovalentFQDNGroupSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentMeshEndpoint) DeepCopyInto(out *IsovalentMeshEndpoint) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentMeshEndpoint.
func (in *IsovalentMeshEndpoint) DeepCopy() *IsovalentMeshEndpoint {
	if in == nil {
		return nil
	}
	out := new(IsovalentMeshEndpoint)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentMeshEndpoint) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentMeshEndpointList) DeepCopyInto(out *IsovalentMeshEndpointList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IsovalentMeshEndpoint, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentMeshEndpointList.
func (in *IsovalentMeshEndpointList) DeepCopy() *IsovalentMeshEndpointList {
	if in == nil {
		return nil
	}
	out := new(IsovalentMeshEndpointList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentMeshEndpointList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentMeshEndpointSpec) DeepCopyInto(out *IsovalentMeshEndpointSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentMeshEndpointSpec.
func (in *IsovalentMeshEndpointSpec) DeepCopy() *IsovalentMeshEndpointSpec {
	if in == nil {
		return nil
	}
	out := new(IsovalentMeshEndpointSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentMulticastGroup) DeepCopyInto(out *IsovalentMulticastGroup) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentMulticastGroup.
func (in *IsovalentMulticastGroup) DeepCopy() *IsovalentMulticastGroup {
	if in == nil {
		return nil
	}
	out := new(IsovalentMulticastGroup)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentMulticastGroup) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentMulticastGroupList) DeepCopyInto(out *IsovalentMulticastGroupList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IsovalentMulticastGroup, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentMulticastGroupList.
func (in *IsovalentMulticastGroupList) DeepCopy() *IsovalentMulticastGroupList {
	if in == nil {
		return nil
	}
	out := new(IsovalentMulticastGroupList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentMulticastGroupList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentMulticastGroupSpec) DeepCopyInto(out *IsovalentMulticastGroupSpec) {
	*out = *in
	if in.GroupAddrs != nil {
		in, out := &in.GroupAddrs, &out.GroupAddrs
		*out = make([]MulticastGroupAddr, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentMulticastGroupSpec.
func (in *IsovalentMulticastGroupSpec) DeepCopy() *IsovalentMulticastGroupSpec {
	if in == nil {
		return nil
	}
	out := new(IsovalentMulticastGroupSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentMulticastNode) DeepCopyInto(out *IsovalentMulticastNode) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentMulticastNode.
func (in *IsovalentMulticastNode) DeepCopy() *IsovalentMulticastNode {
	if in == nil {
		return nil
	}
	out := new(IsovalentMulticastNode)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentMulticastNode) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentMulticastNodeList) DeepCopyInto(out *IsovalentMulticastNodeList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IsovalentMulticastNode, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentMulticastNodeList.
func (in *IsovalentMulticastNodeList) DeepCopy() *IsovalentMulticastNodeList {
	if in == nil {
		return nil
	}
	out := new(IsovalentMulticastNodeList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentMulticastNodeList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentMulticastNodeSpec) DeepCopyInto(out *IsovalentMulticastNodeSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentMulticastNodeSpec.
func (in *IsovalentMulticastNodeSpec) DeepCopy() *IsovalentMulticastNodeSpec {
	if in == nil {
		return nil
	}
	out := new(IsovalentMulticastNodeSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentMulticastNodeStatus) DeepCopyInto(out *IsovalentMulticastNodeStatus) {
	*out = *in
	if in.MulticastSubscribers != nil {
		in, out := &in.MulticastSubscribers, &out.MulticastSubscribers
		*out = make([]MulticastNodeSubscriberData, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentMulticastNodeStatus.
func (in *IsovalentMulticastNodeStatus) DeepCopy() *IsovalentMulticastNodeStatus {
	if in == nil {
		return nil
	}
	out := new(IsovalentMulticastNodeStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentPodNetwork) DeepCopyInto(out *IsovalentPodNetwork) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentPodNetwork.
func (in *IsovalentPodNetwork) DeepCopy() *IsovalentPodNetwork {
	if in == nil {
		return nil
	}
	out := new(IsovalentPodNetwork)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentPodNetwork) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentPodNetworkList) DeepCopyInto(out *IsovalentPodNetworkList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IsovalentPodNetwork, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentPodNetworkList.
func (in *IsovalentPodNetworkList) DeepCopy() *IsovalentPodNetworkList {
	if in == nil {
		return nil
	}
	out := new(IsovalentPodNetworkList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentPodNetworkList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6EgressPolicy) DeepCopyInto(out *IsovalentSRv6EgressPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6EgressPolicy.
func (in *IsovalentSRv6EgressPolicy) DeepCopy() *IsovalentSRv6EgressPolicy {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6EgressPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentSRv6EgressPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6EgressPolicyList) DeepCopyInto(out *IsovalentSRv6EgressPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IsovalentSRv6EgressPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6EgressPolicyList.
func (in *IsovalentSRv6EgressPolicyList) DeepCopy() *IsovalentSRv6EgressPolicyList {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6EgressPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentSRv6EgressPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6EgressPolicySpec) DeepCopyInto(out *IsovalentSRv6EgressPolicySpec) {
	*out = *in
	if in.DestinationCIDRs != nil {
		in, out := &in.DestinationCIDRs, &out.DestinationCIDRs
		*out = make([]CIDR, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6EgressPolicySpec.
func (in *IsovalentSRv6EgressPolicySpec) DeepCopy() *IsovalentSRv6EgressPolicySpec {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6EgressPolicySpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6Locator) DeepCopyInto(out *IsovalentSRv6Locator) {
	*out = *in
	out.Structure = in.Structure
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6Locator.
func (in *IsovalentSRv6Locator) DeepCopy() *IsovalentSRv6Locator {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6Locator)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6LocatorAllocation) DeepCopyInto(out *IsovalentSRv6LocatorAllocation) {
	*out = *in
	if in.Locators != nil {
		in, out := &in.Locators, &out.Locators
		*out = make([]*IsovalentSRv6Locator, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(IsovalentSRv6Locator)
				**out = **in
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6LocatorAllocation.
func (in *IsovalentSRv6LocatorAllocation) DeepCopy() *IsovalentSRv6LocatorAllocation {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6LocatorAllocation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6LocatorPool) DeepCopyInto(out *IsovalentSRv6LocatorPool) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6LocatorPool.
func (in *IsovalentSRv6LocatorPool) DeepCopy() *IsovalentSRv6LocatorPool {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6LocatorPool)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentSRv6LocatorPool) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6LocatorPoolList) DeepCopyInto(out *IsovalentSRv6LocatorPoolList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IsovalentSRv6LocatorPool, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6LocatorPoolList.
func (in *IsovalentSRv6LocatorPoolList) DeepCopy() *IsovalentSRv6LocatorPoolList {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6LocatorPoolList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentSRv6LocatorPoolList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6LocatorPoolSpec) DeepCopyInto(out *IsovalentSRv6LocatorPoolSpec) {
	*out = *in
	out.Structure = in.Structure
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6LocatorPoolSpec.
func (in *IsovalentSRv6LocatorPoolSpec) DeepCopy() *IsovalentSRv6LocatorPoolSpec {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6LocatorPoolSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6SID) DeepCopyInto(out *IsovalentSRv6SID) {
	*out = *in
	out.Structure = in.Structure
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6SID.
func (in *IsovalentSRv6SID) DeepCopy() *IsovalentSRv6SID {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6SID)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6SIDAllocation) DeepCopyInto(out *IsovalentSRv6SIDAllocation) {
	*out = *in
	if in.SIDs != nil {
		in, out := &in.SIDs, &out.SIDs
		*out = make([]*IsovalentSRv6SIDInfo, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(IsovalentSRv6SIDInfo)
				**out = **in
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6SIDAllocation.
func (in *IsovalentSRv6SIDAllocation) DeepCopy() *IsovalentSRv6SIDAllocation {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6SIDAllocation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6SIDInfo) DeepCopyInto(out *IsovalentSRv6SIDInfo) {
	*out = *in
	out.SID = in.SID
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6SIDInfo.
func (in *IsovalentSRv6SIDInfo) DeepCopy() *IsovalentSRv6SIDInfo {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6SIDInfo)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6SIDManager) DeepCopyInto(out *IsovalentSRv6SIDManager) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	if in.Status != nil {
		in, out := &in.Status, &out.Status
		*out = new(IsovalentSRv6SIDManagerStatus)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6SIDManager.
func (in *IsovalentSRv6SIDManager) DeepCopy() *IsovalentSRv6SIDManager {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6SIDManager)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentSRv6SIDManager) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6SIDManagerList) DeepCopyInto(out *IsovalentSRv6SIDManagerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IsovalentSRv6SIDManager, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6SIDManagerList.
func (in *IsovalentSRv6SIDManagerList) DeepCopy() *IsovalentSRv6SIDManagerList {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6SIDManagerList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentSRv6SIDManagerList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6SIDManagerSpec) DeepCopyInto(out *IsovalentSRv6SIDManagerSpec) {
	*out = *in
	if in.LocatorAllocations != nil {
		in, out := &in.LocatorAllocations, &out.LocatorAllocations
		*out = make([]*IsovalentSRv6LocatorAllocation, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(IsovalentSRv6LocatorAllocation)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6SIDManagerSpec.
func (in *IsovalentSRv6SIDManagerSpec) DeepCopy() *IsovalentSRv6SIDManagerSpec {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6SIDManagerSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6SIDManagerStatus) DeepCopyInto(out *IsovalentSRv6SIDManagerStatus) {
	*out = *in
	if in.SIDAllocations != nil {
		in, out := &in.SIDAllocations, &out.SIDAllocations
		*out = make([]*IsovalentSRv6SIDAllocation, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(IsovalentSRv6SIDAllocation)
				(*in).DeepCopyInto(*out)
			}
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6SIDManagerStatus.
func (in *IsovalentSRv6SIDManagerStatus) DeepCopy() *IsovalentSRv6SIDManagerStatus {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6SIDManagerStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentSRv6SIDStructure) DeepCopyInto(out *IsovalentSRv6SIDStructure) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentSRv6SIDStructure.
func (in *IsovalentSRv6SIDStructure) DeepCopy() *IsovalentSRv6SIDStructure {
	if in == nil {
		return nil
	}
	out := new(IsovalentSRv6SIDStructure)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentVRF) DeepCopyInto(out *IsovalentVRF) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentVRF.
func (in *IsovalentVRF) DeepCopy() *IsovalentVRF {
	if in == nil {
		return nil
	}
	out := new(IsovalentVRF)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentVRF) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentVRFEgressRule) DeepCopyInto(out *IsovalentVRFEgressRule) {
	*out = *in
	if in.NamespaceSelector != nil {
		in, out := &in.NamespaceSelector, &out.NamespaceSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.EndpointSelector != nil {
		in, out := &in.EndpointSelector, &out.EndpointSelector
		*out = new(metav1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentVRFEgressRule.
func (in *IsovalentVRFEgressRule) DeepCopy() *IsovalentVRFEgressRule {
	if in == nil {
		return nil
	}
	out := new(IsovalentVRFEgressRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentVRFList) DeepCopyInto(out *IsovalentVRFList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IsovalentVRF, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentVRFList.
func (in *IsovalentVRFList) DeepCopy() *IsovalentVRFList {
	if in == nil {
		return nil
	}
	out := new(IsovalentVRFList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IsovalentVRFList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentVRFRule) DeepCopyInto(out *IsovalentVRFRule) {
	*out = *in
	if in.Selectors != nil {
		in, out := &in.Selectors, &out.Selectors
		*out = make([]IsovalentVRFEgressRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.DestinationCIDRs != nil {
		in, out := &in.DestinationCIDRs, &out.DestinationCIDRs
		*out = make([]CIDR, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentVRFRule.
func (in *IsovalentVRFRule) DeepCopy() *IsovalentVRFRule {
	if in == nil {
		return nil
	}
	out := new(IsovalentVRFRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IsovalentVRFSpec) DeepCopyInto(out *IsovalentVRFSpec) {
	*out = *in
	if in.Rules != nil {
		in, out := &in.Rules, &out.Rules
		*out = make([]IsovalentVRFRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IsovalentVRFSpec.
func (in *IsovalentVRFSpec) DeepCopy() *IsovalentVRFSpec {
	if in == nil {
		return nil
	}
	out := new(IsovalentVRFSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MulticastNodeSubscriberData) DeepCopyInto(out *MulticastNodeSubscriberData) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MulticastNodeSubscriberData.
func (in *MulticastNodeSubscriberData) DeepCopy() *MulticastNodeSubscriberData {
	if in == nil {
		return nil
	}
	out := new(MulticastNodeSubscriberData)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PodNetworkSpec) DeepCopyInto(out *PodNetworkSpec) {
	*out = *in
	out.IPAM = in.IPAM
	if in.Routes != nil {
		in, out := &in.Routes, &out.Routes
		*out = make([]RouteSpec, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PodNetworkSpec.
func (in *PodNetworkSpec) DeepCopy() *PodNetworkSpec {
	if in == nil {
		return nil
	}
	out := new(PodNetworkSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RouteSpec) DeepCopyInto(out *RouteSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RouteSpec.
func (in *RouteSpec) DeepCopy() *RouteSpec {
	if in == nil {
		return nil
	}
	out := new(RouteSpec)
	in.DeepCopyInto(out)
	return out
}
