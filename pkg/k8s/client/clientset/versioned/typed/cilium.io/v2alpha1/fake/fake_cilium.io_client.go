// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeCiliumV2alpha1 struct {
	*testing.Fake
}

func (c *FakeCiliumV2alpha1) CiliumBGPPeeringPolicies() v2alpha1.CiliumBGPPeeringPolicyInterface {
	return &FakeCiliumBGPPeeringPolicies{c}
}

func (c *FakeCiliumV2alpha1) CiliumCIDRGroups() v2alpha1.CiliumCIDRGroupInterface {
	return &FakeCiliumCIDRGroups{c}
}

func (c *FakeCiliumV2alpha1) CiliumEndpointSlices() v2alpha1.CiliumEndpointSliceInterface {
	return &FakeCiliumEndpointSlices{c}
}

func (c *FakeCiliumV2alpha1) CiliumLoadBalancerIPPools() v2alpha1.CiliumLoadBalancerIPPoolInterface {
	return &FakeCiliumLoadBalancerIPPools{c}
}

func (c *FakeCiliumV2alpha1) CiliumNodeConfigs(namespace string) v2alpha1.CiliumNodeConfigInterface {
	return &FakeCiliumNodeConfigs{c, namespace}
}

func (c *FakeCiliumV2alpha1) CiliumSRv6EgressPolicies() v2alpha1.CiliumSRv6EgressPolicyInterface {
	return &FakeCiliumSRv6EgressPolicies{c}
}

func (c *FakeCiliumV2alpha1) CiliumSRv6VRFs() v2alpha1.CiliumSRv6VRFInterface {
	return &FakeCiliumSRv6VRFs{c}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeCiliumV2alpha1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
