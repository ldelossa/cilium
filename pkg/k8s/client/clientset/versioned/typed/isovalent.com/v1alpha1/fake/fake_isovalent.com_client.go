// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/isovalent.com/v1alpha1"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeIsovalentV1alpha1 struct {
	*testing.Fake
}

func (c *FakeIsovalentV1alpha1) IsovalentFQDNGroups() v1alpha1.IsovalentFQDNGroupInterface {
	return &FakeIsovalentFQDNGroups{c}
}

func (c *FakeIsovalentV1alpha1) IsovalentMulticastGroups() v1alpha1.IsovalentMulticastGroupInterface {
	return &FakeIsovalentMulticastGroups{c}
}

func (c *FakeIsovalentV1alpha1) IsovalentMulticastNodes() v1alpha1.IsovalentMulticastNodeInterface {
	return &FakeIsovalentMulticastNodes{c}
}

func (c *FakeIsovalentV1alpha1) IsovalentPodNetworks() v1alpha1.IsovalentPodNetworkInterface {
	return &FakeIsovalentPodNetworks{c}
}

func (c *FakeIsovalentV1alpha1) IsovalentSRv6EgressPolicies() v1alpha1.IsovalentSRv6EgressPolicyInterface {
	return &FakeIsovalentSRv6EgressPolicies{c}
}

func (c *FakeIsovalentV1alpha1) IsovalentSRv6LocatorPools() v1alpha1.IsovalentSRv6LocatorPoolInterface {
	return &FakeIsovalentSRv6LocatorPools{c}
}

func (c *FakeIsovalentV1alpha1) IsovalentSRv6SIDManagers() v1alpha1.IsovalentSRv6SIDManagerInterface {
	return &FakeIsovalentSRv6SIDManagers{c}
}

func (c *FakeIsovalentV1alpha1) IsovalentVRFs() v1alpha1.IsovalentVRFInterface {
	return &FakeIsovalentVRFs{c}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeIsovalentV1alpha1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
