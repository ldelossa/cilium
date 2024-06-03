// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeIsovalentBGPPeerConfigs implements IsovalentBGPPeerConfigInterface
type FakeIsovalentBGPPeerConfigs struct {
	Fake *FakeIsovalentV1alpha1
}

var isovalentbgppeerconfigsResource = v1alpha1.SchemeGroupVersion.WithResource("isovalentbgppeerconfigs")

var isovalentbgppeerconfigsKind = v1alpha1.SchemeGroupVersion.WithKind("IsovalentBGPPeerConfig")

// Get takes name of the isovalentBGPPeerConfig, and returns the corresponding isovalentBGPPeerConfig object, and an error if there is any.
func (c *FakeIsovalentBGPPeerConfigs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.IsovalentBGPPeerConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(isovalentbgppeerconfigsResource, name), &v1alpha1.IsovalentBGPPeerConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentBGPPeerConfig), err
}

// List takes label and field selectors, and returns the list of IsovalentBGPPeerConfigs that match those selectors.
func (c *FakeIsovalentBGPPeerConfigs) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.IsovalentBGPPeerConfigList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(isovalentbgppeerconfigsResource, isovalentbgppeerconfigsKind, opts), &v1alpha1.IsovalentBGPPeerConfigList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.IsovalentBGPPeerConfigList{ListMeta: obj.(*v1alpha1.IsovalentBGPPeerConfigList).ListMeta}
	for _, item := range obj.(*v1alpha1.IsovalentBGPPeerConfigList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested isovalentBGPPeerConfigs.
func (c *FakeIsovalentBGPPeerConfigs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(isovalentbgppeerconfigsResource, opts))
}

// Create takes the representation of a isovalentBGPPeerConfig and creates it.  Returns the server's representation of the isovalentBGPPeerConfig, and an error, if there is any.
func (c *FakeIsovalentBGPPeerConfigs) Create(ctx context.Context, isovalentBGPPeerConfig *v1alpha1.IsovalentBGPPeerConfig, opts v1.CreateOptions) (result *v1alpha1.IsovalentBGPPeerConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(isovalentbgppeerconfigsResource, isovalentBGPPeerConfig), &v1alpha1.IsovalentBGPPeerConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentBGPPeerConfig), err
}

// Update takes the representation of a isovalentBGPPeerConfig and updates it. Returns the server's representation of the isovalentBGPPeerConfig, and an error, if there is any.
func (c *FakeIsovalentBGPPeerConfigs) Update(ctx context.Context, isovalentBGPPeerConfig *v1alpha1.IsovalentBGPPeerConfig, opts v1.UpdateOptions) (result *v1alpha1.IsovalentBGPPeerConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(isovalentbgppeerconfigsResource, isovalentBGPPeerConfig), &v1alpha1.IsovalentBGPPeerConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentBGPPeerConfig), err
}

// Delete takes name of the isovalentBGPPeerConfig and deletes it. Returns an error if one occurs.
func (c *FakeIsovalentBGPPeerConfigs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(isovalentbgppeerconfigsResource, name, opts), &v1alpha1.IsovalentBGPPeerConfig{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeIsovalentBGPPeerConfigs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(isovalentbgppeerconfigsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.IsovalentBGPPeerConfigList{})
	return err
}

// Patch applies the patch and returns the patched isovalentBGPPeerConfig.
func (c *FakeIsovalentBGPPeerConfigs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.IsovalentBGPPeerConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(isovalentbgppeerconfigsResource, name, pt, data, subresources...), &v1alpha1.IsovalentBGPPeerConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentBGPPeerConfig), err
}
