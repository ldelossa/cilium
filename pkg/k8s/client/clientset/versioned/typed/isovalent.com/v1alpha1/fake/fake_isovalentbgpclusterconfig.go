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

// FakeIsovalentBGPClusterConfigs implements IsovalentBGPClusterConfigInterface
type FakeIsovalentBGPClusterConfigs struct {
	Fake *FakeIsovalentV1alpha1
}

var isovalentbgpclusterconfigsResource = v1alpha1.SchemeGroupVersion.WithResource("isovalentbgpclusterconfigs")

var isovalentbgpclusterconfigsKind = v1alpha1.SchemeGroupVersion.WithKind("IsovalentBGPClusterConfig")

// Get takes name of the isovalentBGPClusterConfig, and returns the corresponding isovalentBGPClusterConfig object, and an error if there is any.
func (c *FakeIsovalentBGPClusterConfigs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.IsovalentBGPClusterConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(isovalentbgpclusterconfigsResource, name), &v1alpha1.IsovalentBGPClusterConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentBGPClusterConfig), err
}

// List takes label and field selectors, and returns the list of IsovalentBGPClusterConfigs that match those selectors.
func (c *FakeIsovalentBGPClusterConfigs) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.IsovalentBGPClusterConfigList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(isovalentbgpclusterconfigsResource, isovalentbgpclusterconfigsKind, opts), &v1alpha1.IsovalentBGPClusterConfigList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.IsovalentBGPClusterConfigList{ListMeta: obj.(*v1alpha1.IsovalentBGPClusterConfigList).ListMeta}
	for _, item := range obj.(*v1alpha1.IsovalentBGPClusterConfigList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested isovalentBGPClusterConfigs.
func (c *FakeIsovalentBGPClusterConfigs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(isovalentbgpclusterconfigsResource, opts))
}

// Create takes the representation of a isovalentBGPClusterConfig and creates it.  Returns the server's representation of the isovalentBGPClusterConfig, and an error, if there is any.
func (c *FakeIsovalentBGPClusterConfigs) Create(ctx context.Context, isovalentBGPClusterConfig *v1alpha1.IsovalentBGPClusterConfig, opts v1.CreateOptions) (result *v1alpha1.IsovalentBGPClusterConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(isovalentbgpclusterconfigsResource, isovalentBGPClusterConfig), &v1alpha1.IsovalentBGPClusterConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentBGPClusterConfig), err
}

// Update takes the representation of a isovalentBGPClusterConfig and updates it. Returns the server's representation of the isovalentBGPClusterConfig, and an error, if there is any.
func (c *FakeIsovalentBGPClusterConfigs) Update(ctx context.Context, isovalentBGPClusterConfig *v1alpha1.IsovalentBGPClusterConfig, opts v1.UpdateOptions) (result *v1alpha1.IsovalentBGPClusterConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(isovalentbgpclusterconfigsResource, isovalentBGPClusterConfig), &v1alpha1.IsovalentBGPClusterConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentBGPClusterConfig), err
}

// Delete takes name of the isovalentBGPClusterConfig and deletes it. Returns an error if one occurs.
func (c *FakeIsovalentBGPClusterConfigs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(isovalentbgpclusterconfigsResource, name, opts), &v1alpha1.IsovalentBGPClusterConfig{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeIsovalentBGPClusterConfigs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(isovalentbgpclusterconfigsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.IsovalentBGPClusterConfigList{})
	return err
}

// Patch applies the patch and returns the patched isovalentBGPClusterConfig.
func (c *FakeIsovalentBGPClusterConfigs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.IsovalentBGPClusterConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(isovalentbgpclusterconfigsResource, name, pt, data, subresources...), &v1alpha1.IsovalentBGPClusterConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentBGPClusterConfig), err
}
