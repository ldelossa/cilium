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

// FakeIsovalentMulticastGroups implements IsovalentMulticastGroupInterface
type FakeIsovalentMulticastGroups struct {
	Fake *FakeIsovalentV1alpha1
}

var isovalentmulticastgroupsResource = v1alpha1.SchemeGroupVersion.WithResource("isovalentmulticastgroups")

var isovalentmulticastgroupsKind = v1alpha1.SchemeGroupVersion.WithKind("IsovalentMulticastGroup")

// Get takes name of the isovalentMulticastGroup, and returns the corresponding isovalentMulticastGroup object, and an error if there is any.
func (c *FakeIsovalentMulticastGroups) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.IsovalentMulticastGroup, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(isovalentmulticastgroupsResource, name), &v1alpha1.IsovalentMulticastGroup{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentMulticastGroup), err
}

// List takes label and field selectors, and returns the list of IsovalentMulticastGroups that match those selectors.
func (c *FakeIsovalentMulticastGroups) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.IsovalentMulticastGroupList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(isovalentmulticastgroupsResource, isovalentmulticastgroupsKind, opts), &v1alpha1.IsovalentMulticastGroupList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.IsovalentMulticastGroupList{ListMeta: obj.(*v1alpha1.IsovalentMulticastGroupList).ListMeta}
	for _, item := range obj.(*v1alpha1.IsovalentMulticastGroupList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested isovalentMulticastGroups.
func (c *FakeIsovalentMulticastGroups) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(isovalentmulticastgroupsResource, opts))
}

// Create takes the representation of a isovalentMulticastGroup and creates it.  Returns the server's representation of the isovalentMulticastGroup, and an error, if there is any.
func (c *FakeIsovalentMulticastGroups) Create(ctx context.Context, isovalentMulticastGroup *v1alpha1.IsovalentMulticastGroup, opts v1.CreateOptions) (result *v1alpha1.IsovalentMulticastGroup, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(isovalentmulticastgroupsResource, isovalentMulticastGroup), &v1alpha1.IsovalentMulticastGroup{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentMulticastGroup), err
}

// Update takes the representation of a isovalentMulticastGroup and updates it. Returns the server's representation of the isovalentMulticastGroup, and an error, if there is any.
func (c *FakeIsovalentMulticastGroups) Update(ctx context.Context, isovalentMulticastGroup *v1alpha1.IsovalentMulticastGroup, opts v1.UpdateOptions) (result *v1alpha1.IsovalentMulticastGroup, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(isovalentmulticastgroupsResource, isovalentMulticastGroup), &v1alpha1.IsovalentMulticastGroup{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentMulticastGroup), err
}

// Delete takes name of the isovalentMulticastGroup and deletes it. Returns an error if one occurs.
func (c *FakeIsovalentMulticastGroups) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(isovalentmulticastgroupsResource, name, opts), &v1alpha1.IsovalentMulticastGroup{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeIsovalentMulticastGroups) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(isovalentmulticastgroupsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.IsovalentMulticastGroupList{})
	return err
}

// Patch applies the patch and returns the patched isovalentMulticastGroup.
func (c *FakeIsovalentMulticastGroups) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.IsovalentMulticastGroup, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(isovalentmulticastgroupsResource, name, pt, data, subresources...), &v1alpha1.IsovalentMulticastGroup{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentMulticastGroup), err
}