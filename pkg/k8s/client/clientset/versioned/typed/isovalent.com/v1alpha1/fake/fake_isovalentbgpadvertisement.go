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

// FakeIsovalentBGPAdvertisements implements IsovalentBGPAdvertisementInterface
type FakeIsovalentBGPAdvertisements struct {
	Fake *FakeIsovalentV1alpha1
}

var isovalentbgpadvertisementsResource = v1alpha1.SchemeGroupVersion.WithResource("isovalentbgpadvertisements")

var isovalentbgpadvertisementsKind = v1alpha1.SchemeGroupVersion.WithKind("IsovalentBGPAdvertisement")

// Get takes name of the isovalentBGPAdvertisement, and returns the corresponding isovalentBGPAdvertisement object, and an error if there is any.
func (c *FakeIsovalentBGPAdvertisements) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.IsovalentBGPAdvertisement, err error) {
	emptyResult := &v1alpha1.IsovalentBGPAdvertisement{}
	obj, err := c.Fake.
		Invokes(testing.NewRootGetActionWithOptions(isovalentbgpadvertisementsResource, name, options), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.IsovalentBGPAdvertisement), err
}

// List takes label and field selectors, and returns the list of IsovalentBGPAdvertisements that match those selectors.
func (c *FakeIsovalentBGPAdvertisements) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.IsovalentBGPAdvertisementList, err error) {
	emptyResult := &v1alpha1.IsovalentBGPAdvertisementList{}
	obj, err := c.Fake.
		Invokes(testing.NewRootListActionWithOptions(isovalentbgpadvertisementsResource, isovalentbgpadvertisementsKind, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.IsovalentBGPAdvertisementList{ListMeta: obj.(*v1alpha1.IsovalentBGPAdvertisementList).ListMeta}
	for _, item := range obj.(*v1alpha1.IsovalentBGPAdvertisementList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested isovalentBGPAdvertisements.
func (c *FakeIsovalentBGPAdvertisements) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchActionWithOptions(isovalentbgpadvertisementsResource, opts))
}

// Create takes the representation of a isovalentBGPAdvertisement and creates it.  Returns the server's representation of the isovalentBGPAdvertisement, and an error, if there is any.
func (c *FakeIsovalentBGPAdvertisements) Create(ctx context.Context, isovalentBGPAdvertisement *v1alpha1.IsovalentBGPAdvertisement, opts v1.CreateOptions) (result *v1alpha1.IsovalentBGPAdvertisement, err error) {
	emptyResult := &v1alpha1.IsovalentBGPAdvertisement{}
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateActionWithOptions(isovalentbgpadvertisementsResource, isovalentBGPAdvertisement, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.IsovalentBGPAdvertisement), err
}

// Update takes the representation of a isovalentBGPAdvertisement and updates it. Returns the server's representation of the isovalentBGPAdvertisement, and an error, if there is any.
func (c *FakeIsovalentBGPAdvertisements) Update(ctx context.Context, isovalentBGPAdvertisement *v1alpha1.IsovalentBGPAdvertisement, opts v1.UpdateOptions) (result *v1alpha1.IsovalentBGPAdvertisement, err error) {
	emptyResult := &v1alpha1.IsovalentBGPAdvertisement{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateActionWithOptions(isovalentbgpadvertisementsResource, isovalentBGPAdvertisement, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.IsovalentBGPAdvertisement), err
}

// Delete takes name of the isovalentBGPAdvertisement and deletes it. Returns an error if one occurs.
func (c *FakeIsovalentBGPAdvertisements) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(isovalentbgpadvertisementsResource, name, opts), &v1alpha1.IsovalentBGPAdvertisement{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeIsovalentBGPAdvertisements) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionActionWithOptions(isovalentbgpadvertisementsResource, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.IsovalentBGPAdvertisementList{})
	return err
}

// Patch applies the patch and returns the patched isovalentBGPAdvertisement.
func (c *FakeIsovalentBGPAdvertisements) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.IsovalentBGPAdvertisement, err error) {
	emptyResult := &v1alpha1.IsovalentBGPAdvertisement{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(isovalentbgpadvertisementsResource, name, pt, data, opts, subresources...), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v1alpha1.IsovalentBGPAdvertisement), err
}
