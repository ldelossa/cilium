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
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(isovalentbgpadvertisementsResource, name), &v1alpha1.IsovalentBGPAdvertisement{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentBGPAdvertisement), err
}

// List takes label and field selectors, and returns the list of IsovalentBGPAdvertisements that match those selectors.
func (c *FakeIsovalentBGPAdvertisements) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.IsovalentBGPAdvertisementList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(isovalentbgpadvertisementsResource, isovalentbgpadvertisementsKind, opts), &v1alpha1.IsovalentBGPAdvertisementList{})
	if obj == nil {
		return nil, err
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
		InvokesWatch(testing.NewRootWatchAction(isovalentbgpadvertisementsResource, opts))
}

// Create takes the representation of a isovalentBGPAdvertisement and creates it.  Returns the server's representation of the isovalentBGPAdvertisement, and an error, if there is any.
func (c *FakeIsovalentBGPAdvertisements) Create(ctx context.Context, isovalentBGPAdvertisement *v1alpha1.IsovalentBGPAdvertisement, opts v1.CreateOptions) (result *v1alpha1.IsovalentBGPAdvertisement, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(isovalentbgpadvertisementsResource, isovalentBGPAdvertisement), &v1alpha1.IsovalentBGPAdvertisement{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentBGPAdvertisement), err
}

// Update takes the representation of a isovalentBGPAdvertisement and updates it. Returns the server's representation of the isovalentBGPAdvertisement, and an error, if there is any.
func (c *FakeIsovalentBGPAdvertisements) Update(ctx context.Context, isovalentBGPAdvertisement *v1alpha1.IsovalentBGPAdvertisement, opts v1.UpdateOptions) (result *v1alpha1.IsovalentBGPAdvertisement, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(isovalentbgpadvertisementsResource, isovalentBGPAdvertisement), &v1alpha1.IsovalentBGPAdvertisement{})
	if obj == nil {
		return nil, err
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
	action := testing.NewRootDeleteCollectionAction(isovalentbgpadvertisementsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.IsovalentBGPAdvertisementList{})
	return err
}

// Patch applies the patch and returns the patched isovalentBGPAdvertisement.
func (c *FakeIsovalentBGPAdvertisements) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.IsovalentBGPAdvertisement, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(isovalentbgpadvertisementsResource, name, pt, data, subresources...), &v1alpha1.IsovalentBGPAdvertisement{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentBGPAdvertisement), err
}
