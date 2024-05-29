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

// FakeIsovalentBFDProfiles implements IsovalentBFDProfileInterface
type FakeIsovalentBFDProfiles struct {
	Fake *FakeIsovalentV1alpha1
}

var isovalentbfdprofilesResource = v1alpha1.SchemeGroupVersion.WithResource("isovalentbfdprofiles")

var isovalentbfdprofilesKind = v1alpha1.SchemeGroupVersion.WithKind("IsovalentBFDProfile")

// Get takes name of the isovalentBFDProfile, and returns the corresponding isovalentBFDProfile object, and an error if there is any.
func (c *FakeIsovalentBFDProfiles) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.IsovalentBFDProfile, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(isovalentbfdprofilesResource, name), &v1alpha1.IsovalentBFDProfile{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentBFDProfile), err
}

// List takes label and field selectors, and returns the list of IsovalentBFDProfiles that match those selectors.
func (c *FakeIsovalentBFDProfiles) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.IsovalentBFDProfileList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(isovalentbfdprofilesResource, isovalentbfdprofilesKind, opts), &v1alpha1.IsovalentBFDProfileList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.IsovalentBFDProfileList{ListMeta: obj.(*v1alpha1.IsovalentBFDProfileList).ListMeta}
	for _, item := range obj.(*v1alpha1.IsovalentBFDProfileList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested isovalentBFDProfiles.
func (c *FakeIsovalentBFDProfiles) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(isovalentbfdprofilesResource, opts))
}

// Create takes the representation of a isovalentBFDProfile and creates it.  Returns the server's representation of the isovalentBFDProfile, and an error, if there is any.
func (c *FakeIsovalentBFDProfiles) Create(ctx context.Context, isovalentBFDProfile *v1alpha1.IsovalentBFDProfile, opts v1.CreateOptions) (result *v1alpha1.IsovalentBFDProfile, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(isovalentbfdprofilesResource, isovalentBFDProfile), &v1alpha1.IsovalentBFDProfile{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentBFDProfile), err
}

// Update takes the representation of a isovalentBFDProfile and updates it. Returns the server's representation of the isovalentBFDProfile, and an error, if there is any.
func (c *FakeIsovalentBFDProfiles) Update(ctx context.Context, isovalentBFDProfile *v1alpha1.IsovalentBFDProfile, opts v1.UpdateOptions) (result *v1alpha1.IsovalentBFDProfile, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(isovalentbfdprofilesResource, isovalentBFDProfile), &v1alpha1.IsovalentBFDProfile{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentBFDProfile), err
}

// Delete takes name of the isovalentBFDProfile and deletes it. Returns an error if one occurs.
func (c *FakeIsovalentBFDProfiles) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(isovalentbfdprofilesResource, name, opts), &v1alpha1.IsovalentBFDProfile{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeIsovalentBFDProfiles) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(isovalentbfdprofilesResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.IsovalentBFDProfileList{})
	return err
}

// Patch applies the patch and returns the patched isovalentBFDProfile.
func (c *FakeIsovalentBFDProfiles) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.IsovalentBFDProfile, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(isovalentbfdprofilesResource, name, pt, data, subresources...), &v1alpha1.IsovalentBFDProfile{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.IsovalentBFDProfile), err
}