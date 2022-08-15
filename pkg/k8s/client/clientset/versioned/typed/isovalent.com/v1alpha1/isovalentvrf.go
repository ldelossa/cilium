// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	scheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// IsovalentVRFsGetter has a method to return a IsovalentVRFInterface.
// A group's client should implement this interface.
type IsovalentVRFsGetter interface {
	IsovalentVRFs() IsovalentVRFInterface
}

// IsovalentVRFInterface has methods to work with IsovalentVRF resources.
type IsovalentVRFInterface interface {
	Create(ctx context.Context, isovalentVRF *v1alpha1.IsovalentVRF, opts v1.CreateOptions) (*v1alpha1.IsovalentVRF, error)
	Update(ctx context.Context, isovalentVRF *v1alpha1.IsovalentVRF, opts v1.UpdateOptions) (*v1alpha1.IsovalentVRF, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.IsovalentVRF, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.IsovalentVRFList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.IsovalentVRF, err error)
	IsovalentVRFExpansion
}

// isovalentVRFs implements IsovalentVRFInterface
type isovalentVRFs struct {
	client rest.Interface
}

// newIsovalentVRFs returns a IsovalentVRFs
func newIsovalentVRFs(c *IsovalentV1alpha1Client) *isovalentVRFs {
	return &isovalentVRFs{
		client: c.RESTClient(),
	}
}

// Get takes name of the isovalentVRF, and returns the corresponding isovalentVRF object, and an error if there is any.
func (c *isovalentVRFs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.IsovalentVRF, err error) {
	result = &v1alpha1.IsovalentVRF{}
	err = c.client.Get().
		Resource("isovalentvrfs").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of IsovalentVRFs that match those selectors.
func (c *isovalentVRFs) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.IsovalentVRFList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.IsovalentVRFList{}
	err = c.client.Get().
		Resource("isovalentvrfs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested isovalentVRFs.
func (c *isovalentVRFs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("isovalentvrfs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a isovalentVRF and creates it.  Returns the server's representation of the isovalentVRF, and an error, if there is any.
func (c *isovalentVRFs) Create(ctx context.Context, isovalentVRF *v1alpha1.IsovalentVRF, opts v1.CreateOptions) (result *v1alpha1.IsovalentVRF, err error) {
	result = &v1alpha1.IsovalentVRF{}
	err = c.client.Post().
		Resource("isovalentvrfs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(isovalentVRF).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a isovalentVRF and updates it. Returns the server's representation of the isovalentVRF, and an error, if there is any.
func (c *isovalentVRFs) Update(ctx context.Context, isovalentVRF *v1alpha1.IsovalentVRF, opts v1.UpdateOptions) (result *v1alpha1.IsovalentVRF, err error) {
	result = &v1alpha1.IsovalentVRF{}
	err = c.client.Put().
		Resource("isovalentvrfs").
		Name(isovalentVRF.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(isovalentVRF).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the isovalentVRF and deletes it. Returns an error if one occurs.
func (c *isovalentVRFs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("isovalentvrfs").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *isovalentVRFs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("isovalentvrfs").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched isovalentVRF.
func (c *isovalentVRFs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.IsovalentVRF, err error) {
	result = &v1alpha1.IsovalentVRF{}
	err = c.client.Patch(pt).
		Resource("isovalentvrfs").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
