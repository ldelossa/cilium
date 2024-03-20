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

// IsovalentMulticastNodesGetter has a method to return a IsovalentMulticastNodeInterface.
// A group's client should implement this interface.
type IsovalentMulticastNodesGetter interface {
	IsovalentMulticastNodes() IsovalentMulticastNodeInterface
}

// IsovalentMulticastNodeInterface has methods to work with IsovalentMulticastNode resources.
type IsovalentMulticastNodeInterface interface {
	Create(ctx context.Context, isovalentMulticastNode *v1alpha1.IsovalentMulticastNode, opts v1.CreateOptions) (*v1alpha1.IsovalentMulticastNode, error)
	Update(ctx context.Context, isovalentMulticastNode *v1alpha1.IsovalentMulticastNode, opts v1.UpdateOptions) (*v1alpha1.IsovalentMulticastNode, error)
	UpdateStatus(ctx context.Context, isovalentMulticastNode *v1alpha1.IsovalentMulticastNode, opts v1.UpdateOptions) (*v1alpha1.IsovalentMulticastNode, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.IsovalentMulticastNode, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.IsovalentMulticastNodeList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.IsovalentMulticastNode, err error)
	IsovalentMulticastNodeExpansion
}

// isovalentMulticastNodes implements IsovalentMulticastNodeInterface
type isovalentMulticastNodes struct {
	client rest.Interface
}

// newIsovalentMulticastNodes returns a IsovalentMulticastNodes
func newIsovalentMulticastNodes(c *IsovalentV1alpha1Client) *isovalentMulticastNodes {
	return &isovalentMulticastNodes{
		client: c.RESTClient(),
	}
}

// Get takes name of the isovalentMulticastNode, and returns the corresponding isovalentMulticastNode object, and an error if there is any.
func (c *isovalentMulticastNodes) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.IsovalentMulticastNode, err error) {
	result = &v1alpha1.IsovalentMulticastNode{}
	err = c.client.Get().
		Resource("isovalentmulticastnodes").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of IsovalentMulticastNodes that match those selectors.
func (c *isovalentMulticastNodes) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.IsovalentMulticastNodeList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.IsovalentMulticastNodeList{}
	err = c.client.Get().
		Resource("isovalentmulticastnodes").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested isovalentMulticastNodes.
func (c *isovalentMulticastNodes) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("isovalentmulticastnodes").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a isovalentMulticastNode and creates it.  Returns the server's representation of the isovalentMulticastNode, and an error, if there is any.
func (c *isovalentMulticastNodes) Create(ctx context.Context, isovalentMulticastNode *v1alpha1.IsovalentMulticastNode, opts v1.CreateOptions) (result *v1alpha1.IsovalentMulticastNode, err error) {
	result = &v1alpha1.IsovalentMulticastNode{}
	err = c.client.Post().
		Resource("isovalentmulticastnodes").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(isovalentMulticastNode).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a isovalentMulticastNode and updates it. Returns the server's representation of the isovalentMulticastNode, and an error, if there is any.
func (c *isovalentMulticastNodes) Update(ctx context.Context, isovalentMulticastNode *v1alpha1.IsovalentMulticastNode, opts v1.UpdateOptions) (result *v1alpha1.IsovalentMulticastNode, err error) {
	result = &v1alpha1.IsovalentMulticastNode{}
	err = c.client.Put().
		Resource("isovalentmulticastnodes").
		Name(isovalentMulticastNode.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(isovalentMulticastNode).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *isovalentMulticastNodes) UpdateStatus(ctx context.Context, isovalentMulticastNode *v1alpha1.IsovalentMulticastNode, opts v1.UpdateOptions) (result *v1alpha1.IsovalentMulticastNode, err error) {
	result = &v1alpha1.IsovalentMulticastNode{}
	err = c.client.Put().
		Resource("isovalentmulticastnodes").
		Name(isovalentMulticastNode.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(isovalentMulticastNode).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the isovalentMulticastNode and deletes it. Returns an error if one occurs.
func (c *isovalentMulticastNodes) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("isovalentmulticastnodes").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *isovalentMulticastNodes) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("isovalentmulticastnodes").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched isovalentMulticastNode.
func (c *isovalentMulticastNodes) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.IsovalentMulticastNode, err error) {
	result = &v1alpha1.IsovalentMulticastNode{}
	err = c.client.Patch(pt).
		Resource("isovalentmulticastnodes").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}