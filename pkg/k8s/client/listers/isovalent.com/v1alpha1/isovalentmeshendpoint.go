// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// IsovalentMeshEndpointLister helps list IsovalentMeshEndpoints.
// All objects returned here must be treated as read-only.
type IsovalentMeshEndpointLister interface {
	// List lists all IsovalentMeshEndpoints in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.IsovalentMeshEndpoint, err error)
	// IsovalentMeshEndpoints returns an object that can list and get IsovalentMeshEndpoints.
	IsovalentMeshEndpoints(namespace string) IsovalentMeshEndpointNamespaceLister
	IsovalentMeshEndpointListerExpansion
}

// isovalentMeshEndpointLister implements the IsovalentMeshEndpointLister interface.
type isovalentMeshEndpointLister struct {
	indexer cache.Indexer
}

// NewIsovalentMeshEndpointLister returns a new IsovalentMeshEndpointLister.
func NewIsovalentMeshEndpointLister(indexer cache.Indexer) IsovalentMeshEndpointLister {
	return &isovalentMeshEndpointLister{indexer: indexer}
}

// List lists all IsovalentMeshEndpoints in the indexer.
func (s *isovalentMeshEndpointLister) List(selector labels.Selector) (ret []*v1alpha1.IsovalentMeshEndpoint, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.IsovalentMeshEndpoint))
	})
	return ret, err
}

// IsovalentMeshEndpoints returns an object that can list and get IsovalentMeshEndpoints.
func (s *isovalentMeshEndpointLister) IsovalentMeshEndpoints(namespace string) IsovalentMeshEndpointNamespaceLister {
	return isovalentMeshEndpointNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// IsovalentMeshEndpointNamespaceLister helps list and get IsovalentMeshEndpoints.
// All objects returned here must be treated as read-only.
type IsovalentMeshEndpointNamespaceLister interface {
	// List lists all IsovalentMeshEndpoints in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.IsovalentMeshEndpoint, err error)
	// Get retrieves the IsovalentMeshEndpoint from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.IsovalentMeshEndpoint, error)
	IsovalentMeshEndpointNamespaceListerExpansion
}

// isovalentMeshEndpointNamespaceLister implements the IsovalentMeshEndpointNamespaceLister
// interface.
type isovalentMeshEndpointNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all IsovalentMeshEndpoints in the indexer for a given namespace.
func (s isovalentMeshEndpointNamespaceLister) List(selector labels.Selector) (ret []*v1alpha1.IsovalentMeshEndpoint, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.IsovalentMeshEndpoint))
	})
	return ret, err
}

// Get retrieves the IsovalentMeshEndpoint from the indexer for a given namespace and name.
func (s isovalentMeshEndpointNamespaceLister) Get(name string) (*v1alpha1.IsovalentMeshEndpoint, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("isovalentmeshendpoint"), name)
	}
	return obj.(*v1alpha1.IsovalentMeshEndpoint), nil
}