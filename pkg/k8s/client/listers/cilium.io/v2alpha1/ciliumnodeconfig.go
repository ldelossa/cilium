// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by lister-gen. DO NOT EDIT.

package v2alpha1

import (
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// CiliumNodeConfigLister helps list CiliumNodeConfigs.
// All objects returned here must be treated as read-only.
type CiliumNodeConfigLister interface {
	// List lists all CiliumNodeConfigs in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v2alpha1.CiliumNodeConfig, err error)
	// CiliumNodeConfigs returns an object that can list and get CiliumNodeConfigs.
	CiliumNodeConfigs(namespace string) CiliumNodeConfigNamespaceLister
	CiliumNodeConfigListerExpansion
}

// ciliumNodeConfigLister implements the CiliumNodeConfigLister interface.
type ciliumNodeConfigLister struct {
	listers.ResourceIndexer[*v2alpha1.CiliumNodeConfig]
}

// NewCiliumNodeConfigLister returns a new CiliumNodeConfigLister.
func NewCiliumNodeConfigLister(indexer cache.Indexer) CiliumNodeConfigLister {
	return &ciliumNodeConfigLister{listers.New[*v2alpha1.CiliumNodeConfig](indexer, v2alpha1.Resource("ciliumnodeconfig"))}
}

// CiliumNodeConfigs returns an object that can list and get CiliumNodeConfigs.
func (s *ciliumNodeConfigLister) CiliumNodeConfigs(namespace string) CiliumNodeConfigNamespaceLister {
	return ciliumNodeConfigNamespaceLister{listers.NewNamespaced[*v2alpha1.CiliumNodeConfig](s.ResourceIndexer, namespace)}
}

// CiliumNodeConfigNamespaceLister helps list and get CiliumNodeConfigs.
// All objects returned here must be treated as read-only.
type CiliumNodeConfigNamespaceLister interface {
	// List lists all CiliumNodeConfigs in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v2alpha1.CiliumNodeConfig, err error)
	// Get retrieves the CiliumNodeConfig from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v2alpha1.CiliumNodeConfig, error)
	CiliumNodeConfigNamespaceListerExpansion
}

// ciliumNodeConfigNamespaceLister implements the CiliumNodeConfigNamespaceLister
// interface.
type ciliumNodeConfigNamespaceLister struct {
	listers.ResourceIndexer[*v2alpha1.CiliumNodeConfig]
}
