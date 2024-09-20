// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// IsovalentFQDNGroupLister helps list IsovalentFQDNGroups.
// All objects returned here must be treated as read-only.
type IsovalentFQDNGroupLister interface {
	// List lists all IsovalentFQDNGroups in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.IsovalentFQDNGroup, err error)
	// Get retrieves the IsovalentFQDNGroup from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.IsovalentFQDNGroup, error)
	IsovalentFQDNGroupListerExpansion
}

// isovalentFQDNGroupLister implements the IsovalentFQDNGroupLister interface.
type isovalentFQDNGroupLister struct {
	listers.ResourceIndexer[*v1alpha1.IsovalentFQDNGroup]
}

// NewIsovalentFQDNGroupLister returns a new IsovalentFQDNGroupLister.
func NewIsovalentFQDNGroupLister(indexer cache.Indexer) IsovalentFQDNGroupLister {
	return &isovalentFQDNGroupLister{listers.New[*v1alpha1.IsovalentFQDNGroup](indexer, v1alpha1.Resource("isovalentfqdngroup"))}
}
