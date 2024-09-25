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

// IsovalentPodNetworkLister helps list IsovalentPodNetworks.
// All objects returned here must be treated as read-only.
type IsovalentPodNetworkLister interface {
	// List lists all IsovalentPodNetworks in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.IsovalentPodNetwork, err error)
	// Get retrieves the IsovalentPodNetwork from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.IsovalentPodNetwork, error)
	IsovalentPodNetworkListerExpansion
}

// isovalentPodNetworkLister implements the IsovalentPodNetworkLister interface.
type isovalentPodNetworkLister struct {
	listers.ResourceIndexer[*v1alpha1.IsovalentPodNetwork]
}

// NewIsovalentPodNetworkLister returns a new IsovalentPodNetworkLister.
func NewIsovalentPodNetworkLister(indexer cache.Indexer) IsovalentPodNetworkLister {
	return &isovalentPodNetworkLister{listers.New[*v1alpha1.IsovalentPodNetwork](indexer, v1alpha1.Resource("isovalentpodnetwork"))}
}
