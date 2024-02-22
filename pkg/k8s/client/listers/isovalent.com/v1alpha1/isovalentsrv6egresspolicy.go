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

// IsovalentSRv6EgressPolicyLister helps list IsovalentSRv6EgressPolicies.
// All objects returned here must be treated as read-only.
type IsovalentSRv6EgressPolicyLister interface {
	// List lists all IsovalentSRv6EgressPolicies in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.IsovalentSRv6EgressPolicy, err error)
	// Get retrieves the IsovalentSRv6EgressPolicy from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.IsovalentSRv6EgressPolicy, error)
	IsovalentSRv6EgressPolicyListerExpansion
}

// isovalentSRv6EgressPolicyLister implements the IsovalentSRv6EgressPolicyLister interface.
type isovalentSRv6EgressPolicyLister struct {
	indexer cache.Indexer
}

// NewIsovalentSRv6EgressPolicyLister returns a new IsovalentSRv6EgressPolicyLister.
func NewIsovalentSRv6EgressPolicyLister(indexer cache.Indexer) IsovalentSRv6EgressPolicyLister {
	return &isovalentSRv6EgressPolicyLister{indexer: indexer}
}

// List lists all IsovalentSRv6EgressPolicies in the indexer.
func (s *isovalentSRv6EgressPolicyLister) List(selector labels.Selector) (ret []*v1alpha1.IsovalentSRv6EgressPolicy, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.IsovalentSRv6EgressPolicy))
	})
	return ret, err
}

// Get retrieves the IsovalentSRv6EgressPolicy from the index for a given name.
func (s *isovalentSRv6EgressPolicyLister) Get(name string) (*v1alpha1.IsovalentSRv6EgressPolicy, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("isovalentsrv6egresspolicy"), name)
	}
	return obj.(*v1alpha1.IsovalentSRv6EgressPolicy), nil
}