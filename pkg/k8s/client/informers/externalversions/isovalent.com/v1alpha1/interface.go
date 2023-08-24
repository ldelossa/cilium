// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	internalinterfaces "github.com/cilium/cilium/pkg/k8s/client/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// IsovalentFQDNGroups returns a IsovalentFQDNGroupInformer.
	IsovalentFQDNGroups() IsovalentFQDNGroupInformer
	// IsovalentSRv6LocatorPools returns a IsovalentSRv6LocatorPoolInformer.
	IsovalentSRv6LocatorPools() IsovalentSRv6LocatorPoolInformer
	// IsovalentSRv6SIDManagers returns a IsovalentSRv6SIDManagerInformer.
	IsovalentSRv6SIDManagers() IsovalentSRv6SIDManagerInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// IsovalentFQDNGroups returns a IsovalentFQDNGroupInformer.
func (v *version) IsovalentFQDNGroups() IsovalentFQDNGroupInformer {
	return &isovalentFQDNGroupInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// IsovalentSRv6LocatorPools returns a IsovalentSRv6LocatorPoolInformer.
func (v *version) IsovalentSRv6LocatorPools() IsovalentSRv6LocatorPoolInformer {
	return &isovalentSRv6LocatorPoolInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// IsovalentSRv6SIDManagers returns a IsovalentSRv6SIDManagerInformer.
func (v *version) IsovalentSRv6SIDManagers() IsovalentSRv6SIDManagerInformer {
	return &isovalentSRv6SIDManagerInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}
