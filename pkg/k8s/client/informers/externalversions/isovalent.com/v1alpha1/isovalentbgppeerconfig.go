// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	time "time"

	isovalentcomv1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	versioned "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	internalinterfaces "github.com/cilium/cilium/pkg/k8s/client/informers/externalversions/internalinterfaces"
	v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/listers/isovalent.com/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// IsovalentBGPPeerConfigInformer provides access to a shared informer and lister for
// IsovalentBGPPeerConfigs.
type IsovalentBGPPeerConfigInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.IsovalentBGPPeerConfigLister
}

type isovalentBGPPeerConfigInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewIsovalentBGPPeerConfigInformer constructs a new informer for IsovalentBGPPeerConfig type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewIsovalentBGPPeerConfigInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredIsovalentBGPPeerConfigInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredIsovalentBGPPeerConfigInformer constructs a new informer for IsovalentBGPPeerConfig type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredIsovalentBGPPeerConfigInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.IsovalentV1alpha1().IsovalentBGPPeerConfigs().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.IsovalentV1alpha1().IsovalentBGPPeerConfigs().Watch(context.TODO(), options)
			},
		},
		&isovalentcomv1alpha1.IsovalentBGPPeerConfig{},
		resyncPeriod,
		indexers,
	)
}

func (f *isovalentBGPPeerConfigInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredIsovalentBGPPeerConfigInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *isovalentBGPPeerConfigInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&isovalentcomv1alpha1.IsovalentBGPPeerConfig{}, f.defaultInformer)
}

func (f *isovalentBGPPeerConfigInformer) Lister() v1alpha1.IsovalentBGPPeerConfigLister {
	return v1alpha1.NewIsovalentBGPPeerConfigLister(f.Informer().GetIndexer())
}