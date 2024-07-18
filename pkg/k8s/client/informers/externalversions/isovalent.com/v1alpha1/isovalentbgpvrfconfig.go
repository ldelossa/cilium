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

// IsovalentBGPVRFConfigInformer provides access to a shared informer and lister for
// IsovalentBGPVRFConfigs.
type IsovalentBGPVRFConfigInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.IsovalentBGPVRFConfigLister
}

type isovalentBGPVRFConfigInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewIsovalentBGPVRFConfigInformer constructs a new informer for IsovalentBGPVRFConfig type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewIsovalentBGPVRFConfigInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredIsovalentBGPVRFConfigInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredIsovalentBGPVRFConfigInformer constructs a new informer for IsovalentBGPVRFConfig type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredIsovalentBGPVRFConfigInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.IsovalentV1alpha1().IsovalentBGPVRFConfigs().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.IsovalentV1alpha1().IsovalentBGPVRFConfigs().Watch(context.TODO(), options)
			},
		},
		&isovalentcomv1alpha1.IsovalentBGPVRFConfig{},
		resyncPeriod,
		indexers,
	)
}

func (f *isovalentBGPVRFConfigInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredIsovalentBGPVRFConfigInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *isovalentBGPVRFConfigInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&isovalentcomv1alpha1.IsovalentBGPVRFConfig{}, f.defaultInformer)
}

func (f *isovalentBGPVRFConfigInformer) Lister() v1alpha1.IsovalentBGPVRFConfigLister {
	return v1alpha1.NewIsovalentBGPVRFConfigLister(f.Informer().GetIndexer())
}
