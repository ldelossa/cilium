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

// IsovalentMeshEndpointInformer provides access to a shared informer and lister for
// IsovalentMeshEndpoints.
type IsovalentMeshEndpointInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.IsovalentMeshEndpointLister
}

type isovalentMeshEndpointInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewIsovalentMeshEndpointInformer constructs a new informer for IsovalentMeshEndpoint type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewIsovalentMeshEndpointInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredIsovalentMeshEndpointInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredIsovalentMeshEndpointInformer constructs a new informer for IsovalentMeshEndpoint type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredIsovalentMeshEndpointInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.IsovalentV1alpha1().IsovalentMeshEndpoints(namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.IsovalentV1alpha1().IsovalentMeshEndpoints(namespace).Watch(context.TODO(), options)
			},
		},
		&isovalentcomv1alpha1.IsovalentMeshEndpoint{},
		resyncPeriod,
		indexers,
	)
}

func (f *isovalentMeshEndpointInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredIsovalentMeshEndpointInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *isovalentMeshEndpointInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&isovalentcomv1alpha1.IsovalentMeshEndpoint{}, f.defaultInformer)
}

func (f *isovalentMeshEndpointInformer) Lister() v1alpha1.IsovalentMeshEndpointLister {
	return v1alpha1.NewIsovalentMeshEndpointLister(f.Informer().GetIndexer())
}
