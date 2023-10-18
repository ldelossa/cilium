// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliummesh

import (
	"context"
	"fmt"
	"os"
	"time"

	endpointslicecontroller "github.com/cilium/endpointslice-controller/endpointslice"
	core_v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	v1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/client/informers/externalversions"
	informers_v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/informers/externalversions/isovalent.com/v1alpha1"
	lister_v1alpha1 "github.com/cilium/cilium/pkg/k8s/client/listers/isovalent.com/v1alpha1"
)

const (
	controllerName              = "endpointslice-controller.cilium-mesh.isovalent.com"
	ciliumMeshServiceAnnotation = "com.isovalent/cilium-mesh"
)

func StartCiliumMeshEndpointSliceCreator(ctx context.Context, clientset client.Clientset) {
	// Start shared informers so that we can use the external library.
	sif := informers.NewSharedInformerFactory(clientset, 0)
	extSif := externalversions.NewSharedInformerFactory(clientset, 0)

	// cepInformer is will implement all methods from the PodInformer interface.
	// Since the external libraries use Pods as the structure to use in endpoint
	// slices we will be faking them from IsovalentMeshEndpoints.
	cepInformer := &cepInformer{
		cepLister:   extSif.Isovalent().V1alpha1().IsovalentMeshEndpoints().Lister(),
		cepInformer: extSif.Isovalent().V1alpha1().IsovalentMeshEndpoints(),
	}

	c := endpointslicecontroller.NewControllerWithName(
		ctx,
		cepInformer,
		sif.Core().V1().Services(),
		sif.Core().V1().Nodes(),
		sif.Discovery().V1().EndpointSlices(),
		100,
		clientset,
		time.Second,
		controllerName,
		// Function to check if a service should be synchronized to an
		// endpoint slice.
		// This is just an additional check performed on top of the existing
		// conditions used to synchronize a service in EndpointSlices.
		func(svc *core_v1.Service) bool {
			if svc == nil {
				return false
			}
			if v, ok := svc.GetAnnotations()[ciliumMeshServiceAnnotation]; !ok || v != "true" {
				return false
			}
			return true
		},
	)
	go sif.Start(wait.NeverStop)
	go extSif.Start(wait.NeverStop)
	c.Run(ctx, 2)
}

func convertCEPToPod(obj *v1alpha1.IsovalentMeshEndpoint) *core_v1.Pod {
	var podIPs []core_v1.PodIP
	if obj.Spec.IP != "" {
		podIPs = append(podIPs, core_v1.PodIP{IP: obj.Spec.IP})
	}

	return &core_v1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       v1alpha1.IsovalentMeshEndpointKindDefinition,
			APIVersion: fmt.Sprintf("%s/%s", v1alpha1.CustomResourceDefinitionGroup, v1alpha1.CustomResourceDefinitionVersion),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              obj.GetName(),
			Namespace:         obj.GetNamespace(),
			ResourceVersion:   obj.GetResourceVersion(),
			DeletionTimestamp: obj.GetDeletionTimestamp(),
			Labels:            obj.GetLabels(),
			UID:               obj.GetUID(),
		},
		Spec: core_v1.PodSpec{
			// All the CiliumMesh endpoints will be associated with the
			// node where the TransitGateway is running
			NodeName: os.Getenv("K8S_NODE_NAME"),
		},
		Status: core_v1.PodStatus{
			Conditions: []core_v1.PodCondition{
				{
					Type:   core_v1.PodReady,
					Status: core_v1.ConditionTrue,
				},
			},
			Phase:  core_v1.PodRunning,
			PodIPs: podIPs,
		},
	}
}

func convertObjToPod(obj interface{}) interface{} {
	switch o := obj.(type) {
	case *v1alpha1.IsovalentMeshEndpoint:
		return convertCEPToPod(o)
	case cache.DeletedFinalStateUnknown:
		return cache.DeletedFinalStateUnknown{
			Key: o.Key,
			Obj: convertCEPToPod(o.Obj.(*v1alpha1.IsovalentMeshEndpoint)),
		}
	default:
		panic(fmt.Sprintf("object is not a %T nor a cache.DeletedFinalStateUnknown",
			&v1alpha1.IsovalentMeshEndpoint{}))
	}
}

type cepNamespaceLister struct {
	cenl lister_v1alpha1.IsovalentMeshEndpointNamespaceLister
}

func (c *cepNamespaceLister) List(selector labels.Selector) ([]*core_v1.Pod, error) {
	ceps, err := c.cenl.List(selector)
	if err != nil {
		return nil, err
	}
	pods := make([]*core_v1.Pod, 0, len(ceps))
	for _, cep := range ceps {
		pod := convertCEPToPod(cep)
		pods = append(pods, pod)
	}
	return pods, err
}

func (c cepNamespaceLister) Get(string) (*core_v1.Pod, error) {
	// No need to implement this method since it's not used.
	// If it is ever used then we should panic.
	panic("implement me")
}

type cepInformer struct {
	cepLister   lister_v1alpha1.IsovalentMeshEndpointLister
	cepInformer informers_v1alpha1.IsovalentMeshEndpointInformer
}

func (m *cepInformer) Pods(namespace string) v1listers.PodNamespaceLister {
	return &cepNamespaceLister{
		cenl: m.cepLister.IsovalentMeshEndpoints(namespace),
	}
}

func (m *cepInformer) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	return m.cepInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := convertObjToPod(obj)
			handler.OnAdd(pod, false)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldPod := convertObjToPod(oldObj)
			newPod := convertObjToPod(newObj)
			handler.OnUpdate(oldPod, newPod)
		},
		DeleteFunc: func(obj interface{}) {
			pod := convertObjToPod(obj)
			handler.OnDelete(pod)
		},
	})
}

func (m *cepInformer) HasSynced() bool {
	return m.cepInformer.Informer().HasSynced()
}

func (m *cepInformer) Informer() cache.SharedIndexInformer {
	return m
}

func (m *cepInformer) Lister() v1listers.PodLister {
	return m
}

func (m *cepInformer) List(labels.Selector) ([]*core_v1.Pod, error) {
	// No need to implement this method since it's not used.
	// If it is ever used then we should panic.
	panic("implement me")
}

func (m *cepInformer) AddEventHandlerWithResyncPeriod(cache.ResourceEventHandler, time.Duration) (cache.ResourceEventHandlerRegistration, error) {
	// No need to implement this method since it's not used.
	// If it is ever used then we should panic.
	panic("implement me")
}

func (m *cepInformer) RemoveEventHandler(cache.ResourceEventHandlerRegistration) error {
	// No need to implement this method since it's not used.
	// If it is ever used then we should panic.
	panic("implement me")
}

func (m *cepInformer) GetStore() cache.Store {
	// No need to implement this method since it's not used.
	// If it is ever used then we should panic.
	panic("implement me")
}

func (m *cepInformer) GetController() cache.Controller {
	// No need to implement this method since it's not used.
	// If it is ever used then we should panic.
	panic("implement me")
}

func (m *cepInformer) Run(<-chan struct{}) {
	// No need to implement this method since it's not used.
	// If it is ever used then we should panic.
	panic("implement me")
}

func (m *cepInformer) LastSyncResourceVersion() string {
	// No need to implement this method since it's not used.
	// If it is ever used then we should panic.
	panic("implement me")
}

func (m *cepInformer) SetWatchErrorHandler(cache.WatchErrorHandler) error {
	// No need to implement this method since it's not used.
	// If it is ever used then we should panic.
	panic("implement me")
}

func (m *cepInformer) SetTransform(cache.TransformFunc) error {
	// No need to implement this method since it's not used.
	// If it is ever used then we should panic.
	panic("implement me")
}

func (m *cepInformer) IsStopped() bool {
	// No need to implement this method since it's not used.
	// If it is ever used then we should panic.
	panic("implement me")
}

func (m *cepInformer) AddIndexers(cache.Indexers) error {
	// No need to implement this method since it's not used.
	// If it is ever used then we should panic.
	panic("implement me")
}

func (m *cepInformer) GetIndexer() cache.Indexer {
	// No need to implement this method since it's not used.
	// If it is ever used then we should panic.
	panic("implement me")
}
