// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/srv6"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) ciliumSRv6VRFInit(ciliumClient *k8s.K8sCiliumClient) {
	_, egpController := informer.NewInformer(
		cache.NewListWatchFromClient(ciliumClient.CiliumV2alpha1().RESTClient(),
			"ciliumsrv6vrfs", v1.NamespaceAll, fields.Everything()),
		&cilium_v2alpha1.CiliumSRv6VRF{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCSRVRF, metricCreate, valid, equal) }()
				if csrvrf := k8s.ObjToCSRVRF(obj); csrvrf != nil {
					valid = true
					err := k.addCiliumSRv6VRF(csrvrf)
					k.K8sEventProcessed(metricCSRVRF, metricCreate, err == nil)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCSRVRF, metricUpdate, valid, equal) }()

				newCsrvrf := k8s.ObjToCSRVRF(newObj)
				if newCsrvrf == nil {
					return
				}
				valid = true
				addErr := k.addCiliumSRv6VRF(newCsrvrf)
				k.K8sEventProcessed(metricCSRVRF, metricUpdate, addErr == nil)
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCSRVRF, metricDelete, valid, equal) }()
				csrvrf := k8s.ObjToCSRVRF(obj)
				if csrvrf == nil {
					return
				}
				valid = true
				k.deleteCiliumSRv6VRF(csrvrf)
				k.K8sEventProcessed(metricCSRVRF, metricDelete, true)
			},
		},
		k8s.ConvertToCiliumSRv6VRF,
	)

	k.blockWaitGroupToSyncResources(
		wait.NeverStop,
		nil,
		egpController.HasSynced,
		k8sAPIGroupCiliumSRv6VRFV2,
	)

	go egpController.Run(wait.NeverStop)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumSRv6VRFV2)
}

func (k *K8sWatcher) addCiliumSRv6VRF(csrvrf *cilium_v2alpha1.CiliumSRv6VRF) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumSRv6VRFName: csrvrf.ObjectMeta.Name,
		logfields.K8sUID:            csrvrf.ObjectMeta.UID,
		logfields.K8sAPIVersion:     csrvrf.TypeMeta.APIVersion,
	})

	cp, err := srv6.ParseVRF(csrvrf)
	if err != nil {
		scopedLog.WithError(err).Warn("Malformed CiliumSRv6VRF.")
		return err
	}
	k.srv6Manager.OnAddSRv6VRF(*cp)
	return nil
}

func (k *K8sWatcher) deleteCiliumSRv6VRF(csrvrf *cilium_v2alpha1.CiliumSRv6VRF) {
	cpID := srv6.ParseVRFID(csrvrf)
	k.srv6Manager.OnDeleteSRv6VRF(cpID)
}
