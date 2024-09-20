//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ciliummesh

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/enterprise/pkg/maps/ciliummeshpolicymap"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

type EndpointCreator interface {
	CreateEndpoint(ctx context.Context, epTemplate *models.EndpointChangeRequest) (*endpoint.Endpoint, error)
}

type CiliumMeshController struct {
	// clusterName is the name of the cluster where the Cilium Mesh is running.
	clusterName string

	// logger is the internal logger of this Controller
	logger logrus.FieldLogger

	// resource is a Resource[T] IsovalentMeshEndpoint (IME).
	resource IsovalentMeshEndpointResource

	// meshEndpoints contains a list of IME that we have received. We need this
	// map so that we know which endpoints we have received because we don't
	// yet support endpoint updates. TODO: Implement
	meshEndpoints map[string]struct{}

	// endpointsCreator will be used to create IME into the local daemon.
	endpointsCreator EndpointCreator

	// endpointsModify will be used to delete IME from the local daemon.
	endpointsModify endpointmanager.EndpointsModify

	// endpointsLookup will be used to lookup IME from the local daemon.
	endpointsLookup endpointmanager.EndpointsLookup

	ciliumMeshPolicyMap ciliummeshpolicymap.CiliumMeshPolicyWriter
}

type ciliumMeshParams struct {
	cell.In

	Logger   logrus.FieldLogger
	JobGroup job.Group

	DaemonCfg *option.DaemonConfig

	Config Config

	EndpointsModify endpointmanager.EndpointsModify

	EndpointsLookup endpointmanager.EndpointsLookup

	EndpointCreator promise.Promise[EndpointCreator]

	CiliumMeshPolicyWriter ciliummeshpolicymap.CiliumMeshPolicyWriter

	Resource IsovalentMeshEndpointResource
}

// newCiliumMeshController creates a new cilium mesh manager and returns it.
func newCiliumMeshController(p ciliumMeshParams) *CiliumMeshController {
	if !p.Config.EnableCiliumMesh {
		return nil
	}

	cmm := &CiliumMeshController{
		clusterName:         p.DaemonCfg.ClusterName,
		resource:            p.Resource,
		logger:              p.Logger,
		meshEndpoints:       make(map[string]struct{}),
		endpointsModify:     p.EndpointsModify,
		endpointsLookup:     p.EndpointsLookup,
		ciliumMeshPolicyMap: p.CiliumMeshPolicyWriter,
		// endpointsCreator can't be initialized now, it will be initialized
		// later, when the jobs runs.
		endpointsCreator: nil,
	}

	p.JobGroup.Add(
		job.OneShot("cilium-mesh-main", func(ctx context.Context, _ cell.Health) error {
			var err error
			// We need the endpoint creator to be ready before we start handling
			// events.
			cmm.endpointsCreator, err = p.EndpointCreator.Await(ctx)
			if err != nil {
				return err
			}
			cmm.run(ctx)
			return nil
		}),
	)

	return cmm
}

func (cmm *CiliumMeshController) run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cmm.logger.Info("Initializing")
	defer cmm.logger.Info("Shutting down")

	for ev := range cmm.resource.Events(ctx) {
		switch ev.Kind {
		case resource.Sync:
		case resource.Delete:
			ep := ev.Object

			if err := cmm.delMeshEndpoint(ep); err != nil {
				cmm.logger.WithFields(logrus.Fields{
					logfields.Object:       ep.ObjectMeta.Name,
					logfields.K8sNamespace: ep.ObjectMeta.Namespace,
				}).WithError(err).Warn("failed to delete IsovalentMeshEndpoint")
				ev.Done(err)
				continue
			}
			objName := fmt.Sprintf("%s/%s", ev.Object.GetNamespace(), ev.Object.GetName())
			delete(cmm.meshEndpoints, objName)

		case resource.Upsert:
			objName := fmt.Sprintf("%s/%s", ev.Object.GetNamespace(), ev.Object.GetName())
			ep := ev.Object
			_, ok := cmm.meshEndpoints[objName]
			if !ok {
				err := cmm.addMeshEndpoint(ep)
				if err != nil {
					ev.Done(err)
					continue
				}
				cmm.meshEndpoints[objName] = struct{}{}
			}
			// TODO we don't handle endpoint updates
			cmm.logger.WithFields(logrus.Fields{
				logfields.Object:       ep.ObjectMeta.Name,
				logfields.K8sNamespace: ep.ObjectMeta.Namespace,
			}).Info("ignoring IsovalentMeshEndpoint update event (NYI)")
		}
		ev.Done(nil)
	}
}

func populatePolicyMetaMap(cmm *CiliumMeshController, ep *endpoint.Endpoint) error {

	policyMap, err := ep.GetPolicyMap()
	if err != nil {
		cmm.logger.WithError(err).Warn("failed to get ep.policyMap")
		return err
	}

	err = cmm.ciliumMeshPolicyMap.WriteEndpoint(ep.IPv4, policyMap)
	if err != nil {
		cmm.logger.WithError(err).Warn("failed to write to the ciliummeshpolicymap")
		return err
	}

	return nil
}

func (cmm *CiliumMeshController) addMeshEndpoint(e *v1alpha1.IsovalentMeshEndpoint) error {
	epReq := &models.EndpointChangeRequest{
		ID:           0,
		K8sNamespace: e.GetNamespace(),
		Addressing:   &models.AddressPair{IPV4: e.Spec.IP},
		State:        models.EndpointStateWaitingDashForDashIdentity.Pointer(),
		Properties: map[string]interface{}{
			// We will mark this as a "fake" endpoint.
			endpoint.PropertyFakeEndpoint: true,
			// We don't want any BPF regeneration done to this endpoint.
			endpoint.PropertySkipBPFPolicy:                  false,
			endpoint.PropertyWithouteBPFDatapath:            true,
			endpoint.PropertyMeshEndpoint:                   true,
			endpoint.PropertyIsovalentMeshEndpointName:      e.GetName(),
			endpoint.PropertyIsovalentMeshEndpointNamespace: e.GetNamespace(),
			endpoint.PropertyIsovalentMeshEndpointUID:       e.GetUID(),
			endpoint.PropertyIsovalentMeshEndpoint:          e,
			endpoint.PropertyCEPOwner:                       e,
			endpoint.PropertyCEPName:                        e.GetName(),
		},
	}

	var err error

	// Check if there is an existing Isovalent
	ep := cmm.endpointsLookup.LookupIPv4(e.Spec.IP)
	if ep != nil {
		for k, v := range epReq.Properties {
			ep.SetPropertyValue(k, v)
		}
		if e.GetNamespace() != ep.K8sNamespace {
			return fmt.Errorf("%T '%s/%s' in a different namespace than local endpoint, please recreate it %q!=%q",
				e, e.GetNamespace(), e.GetName(), e.GetNamespace(), ep.GetK8sNamespace())
		}
	} else {
		ep, err = cmm.endpointsCreator.CreateEndpoint(context.TODO(), epReq)
		if err != nil {
			return err
		}
	}

	l := utils.SanitizePodLabels(e.ObjectMeta.Labels, &slim_core_v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: e.GetNamespace(),
		},
	}, "", cmm.clusterName)

	// Mark all the labels with source "k8s".
	epLbls := labels.Map2Labels(l, labels.LabelSourceK8s)

	// Mark this IME as a Cilium Mesh endpoint with the labels.LabelCiliumMesh.
	lbs := labels.NewFrom(labels.LabelCiliumMesh)

	// Merge the labels into the endpoint labels.
	epLbls.MergeLabels(lbs)

	ep.UpdateLabels(context.TODO(), labels.LabelSourceAny, epLbls, nil, true)

	// Set a nil metadata so that we can create a CEP from the endpointsynchronizer
	ep.SetK8sMetadata(nil)

	// Set a nil metadata so that we can create a CEP from the endpointsynchronizer
	populatePolicyMetaMap(cmm, ep)

	return nil
}

func (cmm *CiliumMeshController) delMeshEndpoint(e *v1alpha1.IsovalentMeshEndpoint) error {
	ip := e.Spec.IP // indexing by other fields are currently broken

	ep := cmm.endpointsLookup.LookupIPv4(ip)
	if ep == nil {
		return nil
	}
	errs := cmm.endpointsModify.RemoveEndpoint(ep, endpoint.DeleteConfig{})
	if len(errs) != 0 {
		return errs[0]
	}
	return nil
}

// IsovalentMeshEndpointResource is a Resource[T] for the local
// newCiliumMeshController.
type IsovalentMeshEndpointResource resource.Resource[*v1alpha1.IsovalentMeshEndpoint]

type meshEndpointResourceParams struct {
	cell.In

	Config Config
}

func NewIsovalentMeshEndpointResource(p meshEndpointResourceParams, lc cell.Lifecycle, cs client.Clientset) IsovalentMeshEndpointResource {
	if !p.Config.EnableCiliumMesh || !cs.IsEnabled() {
		return nil
	}
	lw := utils.ListerWatcherWithFields(
		utils.ListerWatcherFromTyped[*v1alpha1.IsovalentMeshEndpointList](cs.IsovalentV1alpha1().IsovalentMeshEndpoints(v1.NamespaceAll)),
		fields.Everything(),
	)
	return resource.New[*v1alpha1.IsovalentMeshEndpoint](lc, lw, resource.WithMetric("IsovalentMeshEndpointResource"))
}
