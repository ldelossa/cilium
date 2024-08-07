// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"

	daemon_k8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
)

var (
	NotInitializedErr     = fmt.Errorf("not initialized")
	UpdateConfigNotSetErr = fmt.Errorf("config missing")
)

// EnterpriseReconcileParams is an enterprise specific version of
// reconcilerv2.ReconcileParams. It must be created with
// reconcileParamsUpgrader.upgrade.
type EnterpriseReconcileParams struct {
	BGPInstance   *EnterpriseBGPInstance
	DesiredConfig *v1alpha1.IsovalentBGPNodeInstance
	CiliumNode    *ciliumv2.CiliumNode
}

// EnterpriseStateReconcileParams is an enterprise specific version of
// reconcilerv2.StateReconcileParams. It must be created with
// reconcileParamsUpgrader.upgradeState.
type EnterpriseStateReconcileParams struct {
	DesiredConfig   *v1alpha1.IsovalentBGPNodeInstance
	UpdatedInstance *EnterpriseBGPInstance
	DeletedInstance string
}

// EnterpriseBGPInstance is an enterprise specific version of
// reconcilerv2.BGPInstance. It must be created with
// reconcileParamsUpgrader.upgrade.
type EnterpriseBGPInstance struct {
	ASN    uint32
	Config *v1alpha1.IsovalentBGPNodeInstance
	Router types.Router

	// Shallow copy of the metadata from the reconcilerv2.BGPInstance. You
	// can put enterprise-specific metadata directly into this map and it
	// will be persisted between reconciliations. Thus, you are
	// responsible for ensuring there's no key collision between the OSS
	// reconcilers.
	Metadata map[string]any
}

type paramUpgrader interface {
	upgrade(params reconcilerv2.ReconcileParams) (EnterpriseReconcileParams, error)
	upgradeState(params reconcilerv2.StateReconcileParams) (EnterpriseStateReconcileParams, error)
}

type reconcilerParamsUpgraderIn struct {
	cell.In

	Logger           logrus.FieldLogger
	BGPConfig        config.Config
	BGPNodeConfigRes resource.Resource[*v1alpha1.IsovalentBGPNodeConfig]
	LocalNodeRes     daemon_k8s.LocalCiliumNodeResource
	Signaler         *signaler.BGPCPSignaler
	JobGroup         job.Group
}

type reconcileParamsUpgrader struct {
	initialized   atomic.Bool
	nodeName      string
	nodeNameMutex lock.Mutex
	store         resource.Store[*v1alpha1.IsovalentBGPNodeConfig]
}

func newReconcileParamsUpgrader(in reconcilerParamsUpgraderIn) paramUpgrader {
	u := &reconcileParamsUpgrader{}
	if !in.BGPConfig.Enabled {
		// No need to initialize the upgrader if enterprise BGP control plane is not enabled.
		return u
	}

	in.JobGroup.Add(job.OneShot("bgp-reconcile-params-upgrader-init", func(ctx context.Context, health cell.Health) error {
		s, err := in.BGPNodeConfigRes.Store(ctx)
		if err != nil {
			return err
		}
		u.store = s

		for event := range in.LocalNodeRes.Events(ctx) {
			switch event.Kind {
			case resource.Upsert:
				u.setNodeName(event.Object.GetName())

				// initialize upgrader once we have the node name
				u.initialized.Store(true)
				in.Logger.Debug("BGP params upgrader initialized")
			}
			event.Done(nil)
		}

		return nil
	}))

	// Trigger BGP CP reconciliation upon IsovalentBGPNodeConfig events.
	// As CiliumBGPNodeConfig is not updated upon IsovalentBGPNodeConfig changes, we need to trigger it from here.
	// All other IsovalentBGP* resources are synced by the operator to their CiliumBGP* version (including the reference
	// to the IsovalentBGP* resource version in an annotation), so we do not need to trigger reconciliation for them.
	in.JobGroup.Add(job.OneShot("bgp-upgrader-node-config-events", func(ctx context.Context, health cell.Health) (err error) {
		for event := range in.BGPNodeConfigRes.Events(ctx) {
			// There could be duplicate triggers in cases where a change in IsovalentBGPClusterConfig will change
			// both IsovalentBGPNodeConfig and CiliumBGPNodeConfig (e.g. when adding/removing a peer).
			// However, often they may be coalesced by the signaler anyway. If this triggers too many reconciles,
			// we can consider filtering the events here to only enterprise-related changes.
			in.Signaler.Event(struct{}{})
			event.Done(nil)
		}
		return nil
	}))

	return u
}

func (u *reconcileParamsUpgrader) upgrade(params reconcilerv2.ReconcileParams) (EnterpriseReconcileParams, error) {
	if !u.initialized.Load() {
		return EnterpriseReconcileParams{}, NotInitializedErr
	}

	if params.BGPInstance == nil || params.DesiredConfig == nil || params.CiliumNode == nil {
		return EnterpriseReconcileParams{}, fmt.Errorf("invalid params")
	}

	nc, exists, err := u.store.GetByKey(resource.Key{Name: params.CiliumNode.Name})
	if err != nil {
		return EnterpriseReconcileParams{}, err
	}

	if !exists {
		return EnterpriseReconcileParams{}, fmt.Errorf("enterprise node config not found")
	}

	for i, inst := range nc.Spec.BGPInstances {
		// compare BGP instance names to find the matching instance.
		// We check desired config instead of BGPInstance.Config because
		// BGPInstance.Config is nil at first reconciliation loop. Desired config
		// is considered source of truth.
		if inst.Name != params.DesiredConfig.Name {
			continue
		}
		return EnterpriseReconcileParams{
			BGPInstance: &EnterpriseBGPInstance{
				ASN: params.BGPInstance.ASN,
				// So far, we don't need to keep the previous
				// config. Once we have a use case for it, we
				// can consider storing it in the metadata and
				// copying it here.
				Config:   nil,
				Router:   params.BGPInstance.Router,
				Metadata: params.BGPInstance.Metadata,
			},
			DesiredConfig: &nc.Spec.BGPInstances[i],
			CiliumNode:    params.CiliumNode,
		}, nil
	}

	return EnterpriseReconcileParams{}, fmt.Errorf("enterprise node instance not found")
}

func (u *reconcileParamsUpgrader) upgradeState(params reconcilerv2.StateReconcileParams) (EnterpriseStateReconcileParams, error) {
	if !u.initialized.Load() {
		return EnterpriseStateReconcileParams{}, NotInitializedErr
	}

	// If the instance is being deleted, we don't need to find the instance in the config.
	if params.DeletedInstance != "" {
		return EnterpriseStateReconcileParams{
			DesiredConfig:   nil,
			UpdatedInstance: nil,
			DeletedInstance: params.DeletedInstance,
		}, nil
	}

	if params.UpdatedInstance == nil || params.UpdatedInstance.Config == nil {
		return EnterpriseStateReconcileParams{}, UpdateConfigNotSetErr
	}

	nc, exists, err := u.store.GetByKey(resource.Key{Name: u.getNodeName()})
	if err != nil {
		return EnterpriseStateReconcileParams{}, err
	}

	if !exists {
		return EnterpriseStateReconcileParams{}, fmt.Errorf("enterprise node config not found")
	}

	for i, inst := range nc.Spec.BGPInstances {
		if inst.Name == params.UpdatedInstance.Config.Name {
			return EnterpriseStateReconcileParams{
				DesiredConfig: &nc.Spec.BGPInstances[i],
				UpdatedInstance: &EnterpriseBGPInstance{
					// So far, we don't need to keep the previous
					// config. Once we have a use case for it, we
					// can consider storing it in the metadata and
					// copying it here.
					Config:   nil,
					Router:   params.UpdatedInstance.Router,
					Metadata: params.UpdatedInstance.Metadata,
				},
			}, nil
		}
	}

	return EnterpriseStateReconcileParams{}, fmt.Errorf("enterprise node instance not found")
}

func (u *reconcileParamsUpgrader) getNodeName() string {
	u.nodeNameMutex.Lock()
	defer u.nodeNameMutex.Unlock()
	return u.nodeName
}

func (u *reconcileParamsUpgrader) setNodeName(name string) {
	u.nodeNameMutex.Lock()
	u.nodeName = name
	u.nodeNameMutex.Unlock()
}
