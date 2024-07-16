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

	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

// EnterpriseReconcileParams is an enterprise specific version of
// reconcilerv2.ReconcileParams. It must be created with
// reconcileParamsUpgrader.upgrade.
type EnterpriseReconcileParams struct {
	BGPInstance   *EnterpriseBGPInstance
	DesiredConfig *v1alpha1.IsovalentBGPNodeInstance
	CiliumNode    *ciliumv2.CiliumNode
}

// EnterpriseBGPInstance is an enterprise specific version of
// reconcilerv2.BGPInstance. It must be created with
// reconcileParamsUpgrader.upgrade.
type EnterpriseBGPInstance struct {
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
}

type reconcileParamsUpgrader struct {
	initialized atomic.Bool
	store       resource.Store[*v1alpha1.IsovalentBGPNodeConfig]
}

func newReconcileParamsUpgrader(r resource.Resource[*v1alpha1.IsovalentBGPNodeConfig], g job.Group) *reconcileParamsUpgrader {
	u := &reconcileParamsUpgrader{}

	g.Add(job.OneShot("bgp-reconcile-params-upgrader-init", func(ctx context.Context, health cell.Health) error {
		s, err := r.Store(ctx)
		if err != nil {
			return err
		}
		u.store = s
		u.initialized.Store(true)
		return nil
	}))

	return u
}

func (u *reconcileParamsUpgrader) upgrade(params reconcilerv2.ReconcileParams) (EnterpriseReconcileParams, error) {
	if !u.initialized.Load() {
		return EnterpriseReconcileParams{}, fmt.Errorf("not initialized")
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
