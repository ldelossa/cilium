// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconciler

import (
	"context"
	"net/netip"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

type LocalServices localServices

func (r *ServiceReconciler) PopulateLocalServices(localNodeName string) (LocalServices, error) {
	ls, err := r.populateLocalServices(localNodeName)
	return LocalServices(ls), err
}

func (r *ServiceReconciler) RequiresFullReconciliation(p ReconcileParams) bool {
	return r.requiresFullReconciliation(p)
}

func (r *ServiceReconciler) FullReconciliationServiceList(sc *instance.ServerWithConfig) (toReconcile []*slim_corev1.Service, toWithdraw []resource.Key, err error) {
	return r.fullReconciliationServiceList(sc)
}

func (r *ServiceReconciler) SvcDesiredRoutes(newc *v2alpha1api.CiliumBGPVirtualRouter, svc *slim_corev1.Service, ls LocalServices) ([]netip.Prefix, error) {
	return r.svcDesiredRoutes(newc, svc, localServices(ls))
}

func (r *ServiceReconciler) ReconcileServiceRoutes(ctx context.Context, sc *instance.ServerWithConfig, svc *slim_corev1.Service, desiredRoutes []netip.Prefix) error {
	return r.reconcileServiceRoutes(ctx, sc, svc, desiredRoutes)
}

func (r *ServiceReconciler) WithdrawService(ctx context.Context, sc *instance.ServerWithConfig, key resource.Key) error {
	return r.withdrawService(ctx, sc, key)
}

func (r *ServiceReconciler) DiffReconciliationServiceList(sc *instance.ServerWithConfig) (toReconcile []*slim_corev1.Service, toWithdraw []resource.Key, err error) {
	return r.diffReconciliationServiceList(sc)
}

func (r *ServiceReconciler) GetMetadata(sc *instance.ServerWithConfig) LBServiceReconcilerMetadata {
	return r.getMetadata(sc)
}

func (r *ServiceReconciler) GetService(svcKey resource.Key) (*slim_corev1.Service, bool, error) {
	return r.diffStore.GetByKey(svcKey)
}
