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

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

func (r *ServiceReconciler) GetPeerAdvertisement() *CiliumPeerAdvertisement {
	return r.peerAdvert
}

func (r *ServiceReconciler) PopulateLocalServices(localNodeName string) (sets.Set[resource.Key], error) {
	return r.populateLocalServices(localNodeName)
}

func (r *ServiceReconciler) ModifiedServiceAdvertisements(p ReconcileParams, desiredPeerAdverts PeerAdvertisements) bool {
	return r.modifiedServiceAdvertisements(p, desiredPeerAdverts)
}

func (r *ServiceReconciler) UpdateServiceAdvertisementsMetadata(p ReconcileParams, peerAdverts PeerAdvertisements) {
	r.updateServiceAdvertisementsMetadata(p, peerAdverts)
}

func (r *ServiceReconciler) FullReconciliationServiceList(p ReconcileParams) (toReconcile []*slim_corev1.Service, toWithdraw []resource.Key, err error) {
	return r.fullReconciliationServiceList(p)
}

func (r *ServiceReconciler) DiffReconciliationServiceList(p ReconcileParams) (toReconcile []*slim_corev1.Service, toWithdraw []resource.Key, err error) {
	return r.diffReconciliationServiceList(p)
}

func (r *ServiceReconciler) GetDesiredRoutePolicies(p ReconcileParams, desiredPeerAdverts PeerAdvertisements, toUpdate []*slim_corev1.Service, toRemove []resource.Key, ls sets.Set[resource.Key]) (ResourceRoutePolicyMap, error) {
	return r.getDesiredRoutePolicies(p, desiredPeerAdverts, toUpdate, toRemove, ls)
}

func (r *ServiceReconciler) ReconcileSvcRoutePolicies(ctx context.Context, p ReconcileParams, desiredSvcRoutePolicies ResourceRoutePolicyMap) error {
	return r.reconcileSvcRoutePolicies(ctx, p, desiredSvcRoutePolicies)
}

func (r *ServiceReconciler) GetServiceAFPaths(p ReconcileParams, desiredPeerAdverts PeerAdvertisements, svc *slim_corev1.Service, ls sets.Set[resource.Key]) (AFPathsMap, error) {
	return r.getServiceAFPaths(p, desiredPeerAdverts, svc, ls)
}

func (r *ServiceReconciler) ReconcilePaths(ctx context.Context, p ReconcileParams, desiredSvcPaths ResourceAFPathsMap) error {
	return r.reconcilePaths(ctx, p, desiredSvcPaths)
}

func (r *ServiceReconciler) GetService(svcKey resource.Key) (*slim_corev1.Service, bool, error) {
	return r.svcDiffStore.GetByKey(svcKey)
}

func (r *ServiceReconciler) GetMetadata(i *instance.BGPInstance) ServiceReconcilerMetadata {
	return r.getMetadata(i)
}
