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
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

// ConfigReconcilers contains cells of enterprise-only reconcilers
var ConfigReconcilers = cell.Group(
	cell.ProvidePrivate(
		newReconcileParamsUpgrader,
		newIsovalentAdvertisement,
		newSRv6Paths,
	),

	// provide stores
	cell.Provide(
		store.NewBGPCPResourceStore[*v1alpha1.IsovalentBGPVRFConfig],
	),

	cell.Provide(
		k8s.IsovalentSRv6LocatorPoolResource,
	),

	cell.Provide(
		NewServiceReconciler,
		NewEgressGatewayIPsReconciler,
		NewBFDStateReconciler,
		NewSRv6LocatorPoolReconciler,
		NewVPNRoutePolicyReconciler,
		NewImportedVPNRouteReconciler,
		NewPodCIDRVRFReconciler,
		NewServiceVRFReconciler,
	),

	// wire the enterprise Service reconciler with the OSS version
	cell.Invoke(WireServiceReconcilers),

	// config of the enterprise reconcilers
	cell.Config(defaultConfig),
)
