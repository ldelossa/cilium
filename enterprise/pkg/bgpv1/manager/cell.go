// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package manager

import (
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/reconciler"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// ConfigReconcilers contains cells of enterprise-only reconcilers
var ConfigReconcilers = cell.Group(

	// Provide reconcilers publicly here, as they need to be injected into OSS BGPRouterManager
	cell.Provide(
		reconciler.NewLBServiceReconciler,
	),

	// Wire enterprise LB Service reconciler with the OSS version
	cell.Invoke(reconciler.WireLBServiceReconcilers),

	// config of the enterprise reconcilers
	cell.Config(reconciler.Config{}),
)
