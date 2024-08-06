// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgpv1

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/enterprise/operator/pkg/bgpv2/config"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/reconciler"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/k8s"
)

// Cell is module with Enterprise BGP Control Plane components
var Cell = cell.Module(
	"enterprise-bgp-control-plane",
	"Enterprise BGP Control Plane",

	// BGP resources
	cell.Provide(
		k8s.IsovalentBGPPeerConfigResource,
		k8s.IsovalentBGPAdvertisementResource,
		k8s.IsovalentBGPNodeConfigResource,
		k8s.IsovalentBGPVRFConfigResource,
	),

	// enterprise-only reconcilers
	reconciler.ConfigReconcilers,
	reconcilerv2.ConfigReconcilers,

	// set enterprise BGP config object in agent
	cell.Config(config.Config{}),
)
