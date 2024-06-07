// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bgpv2

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

var Cell = cell.Module(
	"bgp-enterprise-control-plane-operator",
	"BGP Control Plane Operator",

	cell.Provide(
		k8s.IsovalentBGPClusterConfigResource,
		k8s.IsovalentBGPPeerConfigResource,
		k8s.IsovalentBGPAdvertisementResource,
		k8s.IsovalentBGPNodeConfigOverrideResource,
	),

	cell.ProvidePrivate(
		store.NewBGPCPResourceStore[*v1alpha1.IsovalentBGPClusterConfig],
		store.NewBGPCPResourceStore[*v1alpha1.IsovalentBGPPeerConfig],
		store.NewBGPCPResourceStore[*v1alpha1.IsovalentBGPAdvertisement],
		store.NewBGPCPResourceStore[*v1alpha1.IsovalentBGPNodeConfigOverride],
	),

	cell.ProvidePrivate(signaler.NewBGPCPSignaler),

	cell.Invoke(RegisterBGPResourceMapper),
)
