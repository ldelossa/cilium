//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package reconciler

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

var Cell = cell.Module(
	"bfd-reconciler",
	"BFD configuration reconciler",

	cell.Provide(
		types.NewBFDPeersTable,
		statedb.RWTable[*types.BFDPeerStatus].ToTable,
	),
	cell.Invoke(statedb.RegisterTable[*types.BFDPeerStatus]),

	cell.ProvidePrivate(
		newBFDProfileResource,
		newBFDNodeConfigResource,
	),

	cell.Invoke(func(p bfdReconcilerParams) {
		newBFDReconciler(p)
	}),
)

func newBFDProfileResource(lc cell.Lifecycle, c client.Clientset, cfg types.BFDConfig) resource.Resource[*v1alpha1.IsovalentBFDProfile] {
	if !cfg.BFDEnabled {
		return nil
	}

	return resource.New[*v1alpha1.IsovalentBFDProfile](
		lc, utils.ListerWatcherFromTyped[*v1alpha1.IsovalentBFDProfileList](
			c.IsovalentV1alpha1().IsovalentBFDProfiles(),
		), resource.WithMetric("IsovalentBFDProfile"))
}

func newBFDNodeConfigResource(lc cell.Lifecycle, c client.Clientset, cfg types.BFDConfig) resource.Resource[*v1alpha1.IsovalentBFDNodeConfig] {
	if !cfg.BFDEnabled {
		return nil
	}

	return resource.New[*v1alpha1.IsovalentBFDNodeConfig](
		lc, utils.ListerWatcherFromTyped[*v1alpha1.IsovalentBFDNodeConfigList](
			c.IsovalentV1alpha1().IsovalentBFDNodeConfigs(),
		), resource.WithMetric("IsovalentBFDNodeConfig"))
}
