//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package clustermesh

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/option"

	cecmcfg "github.com/cilium/cilium/enterprise/pkg/clustermesh/config"
)

var defaultConfig = cecmcfg.Config{
	EnableClusterAwareAddressing: false,
	EnableInterClusterSNAT:       false,
	EnablePhantomServices:        true,
}

var Cell = cell.Module(
	"enterprise-clustermesh",
	"ClusterMesh is the Isovalent Enterprise for Cilium multicluster implementation",

	cell.Config(defaultConfig),

	cell.Provide(
		// Inject the ClusterIDManager implementation with the extended logic
		// to handle per-cluster maps creation and removal.
		newClusterIDManager,
		func(mgr ClusterIDsManager) clustermesh.ClusterIDsManager { return mgr },

		// Inject the extra datapath configs required for overlapping PodCIDR support.
		datapathNodeHeaderConfigProvider,

		// Inject the extra ipcache watcher options to enable cluster ID propagation.
		extraIPCacheWatcherOptsProvider,
	),

	cell.Invoke(
		// Override the OSS ServiceMerger, to introduce the support for enterprise features.
		clustermesh.InjectCEServiceMerger,

		// Validate the enterprise clustermesh configuration.
		func(cfg cecmcfg.Config, dcfg *option.DaemonConfig) error {
			return cfg.Validate(dcfg)
		},

		// Register enterprise-only jobs, currently handling the garbage
		// collection of stale per-cluster maps.
		registerJobs,

		// Inject the mutator to propagate the cluster ID to the tunnel map.
		linux.InjectCEPrefixClusterMutator,
	),
)
