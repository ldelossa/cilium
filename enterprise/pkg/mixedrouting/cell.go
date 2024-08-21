//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package mixedrouting

import (
	"github.com/cilium/hive/cell"

	cemrcfg "github.com/cilium/cilium/enterprise/pkg/mixedrouting/config"
	"github.com/cilium/cilium/pkg/metrics"
)

var defaultConfig = cemrcfg.Config{
	FallbackRoutingMode: cemrcfg.FallbackDisabled,
}

var Cell = cell.Module(
	"mixed-routing",
	"Support for mixed routing mode",

	cell.Config(defaultConfig),
	metrics.Metric(newMetrics),

	cell.Provide(
		newManager,

		// Configure the datapath to enable the configuration of the tunnel device
		// and the compilation of the corresponding logic when the primary routing
		// mode is native, and fallback it tunnel.
		datapathConfigProvider,

		// Configure the filter to limit the upsertion of ipset entries to only the
		// ones corresponding to nodes that should be reached in native routing mode.
		(*manager).ipsetFilter,
	),

	cell.Invoke(
		// Validate the mixed routing configuration.
		cemrcfg.Config.Validate,

		// Add the supported routing modes annotation to the local node.
		(*manager).configureLocalNode,

		// Hook the extra logic to observe node upsertions and deletions, retrieve
		// the routing modes annotations and configure the datapath accordingly
		// (e.g., node routes, ...).
		(*manager).setupNodeManager,

		// Hook the extra logic to observe endpoint upsertions and deletions,
		// match them with the corresponding node (and the associated routing
		// mode) and configure the datapath accordingly (ipcache map tunnel flag).
		(*manager).setupEndpointManager,

		// Register the jobs required by the mixed routing manager.
		(*manager).registerJobs,
	),
)
