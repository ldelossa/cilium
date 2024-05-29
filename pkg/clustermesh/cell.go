// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/metrics"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/source"
)

var Cell = cell.Module(
	"clustermesh",
	"ClusterMesh is the Cilium multicluster implementation",

	cell.Provide(NewClusterMesh),

	// Convert concrete objects into more restricted interfaces used by clustermesh.
	cell.ProvidePrivate(func(sc *k8s.ServiceCache) (ServiceMerger, k8s.ServiceIPGetter) { return sc, sc }),
	cell.ProvidePrivate(func(ipcache *ipcache.IPCache) ipcache.IPCacher { return ipcache }),
	cell.ProvidePrivate(func(mgr nodemanager.NodeManager) (store.Observer, kvstore.ClusterSizeDependantIntervalFunc) {
		return nodeStore.NewNodeObserver(mgr, source.ClusterMesh), mgr.ClusterSizeDependantInterval
	}),
	cell.ProvidePrivate(func() store.KeyCreator { return nodeStore.KeyCreator }),
	cell.ProvidePrivate(idsMgrProvider),

	cell.Config(common.Config{}),
	cell.Config(wait.TimeoutConfigDefault),

	metrics.Metric(NewMetrics),
	metrics.Metric(common.MetricsProvider(subsystem)),

	cell.Invoke(ipsetSyncer),
)
