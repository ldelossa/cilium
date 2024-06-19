//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package stats

import (
	"github.com/cilium/cilium/pkg/metrics"

	"github.com/cilium/hive/cell"
)

// Cell provides an implementation of topk nat stats metrics that uses
// the OSS pkg/maps/nat/stats.Cell nat-stats manager.
// This watches on updates on statedb.Table[stats.NatMapStats] and manages
// a top-k type metric, useful for customers using EGW/EGW-HA features which
// can exhaust connection tuples on concentrated workloads.
//
// If the nat_endpoint_topk_connection is disabled via metrics config, then
// this module will return nil and not start managing the metric.
var Cell = cell.Module(
	"enterprise-topk-nat-stats",
	"Enterprise Top-K NAT Stats",
	metrics.Metric(newMetrics),
	cell.Provide(func(m Metrics) metricsActions {
		return &m
	}),
	cell.Provide(newTopkMetrics),
	cell.Invoke(func(_ *topkMetrics) {}),
)
