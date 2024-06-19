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
	"github.com/cilium/cilium/pkg/metrics/metric"
)

// Metrics provides metrics for top-k nat stats.
type Metrics struct {
	TopkMetrics metric.DeletableVec[metric.Gauge]
}

func newMetrics() Metrics {
	return Metrics{
		TopkMetrics: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Help:      "Top-K saturation of source ports on a egress-ip/external endpoint tuple",
			Name:      "nat_endpoint_topk_connection",
			Disabled:  true,
		}, []string{"family", "egress_ip", "endpoint_ip", "remote_port", "proto"}),
	}
}
