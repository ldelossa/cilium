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
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	// BufferedEndpoints tracks the number of endpoints buffered waiting for the hosting node information.
	BufferedEndpoints metric.Gauge
}

func newMetrics() Metrics {
	return Metrics{
		BufferedEndpoints: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: "mixed_routing",
			Name:      "buffered_endpoints",
			Help:      "The number of endpoints buffered waiting for the hosting node information",
		}),
	}
}
