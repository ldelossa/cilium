//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package dnsclient

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

// labelFQDN is the label for fqdns queried by the operator DNS client
const labelFQDN = "fqdn"

func newMetrics() *Metrics {
	return &Metrics{
		metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: "dns_client",
			Name:      "rtt_stats_seconds",
			Help:      "Operator DNS client queries RTT stats",
		}, []string{labelFQDN}),
	}
}

type Metrics struct {
	// RTTStats is the RTT for dns queries from the dns client.
	RTTStats metric.Vec[metric.Observer]
}
