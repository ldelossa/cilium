//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package dnsresolver

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

func newMetrics() *Metrics {
	return &Metrics{
		FQDNResolvers: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "fqdn_resolvers_total",
			Help:      "Number of background FQDN resolvers started by the Operator",
		}),
		FQDNGroupReconcilers: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "fqdngroup_reconcilers_total",
			Help:      "Number of IsovalentFQDNGroup reconcilers started by the Operator",
		}),
	}
}

type Metrics struct {
	// FQDNResolvers is the number of background FQDN resolvers started by the DNS resolver manager.
	FQDNResolvers metric.Gauge

	// FQDNResolvers is the number of IsovalentFDQNGroup reconcilers started by the DNS resolver manager.
	FQDNGroupReconcilers metric.Gauge
}
