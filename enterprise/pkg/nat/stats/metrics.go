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
	"context"
	"iter"
	"strconv"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/nat/stats"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/prometheus/client_golang/prometheus"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "nat-topk-stats")

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

func (m *Metrics) upsertTopkMetric(s stats.NatMapStats) {
	m.TopkMetrics.WithLabelValues(
		s.Type,
		s.EgressIP,
		s.EndpointIP,
		strconv.Itoa(int(s.RemotePort)),
		s.Proto,
	).Set(float64(s.Count))
}

func (m *Metrics) deleteTopkMetric(s stats.NatMapStats) {
	m.TopkMetrics.DeletePartialMatch(prometheus.Labels{
		"family":      s.Type,
		"egress_ip":   s.EgressIP,
		"endpoint_ip": s.EndpointIP,
		"remote_port": strconv.Itoa(int(s.RemotePort)),
		"proto":       s.Proto,
	})
}

func (m *Metrics) isEnabled() bool {
	return m.TopkMetrics.IsEnabled()
}

// metricsActions abstracts actions of managing inserts and deletes of topk
// metrics tuples.
type metricsActions interface {
	upsertTopkMetric(stats.NatMapStats)
	deleteTopkMetric(stats.NatMapStats)
	isEnabled() bool
}

type topkMetrics struct {
	metricsActions
	statsTable statedb.Table[stats.NatMapStats]
	db         *statedb.DB

	lastMetricEntriesIpv4 sets.Set[stats.NatMapStats]
	lastMetricEntriesIpv6 sets.Set[stats.NatMapStats]

	lastDeleted int
}

type params struct {
	cell.In
	DB             *statedb.DB
	Stats          statedb.Table[stats.NatMapStats]
	Metrics        metricsActions
	NatStatsConfig stats.Config
	Lifecycle      cell.Lifecycle
	Jobs           job.Group
	Health         cell.Health
}

func newTopkMetrics(p params) *topkMetrics {
	if p.NatStatsConfig.NatMapStatKStoredEntries == 0 {
		return nil
	}

	// Currently, this only emits a metric, so if this metric is disabled
	// we will not create/start the manager.
	if !p.Metrics.isEnabled() {
		return nil
	}

	m := &topkMetrics{
		metricsActions: p.Metrics,
		db:             p.DB,
		statsTable:     p.Stats,
	}

	h := p.Health.NewScope("reconcile-metrics")
	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			go func() {
				tx := m.db.ReadTxn()
				iter := m.statsTable.All(tx)
				if err := m.update(iter); err != nil {
					log.WithError(err).Error("could not populate initial topk nat metrics." +
						" This may result in out of date or incorrect metrics")
				}

				// nat-stats table is updated periodically using a timer (default: 30s).
				// However, add a 1 per 15 second rate limit in case future changes update
				// nat-stats table more.
				limiter := rate.NewLimiter(15*time.Second, 1)
				defer limiter.Stop()
				for {
					tx := m.db.ReadTxn()
					iter, watch := m.statsTable.AllWatch(tx)
					select {
					case <-watch:
						limiter.Wait(ctx)
						if err := m.update(iter); err != nil {
							log.WithError(err).Error("Could not update topk nat metrics." +
								" This may result in out of date or incorrect metrics")
							h.Degraded("failed update topk nat stats", err)
						} else {
							h.OK("update of topk nat stats successful")
							log.Debug("completed topk metrics update")
						}
					case <-ctx.Done():
						return
					}
				}
			}()
			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()
			return nil
		},
	})

	return m
}

func (m *topkMetrics) update(iter iter.Seq2[stats.NatMapStats, statedb.Revision]) error {
	currEntriesIpv4 := sets.New[stats.NatMapStats]()
	currEntriesIpv6 := sets.New[stats.NatMapStats]()
	for entry := range iter {
		// By zeroing of the nth value, we make the entry something we can
		// perform set operations on which will be useful for managing metrics.
		entry.Nth = 0
		switch entry.Type {
		case nat.IPv4.String():
			currEntriesIpv4.Insert(entry)
		case nat.IPv6.String():
			currEntriesIpv6.Insert(entry)
		}
	}

	// toDelete is the set of entries that where previously in the metrics entries, but
	// are not in the current set of metrics.
	//
	// That is, this is the set of entries that no longer appear in the topk list.
	toDelete := m.lastMetricEntriesIpv4.Difference(currEntriesIpv4).Union(
		m.lastMetricEntriesIpv6.Difference(currEntriesIpv6))

	for entry := range toDelete {
		m.deleteTopkMetric(entry)
	}

	m.lastDeleted = len(toDelete)

	for entry := range currEntriesIpv4 {
		m.upsertTopkMetric(entry)
	}
	for entry := range currEntriesIpv6 {
		m.upsertTopkMetric(entry)
	}

	m.lastMetricEntriesIpv4 = currEntriesIpv4
	m.lastMetricEntriesIpv6 = currEntriesIpv6

	return nil
}
