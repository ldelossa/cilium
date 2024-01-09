// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package export

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/aggregator"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

func Test_export_OnDecodedFlow(t *testing.T) {
	testTime := time.Date(2000, 5, 100, 15, 16, 17, 0, time.UTC)
	tests := []struct {
		name            string
		enabled         bool
		flows           []*flow.Flow
		formatVersion   string
		nodeName        string
		aggregationConf *aggregationConfig
		expected        string
		expectedCount   float64
	}{
		{
			name:    "disabled",
			enabled: false,
			flows: []*flow.Flow{
				{NodeName: "foo"},
				{NodeName: "bar"},
			},
			expected:      ``,
			expectedCount: 0,
			formatVersion: formatVersionV1,
		},
		{
			name:    "basic format v1",
			enabled: true,
			flows: []*flow.Flow{
				{NodeName: "foo"},
				{NodeName: "bar"},
			},
			expected: `{"flow":{"node_name":"foo"},"node_name":"foo"}
{"flow":{"node_name":"bar"},"node_name":"bar"}
`,
			expectedCount: 2,
			formatVersion: formatVersionV1,
		},
		{
			name:    "basic format v0",
			enabled: true,
			flows: []*flow.Flow{
				{NodeName: "foo"},
				{NodeName: "bar"},
			},
			expected: `{"node_name":"foo"}
{"node_name":"bar"}
`,
			expectedCount: 2,
			formatVersion: "",
		},
		{
			name:    "override node name",
			enabled: true,
			flows: []*flow.Flow{
				{NodeName: "foo"},
				{NodeName: "bar"},
			},
			expected: `{"flow":{"node_name":"overridden"},"node_name":"overridden"}
{"flow":{"node_name":"overridden"},"node_name":"overridden"}
`,
			expectedCount: 2,
			formatVersion: formatVersionV1,
			nodeName:      "overridden",
		},
		{
			name:    "aggregation",
			enabled: true,
			flows: []*flow.Flow{
				// Three flows with same connection (ignoring source port) within the same 30 second aggregation TTL
				{Time: timestamppb.New(testTime), IP: &flow.IP{Source: "192.168.1.1", Destination: "1.1.1.1"}, L4: &flow.Layer4{Protocol: &flow.Layer4_TCP{TCP: &flow.TCP{SourcePort: 12345, DestinationPort: 443}}}},
				{Time: timestamppb.New(testTime.Add(time.Second)), IP: &flow.IP{Source: "192.168.1.1", Destination: "1.1.1.1"}, L4: &flow.Layer4{Protocol: &flow.Layer4_TCP{TCP: &flow.TCP{SourcePort: 12345, DestinationPort: 443}}}},
				{Time: timestamppb.New(testTime.Add(2 * time.Second)), IP: &flow.IP{Source: "192.168.1.1", Destination: "1.1.1.1"}, L4: &flow.Layer4{Protocol: &flow.Layer4_TCP{TCP: &flow.TCP{SourcePort: 41676, DestinationPort: 443}}}},
				// new connection twice within the same TTL
				{Time: timestamppb.New(testTime.Add(3 * time.Second)), IP: &flow.IP{Source: "192.168.1.1", Destination: "8.8.8.8"}, L4: &flow.Layer4{Protocol: &flow.Layer4_TCP{TCP: &flow.TCP{SourcePort: 33233, DestinationPort: 443}}}},
				{Time: timestamppb.New(testTime.Add(4 * time.Second)), IP: &flow.IP{Source: "192.168.1.1", Destination: "8.8.8.8"}, L4: &flow.Layer4{Protocol: &flow.Layer4_TCP{TCP: &flow.TCP{SourcePort: 33233, DestinationPort: 443}}}},
				// New connection past the TTL
				{Time: timestamppb.New(testTime.Add(60 * time.Second)), IP: &flow.IP{Source: "192.168.1.1", Destination: "1.1.1.1"}, L4: &flow.Layer4{Protocol: &flow.Layer4_TCP{TCP: &flow.TCP{SourcePort: 41676, DestinationPort: 443}}}},
			},
			aggregationConf: &aggregationConfig{
				aggregations:      []string{"connection"},
				stateChangeFilter: []string{"new", "error", "closed"},
				ignoreSourcePort:  true,
				ttl:               30 * time.Second,
			},
			expected: `{"flow":{"time":"2000-08-08T15:16:17Z","IP":{"source":"192.168.1.1","destination":"1.1.1.1"},"l4":{"TCP":{"source_port":12345,"destination_port":443}}},"time":"2000-08-08T15:16:17Z"}
{"flow":{"time":"2000-08-08T15:16:20Z","IP":{"source":"192.168.1.1","destination":"8.8.8.8"},"l4":{"TCP":{"source_port":33233,"destination_port":443}}},"time":"2000-08-08T15:16:20Z"}
{"flow":{"time":"2000-08-08T15:17:17Z","IP":{"source":"192.168.1.1","destination":"1.1.1.1"},"l4":{"TCP":{"source_port":41676,"destination_port":443}}},"time":"2000-08-08T15:17:17Z"}
`,
			expectedCount: 3,
			formatVersion: formatVersionV1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := logrus.New()
			log.SetOutput(io.Discard)
			clock := clockwork.NewFakeClockAt(testTime)
			var sb strings.Builder
			encoder := json.NewEncoder(&sb)
			exportPlugin := &export{
				enabled:            tt.enabled,
				viper:              viper.New(),
				encoder:            encoder,
				denylist:           []filters.FilterFunc{},
				allowlist:          []filters.FilterFunc{},
				logger:             log,
				flowAggregator:     nil,
				aggregationContext: context.Background(),
				formatVersion:      tt.formatVersion,
				nodeName:           tt.nodeName,
			}

			if tt.aggregationConf != nil {
				var err error
				exportPlugin.flowAggregator = aggregator.NewFlowAggregator(clock, log)
				exportPlugin.aggregationContext, err = exportPlugin.flowAggregator.GetAggregationContext(
					tt.aggregationConf.aggregations,
					tt.aggregationConf.stateChangeFilter,
					tt.aggregationConf.ignoreSourcePort,
					tt.aggregationConf.ttl,
					tt.aggregationConf.renewTTL,
				)
				require.NoError(t, err)
			}
			promRegistry := prometheus.NewRegistry()
			metricsHandler := exportPlugin.NewHandler()
			metricsHandler.Init(promRegistry, api.Options{})

			labelNames := exportPlugin.metricsHandler.getLabelNames()
			labelValues, err := exportPlugin.metricsHandler.getLabelValues(&flow.Flow{})
			require.NoError(t, err)

			metricsLabels := make(prometheus.Labels)
			for i, name := range labelNames {
				metricsLabels[name] = labelValues[i]
			}

			for _, f := range tt.flows {
				// Advance the clock to the time of the flow occurring so aggregation
				// TTL behavior is tested since it compares the flow time to the
				// clock's current time
				flowTime := f.GetTime().AsTime()
				if !flowTime.IsZero() {
					now := clock.Now()
					delta := flowTime.Sub(now)
					clock.Advance(delta)
				}
				stop, err := exportPlugin.OnDecodedFlow(context.Background(), f)
				assert.False(t, stop)
				assert.NoError(t, err)
			}

			// verify the contents of the export
			assert.Equal(t, tt.expected, sb.String(), "export file contents did not match")

			// get the counter metric for this plugin
			counter, err := exportPlugin.metricsHandler.flowsExportedTotal.GetMetricWith(metricsLabels)
			require.NoError(t, err, "got error getting exported flow metrics counter")

			// verify metric
			exportedCount := testutil.ToFloat64(counter)
			assert.EqualValues(t, tt.expectedCount, exportedCount, "flow export metrics incorrect")
		})
	}
}

type jsonEvent struct {
	Flow          json.RawMessage `json:"flow"`
	RateLimitInfo json.RawMessage `json:"rate_limit_info"`
}

func checkEvents(t *testing.T, eventsJSON []byte, wantFlows, wantRateLimitInfo int, wantDropped uint64) {
	t.Helper()

	flows, rateLimitInfo, dropped := 0, 0, uint64(0)
	events := bytes.Split(eventsJSON, []byte("\n"))
	for _, eventLine := range events {
		if len(eventLine) == 0 {
			continue
		}

		var event jsonEvent
		if err := json.Unmarshal(eventLine, &event); err != nil {
			t.Fatalf("failed to unmarshal JSON event %q: %v", eventLine, err)
		}

		decoded := 0
		if len(event.Flow) > 0 {
			flows++
			decoded++
		}
		if len(event.RateLimitInfo) > 0 {
			var ev RateLimitInfoEvent
			if err := json.Unmarshal(eventLine, &ev); err != nil {
				t.Fatalf("failed to unmarshal JSON event %q: %v", eventLine, err)
			}
			rateLimitInfo++
			decoded++
			dropped += ev.RateLimitInfo.NumberOfDroppedEvents

			if len(ev.NodeName) == 0 {
				t.Errorf("empty node name for rate-limit-info event %#v", ev)
			}
		}

		if decoded != 1 {
			t.Fatalf("expected to decode %q as exactly 1 event, got %d", eventLine, decoded)
		}
	}
	assert.Equal(t, wantFlows, flows, "number of flows")
	assert.Equal(t, wantRateLimitInfo, rateLimitInfo, "number of rate_limit_info events")
	assert.Equal(t, wantDropped, dropped, "number of dropped flows")
}

func Test_rateLimitJSON(t *testing.T) {
	ev := RateLimitInfoEvent{
		RateLimitInfo: &RateLimitInfo{NumberOfDroppedEvents: 10},
		NodeName:      "my-node",
		Time:          time.Time{},
	}
	b, err := json.Marshal(ev)
	assert.NoError(t, err)
	assert.Equal(t, `{"rate_limit_info":{"number_of_dropped_events":10},"node_name":"my-node","time":"0001-01-01T00:00:00Z"}`, string(b))
}

func Test_rateLimitExport(t *testing.T) {
	tests := []struct {
		name              string
		totalFlows        int
		rateLimit         int
		wantFlows         int
		wantRateLimitInfo int
		wantDropped       uint64
	}{
		{"no flows", 0, 10, 0, 0, 0},
		{"rate limit", 100, 10, 10, 1, 90},
		{"rate limit all ", 100, 0, 0, 1, 100},
		{"rate limit none", 100, -1, 100, 0, 0},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s (%d flows, %d rate limit)", tt.name, tt.totalFlows, tt.rateLimit), func(t *testing.T) {
			log := logrus.New()
			log.SetOutput(io.Discard)
			var bb bytes.Buffer
			encoder := json.NewEncoder(&bb)
			exportPlugin := &export{
				viper:         viper.New(),
				enabled:       true,
				encoder:       encoder,
				denylist:      []filters.FilterFunc{},
				allowlist:     []filters.FilterFunc{},
				logger:        log,
				formatVersion: formatVersionV1,
			}
			exportPlugin.rateLimiter = newRateLimiter(50*time.Millisecond, tt.rateLimit, exportPlugin)
			reportInterval := 100 * time.Millisecond
			for i := 0; i < tt.totalFlows; i++ {
				stop, err := exportPlugin.OnDecodedFlow(context.Background(), &flow.Flow{})
				assert.False(t, stop)
				assert.NoError(t, err)
			}
			// wait for ~2 report intervals to make sure we get a rate-limit-info event
			time.Sleep(2 * reportInterval)
			exportPlugin.rateLimiter.stop()

			checkEvents(t, bb.Bytes(), tt.wantFlows, tt.wantRateLimitInfo, tt.wantDropped)
		})
	}
}
