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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

func Test_export_OnDecodedFlow(t *testing.T) {
	tests := []struct {
		name          string
		enabled       bool
		flows         []*flow.Flow
		formatVersion string
		nodeName      string
		expected      string
		expectedCount float64
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := logrus.New()
			log.SetOutput(io.Discard)
			var sb strings.Builder
			encoder := json.NewEncoder(&sb)
			exportPlugin := &export{
				enabled:            tt.enabled,
				viper:              viper.New(),
				encoder:            encoder,
				denylist:           []filters.FilterFunc{},
				allowlist:          []filters.FilterFunc{},
				logger:             log,
				aggregationContext: context.Background(),
				formatVersion:      tt.formatVersion,
				nodeName:           tt.nodeName,
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

func Test_export_exportFlowOverrideNodeName(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	var bb bytes.Buffer
	encoder := json.NewEncoder(&bb)
	exportPlugin := &export{
		viper:         viper.New(),
		enabled:       true,
		encoder:       encoder,
		logger:        log,
		formatVersion: formatVersionV1,
		nodeName:      "new-node-name",
	}
	expected := `{"flow":{},"node_name":"new-node-name"}`
	assert.NoError(t, exportPlugin.exportFlow(context.Background(), &flow.Flow{}))
	assert.Equal(t, expected+"\n", bb.String())
}
