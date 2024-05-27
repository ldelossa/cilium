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
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/enterprise/plugins"
	aggregation "github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/aggregator"
	"github.com/cilium/cilium/pkg/hubble/filters"
	metricsAPI "github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type export struct {
	viper              *viper.Viper
	encoder            *json.Encoder
	denylist           filters.FilterFuncs
	allowlist          filters.FilterFuncs
	logger             logrus.FieldLogger
	flowAggregator     aggregator.FlowAggregator
	aggregationContext context.Context
	formatVersion      string
	enabled            bool
	rateLimiter        *rateLimiter
	nodeName           string
	metricsHandler     *metricsHandler
}

var (
	_ plugins.Init        = New
	_ plugins.Flags       = (*export)(nil)
	_ plugins.DepAcceptor = (*export)(nil)
	_ metricsAPI.Handler  = (*metricsHandler)(nil)
)

type Plugin interface {
	exportFlow(ctx context.Context, f *flowpb.Flow) error
}

func New(vp *viper.Viper) (plugins.Instance, error) {
	// Actual initialization of the struct is done in OnServerInit after
	// command line parameters parsing is done except for the logger and metrics plugin registration.
	e := &export{
		viper:  vp,
		logger: logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-flow-export"),
	}

	// Must be done early so that metrics get registered before the launchHubble
	// starts
	metricsAPI.DefaultRegistry().Register("flow_export", e)
	return e, nil
}

func (e *export) AddAgentFlags() *pflag.FlagSet {
	fs := &pflag.FlagSet{}
	fs.String(exportFilePath, "/var/run/cilium/hubble/hubble.log",
		"Absolute path of the export file location. An empty string disables the flow export")
	fs.Int(exportFileMaxSize, 100, "Maximum size of the file in megabytes")
	fs.Duration("export-file-rotation-interval", 0,
		"Interval at which to rotate JSON export files in addition to rotating them by size")
	fs.Int(exportFileMaxBackups, 3, "Number of rotated files to keep")
	fs.Bool(exportFileCompress, true, "Compress rotated files")
	fs.String(exportFlowWhitelist, "", "Whitelist filters for flows")
	fs.String(exportFlowBlacklist, "", "Blacklist filters for flows")
	fs.MarkHidden(exportFlowWhitelist)
	fs.MarkHidden(exportFlowBlacklist)
	fs.String(exportFlowAllowlist, "", "Allowlist filters for flows")
	fs.String(exportFlowDenylist, "", "Denylist filters for flows")
	fs.String(exportFormatVersion, formatVersionV1, "Default to v1 format. Set to '' to use the legacy format")
	fs.Int(exportRateLimit, -1, "Rate limit (per minute) for flow exports. Set to -1 to disable")
	fs.String(exportNodeName, "", "Override the node_name field in exported flows")
	if e.flowAggregator != nil {
		fs.StringSlice(exportAggregation, []string{},
			"Perform aggregation pre-storage ('connection', 'identity')")
		fs.Bool(exportAggregationIgnoreSourcePort, true, "Ignore source port during aggregation")
		fs.Bool(exportAggregationRenewTTL, true, "Renew flow TTL when a new flow is observed")
		fs.StringSlice(exportAggregationStateFilter, []string{"new", "error", "closed"},
			"The state changes to include while aggregating ('new', 'established', 'first_error', 'error', 'closed')")
		fs.Duration(exportAggregationTTL, 30*time.Second, "TTL for flow aggregation")
	}
	return fs
}

func buildFilterFuncs(log logrus.FieldLogger, f string) (filters.FilterFuncs, error) {
	filterFuncs, err := parseFilterList(f)
	if err != nil {
		return nil, err
	}
	return filters.BuildFilterList(context.Background(), filterFuncs, filters.DefaultFilters(log))
}

func parseFilterList(filters string) ([]*flowpb.FlowFilter, error) {
	dec := json.NewDecoder(strings.NewReader(filters))
	var results []*flowpb.FlowFilter
	for {
		var result flowpb.FlowFilter
		if err := dec.Decode(&result); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		results = append(results, &result)
	}
	return results, nil
}

// AcceptDeps is used to check if the aggregation plugin is enabled.
func (e *export) AcceptDeps(list plugins.Instances) error {
	for _, instance := range list {
		if agg, ok := instance.(aggregation.Plugin); ok {
			e.flowAggregator = agg.GetFlowAggregator()
		}
	}
	return nil
}