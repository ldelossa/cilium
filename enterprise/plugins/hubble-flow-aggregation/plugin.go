// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package aggregation

import (
	"context"

	"github.com/jonboulle/clockwork"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/enterprise/plugins"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/aggregator"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	// validate interface conformity
	_ plugins.Init          = New
	_ plugins.ServerOptions = (*flowAggregationPlugin)(nil)
	_ Plugin                = (*flowAggregationPlugin)(nil)
)

type Plugin interface {
	GetFlowAggregator() aggregator.FlowAggregator
}

type flowAggregationPlugin struct {
	flowAggregator aggregator.FlowAggregator
}

// New returns a new flow aggregation plugin
func New(_ *viper.Viper) (plugins.Instance, error) {
	logger := logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-flow-aggregation")
	clock := clockwork.NewRealClock()
	return &flowAggregationPlugin{
		flowAggregator: aggregator.NewFlowAggregator(clock, logger),
	}, nil
}

func (p *flowAggregationPlugin) ServerOptions() []observeroption.Option {
	return []observeroption.Option{
		observeroption.WithOnFlowDelivery(p),
		observeroption.WithOnGetFlows(p),
	}
}

func (p *flowAggregationPlugin) OnGetFlows(ctx context.Context, req *observer.GetFlowsRequest) (context.Context, error) {
	return p.flowAggregator.OnGetFlows(ctx, req)
}

func (p *flowAggregationPlugin) OnFlowDelivery(ctx context.Context, f *flow.Flow) (bool, error) {
	return p.flowAggregator.OnFlowDelivery(ctx, f)
}

func (p *flowAggregationPlugin) GetFlowAggregator() aggregator.FlowAggregator {
	return p.flowAggregator
}
