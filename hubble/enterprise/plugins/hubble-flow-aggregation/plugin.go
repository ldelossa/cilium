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
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/enterprise/api/extensions"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/aggregator"
	aggregationpb "github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/api/aggregation"
	"github.com/cilium/cilium/hubble/cmd/common/conn"
	"github.com/cilium/cilium/hubble/cmd/common/validate"
	"github.com/cilium/cilium/hubble/enterprise/plugins"
)

var (
	_ plugins.Instance = New
	_ plugins.AddFlags = &plugin{}
)

type plugin struct{}

// NewCLIPlugin returns a plugin which adds the aggregation flags to hubble CLI
func New() (plugins.Instance, error) {
	p := &plugin{}
	conn.GRPCOptionFuncs = append(conn.GRPCOptionFuncs, grpcOptionClientInterceptor)
	validate.FlagFuncs = append(validate.FlagFuncs, validateAggregationFlags)
	return p, nil
}

func (p *plugin) AddFlags() []plugins.FlagsInit {
	return []plugins.FlagsInit{
		p.aggregationFlags,
	}
}

func (*plugin) aggregationFlags() (fs *pflag.FlagSet, args []string, persistent bool, err error) {
	args = []string{"hubble", "observe"}
	fs = pflag.NewFlagSet("aggregation", pflag.ContinueOnError)
	fs.StringSlice("aggregate", nil, "Apply aggregation logic before returning list of flows. Valid options: identity and connection.")
	fs.StringSlice("aggregation-state-filter",
		[]string{"new", "first_error", "error", "closed"},
		"The state changes to include while aggregating")
	fs.Bool("aggregate-ignore-source-port", false, "Ignore source port when aggregating.")
	fs.Duration("aggregation-ttl", 0, "TTL to use when aggregating. Set to 0 to only see a flow once for each state change, or non-zero to see non-state changes periodically.")
	return
}

func validateAggregationFlags(_ *cobra.Command, vp *viper.Viper) error {
	aggregators := vp.GetStringSlice("aggregate")
	stateFilters := vp.GetStringSlice("aggregation-state-filter")
	ignoreSourcePort := vp.GetBool("aggregate-ignore-source-port")
	aggregationTTL := vp.GetDuration("aggregation-ttl")
	_, err := aggregator.NewAggregation(aggregators, stateFilters, ignoreSourcePort, aggregationTTL, false)
	return err
}

func grpcOptionClientInterceptor(vp *viper.Viper) (grpc.DialOption, error) {
	return grpc.WithStreamInterceptor(grpcStreamClientInterceptor(vp)), nil
}

func grpcStreamClientInterceptor(vp *viper.Viper) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		stream, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil {
			return nil, err
		}

		//nolint:gocritic
		switch method {
		case "/observer.Observer/GetFlows":
			aggregators := vp.GetStringSlice("aggregate")
			stateFilters := vp.GetStringSlice("aggregation-state-filter")
			ignoreSourcePort := vp.GetBool("aggregate-ignore-source-port")
			aggregationTTL := vp.GetDuration("aggregation-ttl")
			if len(aggregators) == 0 {
				return stream, nil
			}
			agg, err := aggregator.NewAggregation(aggregators, stateFilters, ignoreSourcePort, aggregationTTL, false)
			if err != nil {
				return nil, err
			}
			return &clientStream{ClientStream: stream, aggregation: agg}, nil
		}

		return stream, nil
	}
}

type clientStream struct {
	grpc.ClientStream
	aggregation *aggregationpb.Aggregation
}

func (s *clientStream) SendMsg(m interface{}) error {
	getFlowsReq, ok := m.(*observerpb.GetFlowsRequest)
	if ok {
		// Configure the GetFlowsRequest.Extensions
		ext, err := anypb.New(&extensions.GetFlowsRequestExtension{
			Aggregation: s.aggregation,
		})
		if err != nil {
			return fmt.Errorf("error creating GetFlowsRequestExtension: %w", err)
		}
		getFlowsReq.Extensions = ext

		// Convert the aggregationpb.Aggregation to an observerpb.Aggregation and
		// set the deprecated GetFlowsRequest.Aggregation for backwards
		// compatibility.
		getFlowsReq.Aggregation = convertToObserverAggregation(s.aggregation) //nolint:staticcheck
	}
	return s.ClientStream.SendMsg(m)
}

func convertToObserverAggregation(agg *aggregationpb.Aggregation) *observerpb.Aggregation { //nolint:staticcheck
	newAggregators := make([]*observerpb.Aggregator, 0, len(agg.GetAggregators())) //nolint:staticcheck
	for _, ag := range agg.GetAggregators() {                                      //nolint:staticcheck
		newAggregators = append(newAggregators, &observerpb.Aggregator{
			Type:             observerpb.AggregatorType(ag.GetType()), //nolint:staticcheck
			IgnoreSourcePort: ag.GetIgnoreSourcePort(),
			Ttl:              ag.GetTtl(),
			RenewTtl:         ag.GetRenewTtl(),
		})
	}
	return &observerpb.Aggregation{ //nolint:staticcheck
		Aggregators:       newAggregators,
		StateChangeFilter: observerpb.StateChange(agg.GetStateChangeFilter()), //nolint:staticcheck
	}
}
