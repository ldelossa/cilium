// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package aggregator

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	wrappers "google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/enterprise/api/extensions"
	aggregationpb "github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/api/aggregation"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/chain"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/types"
)

type aggregatorContextKey struct{}

var (
	ctxKey = aggregatorContextKey{}

	_ FlowAggregator = (*flowAggregation)(nil)
)

type FlowAggregator interface {
	GetAggregationContext(
		aggregators []string,
		filters []string,
		ignoreSourcePort bool,
		ttl time.Duration,
		renewTTL bool) (context.Context, error)
	OnGetFlows(context.Context, *observer.GetFlowsRequest) (context.Context, error)
	OnFlowDelivery(context.Context, *flow.Flow) (bool, error)
}

func NewFlowAggregator(logger logrus.FieldLogger) FlowAggregator {
	return &flowAggregation{logger: logger}
}

type flowAggregation struct {
	logger logrus.FieldLogger
}

type aggregatorCtx struct {
	aggregator  types.Aggregator
	aggregation *aggregationpb.Aggregation
}

func extractAggregation(req *observer.GetFlowsRequest) (*aggregationpb.Aggregation, error) {
	ext := new(extensions.GetFlowsRequestExtension)
	if err := anypb.UnmarshalTo(req.Extensions, ext, proto.UnmarshalOptions{DiscardUnknown: true}); err != nil {
		return nil, err
	}
	if ext.Aggregation == nil {
		return nil, nil
	}
	return ext.Aggregation, nil
}

func (p *flowAggregation) OnGetFlows(ctx context.Context, req *observer.GetFlowsRequest) (context.Context, error) {
	if req.Extensions != nil {
		agg, err := extractAggregation(req)
		if err != nil {
			return nil, err
		}
		if agg == nil {
			return ctx, nil
		}
		newCtx, err := p.newContext(ctx, agg)
		if err != nil {
			return ctx, err
		}
		return newCtx, nil
	} else if req.Aggregation != nil { //nolint:staticcheck
		// If the request specifies the 'old' aggregation field (Cilium <= 1.15),
		// convert it to the extension based aggregation type
		newAggregators := make([]*aggregationpb.Aggregator, 0, len(req.Aggregation.Aggregators)) //nolint:staticcheck
		for _, ag := range req.Aggregation.Aggregators {                                         //nolint:staticcheck
			newAggregators = append(newAggregators, &aggregationpb.Aggregator{
				Type:             aggregationpb.AggregatorType(ag.Type),
				IgnoreSourcePort: ag.IgnoreSourcePort,
				Ttl:              ag.Ttl,
				RenewTtl:         ag.RenewTtl,
			})
		}
		agg := &aggregationpb.Aggregation{
			Aggregators:       newAggregators,
			StateChangeFilter: aggregationpb.StateChange(req.Aggregation.StateChangeFilter),
		}
		newCtx, err := p.newContext(ctx, agg)
		if err != nil {
			return ctx, err
		}
		return newCtx, nil
	}
	return ctx, nil
}

func (p *flowAggregation) newContext(ctx context.Context, agg *aggregationpb.Aggregation) (context.Context, error) {
	aggregator, err := ConfigureAggregator(agg.Aggregators)
	p.logger.Debugf("Configured flow aggregator %#v", aggregator)
	if err != nil {
		return ctx, err
	}

	if aggregator == nil {
		return ctx, nil
	}

	go aggregator.Start(ctx)

	return context.WithValue(ctx, ctxKey, &aggregatorCtx{
		aggregator:  aggregator,
		aggregation: agg,
	}), nil
}

func (p *flowAggregation) OnFlowDelivery(ctx context.Context, f *flow.Flow) (bool, error) {
	// Ideally Cilium shouldn't call OnFlowDelivery if the event is LostEvent, but it's better
	// to check if f is nil here to be safe anyways.
	//
	// https://github.com/cilium/cilium/blob/1.10.4/pkg/hubble/observer/local_observer.go#L319
	if f == nil {
		return false, nil
	}

	aggCtx, ok := ctx.Value(ctxKey).(*aggregatorCtx)
	if !ok {
		return false, nil
	}

	fmt.Printf("aggregation %#v\n", aggCtx.aggregation)
	fmt.Printf("aggregator %#v\n", aggCtx.aggregator)

	result := aggCtx.aggregator.Aggregate(&aggregation.AggregatableFlow{Flow: f})
	if result != nil && (result.StateChange&aggCtx.aggregation.StateChangeFilter) == 0 {
		return true, nil
	}

	return false, nil
}

// GetAggregationContext returns a context that can be used with OnFlowDelivery() to perform
// aggregation with the given configuration parameters.
func (p *flowAggregation) GetAggregationContext(
	aggregators []string,
	filters []string,
	ignoreSourcePort bool,
	ttl time.Duration,
	renewTTL bool) (context.Context, error) {
	agg, err := NewAggregation(aggregators, filters, ignoreSourcePort, ttl, renewTTL)
	if err != nil {
		return nil, err
	}
	return p.newContext(context.Background(), agg)
}

// ConfigureAggregator configures a set of aggregators as a chain
func ConfigureAggregator(aggregators []*aggregationpb.Aggregator) (types.Aggregator, error) {
	var as []types.Aggregator
	ttl := 30 * time.Second
	renewTTL := true

	for _, requestedAggregator := range aggregators {
		var a types.Aggregator
		if requestedAggregator.Ttl != nil {
			ttl = requestedAggregator.Ttl.AsDuration()
		}
		if requestedAggregator.RenewTtl != nil {
			renewTTL = requestedAggregator.RenewTtl.Value
		}

		switch requestedAggregator.Type {
		case aggregationpb.AggregatorType_connection:
			a = aggregation.NewConnectionAggregator(ttl, requestedAggregator.IgnoreSourcePort, renewTTL)
		case aggregationpb.AggregatorType_identity:
			a = aggregation.NewIdentityAggregator(ttl, renewTTL)
		default:
			return nil, fmt.Errorf("unknown aggregator: %d", requestedAggregator.Type)
		}

		as = append(as, a)
	}

	switch len(as) {
	case 0:
		return nil, nil
	case 1:
		return as[0], nil
	default:
		return chain.NewAggregationChain(as), nil
	}
}

func NewAggregation(
	aggregators []string,
	filters []string,
	ignoreSourcePort bool,
	ttl time.Duration,
	renewTTL bool) (*aggregationpb.Aggregation, error) {
	agg := aggregationpb.Aggregation{}
	if len(aggregators) > 0 {
		for _, f := range filters {
			v, ok := aggregationpb.StateChange_value[f]
			if !ok {
				return nil, fmt.Errorf("unknown state change: %s", f)
			}
			agg.StateChangeFilter |= aggregationpb.StateChange(v)
		}
		for _, a := range aggregators {
			t, ok := aggregationpb.AggregatorType_value[a]
			if !ok {
				return nil, fmt.Errorf("unknown aggregator: %s", a)
			}
			agg.Aggregators = append(agg.Aggregators, &aggregationpb.Aggregator{
				Type:             aggregationpb.AggregatorType(t),
				IgnoreSourcePort: ignoreSourcePort,
				Ttl:              durationpb.New(ttl),
				RenewTtl:         &wrappers.BoolValue{Value: renewTTL},
			})
		}
	}
	return &agg, nil
}
