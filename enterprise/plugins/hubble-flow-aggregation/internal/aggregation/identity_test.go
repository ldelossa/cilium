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
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
	aggregationpb "github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/api/aggregation"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/aggregation/types"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/cache"
	"github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation/internal/testflow"
)

func TestIdentityggregation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ia := NewIdentityAggregator(clockwork.NewFakeClock(), 10*time.Second, true)
	go ia.Start(ctx)
	defer cancel()
	r := ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		Destination: testflow.Peer{Identity: []byte("svc2"), Port: 22},
		FlowState:   types.FlowState{ConnectionRequest: true},
	})
	assert.True(t, r.StateChange == aggregationpb.StateChange_new|aggregationpb.StateChange_established)

	r = ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc2"), Port: 22},
		Destination: testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		FlowState:   types.FlowState{ConnectionRequest: true},
		Reply:       true,
	})
	assert.True(t, r.StateChange == aggregationpb.StateChange_first_reply)
	assert.True(t, r.Reply)

	r = ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		Destination: testflow.Peer{Identity: []byte("svc2"), Port: 22},
		FlowState:   types.FlowState{Error: true},
	})
	assert.True(t, r.StateChange == aggregationpb.StateChange_first_error)

	r = ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		Destination: testflow.Peer{Identity: []byte("svc2"), Port: 22},
		FlowState:   types.FlowState{Error: true},
	})
	assert.True(t, r.StateChange == aggregationpb.StateChange_error)

	r = ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc2"), Port: 22},
		Destination: testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		Reply:       true,
	})
	assert.True(t, r.StateChange == aggregationpb.StateChange_unspec)

	// Different identity
	r = ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc3"), Port: 2222},
		Destination: testflow.Peer{Identity: []byte("svc4"), Port: 1000},
	})
	assert.True(t, r.StateChange == aggregationpb.StateChange_new|aggregationpb.StateChange_established)

	// Different identity reply
	r = ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc4"), Port: 1000},
		Destination: testflow.Peer{Identity: []byte("svc3"), Port: 2222},
		Reply:       true,
	})
	assert.True(t, r.StateChange == aggregationpb.StateChange_first_reply)
	assert.True(t, r.Reply)

	// Different destination port, different flow
	r = ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		Destination: testflow.Peer{Identity: []byte("svc2"), Port: 2222},
		FlowState:   types.FlowState{ConnectionRequest: true},
	})
	assert.True(t, r.StateChange == aggregationpb.StateChange_new|aggregationpb.StateChange_established)

	// Different source port, same flow
	r = ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc1"), Port: 2000},
		Destination: testflow.Peer{Identity: []byte("svc2"), Port: 22},
		FlowState:   types.FlowState{ConnectionRequest: true},
	})
	assert.True(t, r.StateChange == aggregationpb.StateChange_unspec)

	// Different source port, same flow
	r = ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc2"), Port: 22},
		Destination: testflow.Peer{Identity: []byte("svc1"), Port: 2000},
		FlowState:   types.FlowState{ConnectionRequest: true},
		Reply:       true,
	})
	assert.True(t, r.StateChange == aggregationpb.StateChange_unspec)

	// Different verdict -> different flow
	r = ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		Destination: testflow.Peer{Identity: []byte("svc2"), Port: 22},
		VerdictStr:  "20",
		FlowState:   types.FlowState{ConnectionRequest: true},
	})
	assert.True(t, r.StateChange == aggregationpb.StateChange_new|aggregationpb.StateChange_established)

	r = ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		Destination: testflow.Peer{Identity: []byte("svc2"), Port: 22},
		FlowState:   types.FlowState{CloseRequest: true},
	})
	assert.True(t, r.StateChange == aggregationpb.StateChange_unspec)

	r = ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc2"), Port: 22},
		Destination: testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		FlowState:   types.FlowState{CloseRequest: true},
		Reply:       true,
	})
	assert.True(t, r.StateChange == aggregationpb.StateChange_unspec)

	af := ia.Cache().Lookup(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		Destination: testflow.Peer{Identity: []byte("svc2"), Port: 22},
	})

	assert.True(t, af.Stats.Forward.NumFlows == 5)
	assert.True(t, af.Stats.Reply.NumFlows == 4)
	assert.True(t, af.Stats.Reply.CloseRequests == 1)
	assert.True(t, af.Stats.Forward.CloseRequests == 1)
}

func TestHTTPAggregation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ia := NewIdentityAggregator(clockwork.NewFakeClock(), 10*time.Second, true)
	go ia.Start(ctx)
	defer cancel()
	r := ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		Destination: testflow.Peer{Identity: []byte("svc2"), Port: 80},
		FlowState:   types.FlowState{ConnectionRequest: true},
		L7Data: &types.L7Flow{
			HTTP: &flow.HTTP{
				Method: "GET",
				Url:    "/path",
			},
		},
	})
	assert.True(t, r.StateChange == aggregationpb.StateChange_new|aggregationpb.StateChange_established)

	// Same HTTP request parameters, aggregation should happen
	r = ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		Destination: testflow.Peer{Identity: []byte("svc2"), Port: 80},
		L7Data: &types.L7Flow{
			HTTP: &flow.HTTP{
				Method: "GET",
				Url:    "/path",
			},
		},
	})
	assert.True(t, r.StateChange == aggregationpb.StateChange_unspec)

	// Different HTTP path
	r = ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		Destination: testflow.Peer{Identity: []byte("svc2"), Port: 80},
		FlowState:   types.FlowState{ConnectionRequest: true},
		L7Data: &types.L7Flow{
			HTTP: &flow.HTTP{
				Method: "GET",
				Url:    "/path2",
			},
		},
	})

	assert.True(t, r.StateChange == aggregationpb.StateChange_new|aggregationpb.StateChange_established)

	// Different L7 protocol on same port
	r = ia.Aggregate(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		Destination: testflow.Peer{Identity: []byte("svc2"), Port: 80},
		FlowState:   types.FlowState{ConnectionRequest: true},
		L7Data: &types.L7Flow{
			Kafka: &flow.Kafka{},
		},
	})
	assert.True(t, r.StateChange == aggregationpb.StateChange_new|aggregationpb.StateChange_established)

	af := ia.Cache().Lookup(&testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		Destination: testflow.Peer{Identity: []byte("svc2"), Port: 80},
		L7Data: &types.L7Flow{
			HTTP: &flow.HTTP{
				Method: "GET",
				Url:    "/path",
			},
		},
	})

	assert.True(t, af.Stats.Forward.NumFlows == 2)
	assert.True(t, af.Stats.Forward.CloseRequests == 0)
}

func TestExpiredFlows(t *testing.T) {
	clock := clockwork.NewFakeClock()
	// Not starting the aggregator so no GC
	ia := NewAggregator(clock, cache.Configuration{
		CompareFunc:   identityCompareFunc,
		HashFunc:      identityHashFunc,
		AggregateFunc: aggregateIdentity,
		Expiration:    500 * time.Millisecond,
	})
	f1 := testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		Destination: testflow.Peer{Identity: []byte("svc2"), Port: 80},
		FlowState:   types.FlowState{ConnectionRequest: true},
		L7Data: &types.L7Flow{
			HTTP: &flow.HTTP{
				Method: "GET",
				Url:    "/path",
			},
		},
	}
	// The first flow. It should be considered 'new'.
	r := ia.Aggregate(&f1)
	assert.Equal(t, aggregationpb.StateChange_new|aggregationpb.StateChange_established, r.StateChange)

	// Sorry for sleeping...
	clock.Advance(1 * time.Second)

	// The first flow has expired. The next flow should be considered 'new' again.
	r = ia.Aggregate(&f1)
	assert.Equal(t, aggregationpb.StateChange_new|aggregationpb.StateChange_established, r.StateChange)

	// A subsequent flow shouldn't have any state change since the flow is now in the cache again.
	r = ia.Aggregate(&f1)
	assert.Equal(t, aggregationpb.StateChange_unspec, r.StateChange)
}

func TestIdentityExpiration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clock := clockwork.NewFakeClock()
	ia := NewIdentityAggregator(clock, 1*time.Second, false)
	go ia.Start(ctx)
	defer cancel()
	f := testflow.Flow{
		Source:      testflow.Peer{Identity: []byte("svc1"), Port: 1000},
		Destination: testflow.Peer{Identity: []byte("svc2"), Port: 22},
		ProtocolStr: "TCP",
	}

	// The first flow shows up. The identity aggregator sets "new" and "established" state change
	// flag. The "new" flag matches the default state change filter, which causes the initial flow
	// to be included in the GetFlows() response.
	result := ia.Aggregate(&f)
	assert.Equal(t, aggregationpb.StateChange_new|aggregationpb.StateChange_established, result.StateChange)

	// A subsequent flow shouldn't have any state change since the flow is now in the cache again.
	result = ia.Aggregate(&f)
	assert.Equal(t, aggregationpb.StateChange_unspec, result.StateChange)

	// Expire the flow by advancing the clock
	clock.Advance(2 * time.Second)

	// Subsequent aggregations don't set any state change flag until the flow expires from
	// the aggregation cache. Flows without any state change flags don't get included in
	// the GetFlows() response.
	result = ia.Aggregate(&f)
	// The flow expires after 1 second, and the next flow gets the "new" and "established" flags again.
	assert.Equal(t, aggregationpb.StateChange_new|aggregationpb.StateChange_established, result.StateChange)
}
