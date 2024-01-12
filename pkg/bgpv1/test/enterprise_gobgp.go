// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package test

import (
	"context"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

// GoBGPInstance is an interface of a test gobgp instance.
type GoBGPInstance interface {
	WaitForSessionState(ctx context.Context, expectedStates []string) error
	GetRouteEvents(ctx context.Context, numExpectedEvents int) ([]RouteEvent, error)
}

// RouteEvent contains information about new event in routing table of a gobgp instance
type RouteEvent struct {
	SourceASN           uint32
	Prefix              string
	PrefixLen           uint8
	IsWithdrawn         bool
	ExtraPathAttributes []bgp.PathAttributeInterface // non-standard path attributes (other than Origin / ASPath / NextHop / MpReachNLRI)
}

// WaitForSessionState consumes state changes from the gobgp instance and compares it with expected states
func (g *goBGP) WaitForSessionState(ctx context.Context, expectedStates []string) error {
	return g.waitForSessionState(ctx, expectedStates)
}

// GetRouteEvents drains number of events from the gobgp instance and returns those events to caller.
func (g *goBGP) GetRouteEvents(ctx context.Context, numExpectedEvents int) ([]RouteEvent, error) {
	events, err := g.getRouteEvents(ctx, numExpectedEvents)

	res := make([]RouteEvent, len(events))
	for i, e := range events {
		res[i] = RouteEvent{
			SourceASN:           e.sourceASN,
			Prefix:              e.prefix,
			PrefixLen:           e.prefixLen,
			IsWithdrawn:         e.isWithdrawn,
			ExtraPathAttributes: e.extraPathAttributes,
		}
	}
	return res, err
}
