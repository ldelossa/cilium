// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

import (
	"context"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
)

// HealthUpdateSvcInfo contains service-related information used in the health update callback.
type HealthUpdateSvcInfo struct {
	Name    lb.ServiceName
	Addr    lb.L3n4Addr
	SvcType lb.SVCType
}

// HealthUpdateCallback is a callback function used to notify subscribers about service health updates.
type HealthUpdateCallback func(svcInfo HealthUpdateSvcInfo, activeBackends []lb.Backend)

// HealthCheckSubscriber provides an interface for subscribing to service health updates.
// This interface should be implemented by pkg/service at a later stage.
type HealthCheckSubscriber interface {
	// Subscribe allows subscribing to service health check related events.
	// The subscriber will receive updates on the callback as long as the passed
	// context is not done.
	Subscribe(ctx context.Context, callback HealthUpdateCallback)
}
