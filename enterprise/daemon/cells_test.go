//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/cilium/cilium/daemon/cmd"
	"github.com/cilium/cilium/enterprise/pkg/features"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

var goleakOptions = []goleak.Option{
	// Ignore all the currently running goroutines spawned
	// by prior tests or by package init() functions (like the
	// client-go logger).
	goleak.IgnoreCurrent(),
	// Ignore goroutines started by the policy trifecta, see [newPolicyTrifecta].
	goleak.IgnoreTopFunction("github.com/cilium/cilium/pkg/identity/cache.(*identityWatcher).watch.func1"),
	goleak.IgnoreTopFunction("github.com/cilium/cilium/pkg/trigger.(*Trigger).waiter"),
	// Ignore goroutine started by the ipset reconciler rate limiter
	goleak.IgnoreTopFunction("github.com/cilium/cilium/pkg/rate.NewLimiter.func1"),
}

// TestEnterpriseAgentCell verifies that the EnterpriseAgent can be instantiated with
// default configuration and thus the EnterpriseAgent hive can be inspected with
// the hive commands and documentation can be generated from it.
func TestEnterpriseAgentCell(t *testing.T) {
	defer goleak.VerifyNone(t, goleakOptions...)
	defer metrics.Reinitialize()

	logging.SetLogLevelToDebug()
	// Populate config with default values normally set by Viper flag defaults
	option.Config.IPv4ServiceRange = cmd.AutoCIDR
	option.Config.IPv6ServiceRange = cmd.AutoCIDR

	h := hive.New(EnterpriseAgent)
	hive.AddConfigOverride(h, func(c *features.FeatureGatesConfig) {
		c.FeatureGates = append(c.FeatureGates, features.AllowAll...)
	})
	err := h.Populate(hivetest.Logger(t))
	require.NoError(t, err, "hive.New(EnterpriseAgent).Populate()")
}
