// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconciler

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// bgpServiceHealthCheckingFlag is the name of the flag that enables BGP integration with service health-checking
	bgpServiceHealthCheckingFlag = "enable-bgp-svc-health-checking"
)

// log is the logger used by the reconcilers
var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "enterprise-bgp-control-plane")

// Config holds configuration options of the enterprise reconcilers.
type Config struct {
	SvcHealthCheckingEnabled bool `mapstructure:"enable-bgp-svc-health-checking"`
}

// Flags implements cell.Flagger interface to register the configuration options as command-line flags.
func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(bgpServiceHealthCheckingFlag, cfg.SvcHealthCheckingEnabled, "Enables BGP integration with service health-checking")
}
