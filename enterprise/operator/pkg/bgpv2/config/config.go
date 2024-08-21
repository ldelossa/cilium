// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package config

import (
	"github.com/spf13/pflag"
)

const (
	// enterpriseBGPEnabled is the name of the flag to enable the SRv6 locator pool.
	enterpriseBGPEnabled = "enable-enterprise-bgp-control-plane"
)

// Config parameters for enterprise BGP.
type Config struct {
	Enabled bool `mapstructure:"enable-enterprise-bgp-control-plane"`
}

// Flags implements cell.Flagger interface.
func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(enterpriseBGPEnabled, cfg.Enabled, "Enable enterprise BGP in Cilium")
}

var DefaultConfig = Config{
	Enabled: false,
}
