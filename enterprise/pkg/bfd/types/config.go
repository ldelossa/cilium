//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package types

import "github.com/spf13/pflag"

// BFDConfig holds configuration options of the BFD subsystem.
type BFDConfig struct {
	BFDEnabled bool `mapstructure:"enable-bfd"`
}

// Flags implements cell.Flagger interface to register the configuration options as command-line flags.
func (cfg BFDConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-bfd", cfg.BFDEnabled, "Enables BFD subsystem")
}

var DefaultConfig = BFDConfig{
	BFDEnabled: false,
}
