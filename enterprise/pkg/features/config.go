//nolint:goheader
// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package features

import (
	"github.com/spf13/pflag"
)

// FeatureGateConfig is the configuration for the feature gates.
type FeatureGatesConfig struct {
	FeatureGates []string `mapstructure:"feature-gates"`
}

func (c FeatureGatesConfig) Flags(flags *pflag.FlagSet) {
	flags.StringSlice("feature-gates", c.FeatureGates, "Slice of alpha features to enable, passing AllAlpha, AllBeta, AllLimited enables all alpha, beta and limited features (respectively).")
}
