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

package example

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/enterprise/pkg/features"
	"github.com/cilium/cilium/pkg/option"
)

type exampleFeatureConfig struct {
	// ExampleEnabled is the feature flag for the "example" feature, thus enabling the feature.
	// The 'cilium-feature-flag=<feature-id>' tag is used to mark this field as the feature flag
	// and specify what the feature ID is.
	//
	// This will only be used if the feature ID is declared in a cell.Feature() cell.
	ExampleEnabled bool `cilium-feature:"example" mapstructure:"example-enabled"`
}

func (def exampleFeatureConfig) Flags(flags *pflag.FlagSet) {
	flags.BoolVar(&def.ExampleEnabled, "example-enabled", def.ExampleEnabled, "Enable example feature")
}

var Cell = cell.Module(
	"example",
	"Example Feature",
	cell.Config(exampleFeatureConfig{
		ExampleEnabled: true, // feature flag with cilium-feature="example" tag.
	}),

	// Feature is a cell that registers a declared feature in the Hive.
	// Initially this will be used to perform feature flag checks.
	//
	// In this example, we have marked the ExampleEnabled var on exampleFeatureConfig
	// as being the feature-flag for the "example" feature.
	//
	// If this is enabled, then Hive will bail out when computing configuration as it will
	// check if the feature requires a feature gate to be enabled (currently we terminate
	// but the actual behavior when we crash is TBD).
	//
	// Down the line, we can also use declared Features cells to build a list of available
	// feature gates, similar to the Kubelet ones:
	// 	https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/#feature-gates-for-alpha-or-beta-features
	features.FeatureWithConfigT[exampleFeatureConfig](features.Spec{
		ID:          "example",
		Name:        "Example Feature",
		Description: "This here doohickey is an example feature.",
		Default:     false,
		Since:       features.Version{Major: 1, Minor: 14},
		Stage:       features.Alpha,
	}),

	// Here is an example of using the WithIsEnabledFn option to provide a custom
	// function to determine if the feature is enabled.
	//
	// This is useful for cases where the feature flag is not a single boolean value,
	// a composite of several values, or it is not feasible to modify the ConfigT struct
	// to add the feature tag (i.e. as with the legacy option.DaemonConfig type).
	features.FeatureWithConfigT[*option.DaemonConfig](features.Spec{
		ID:      "dual-stack",
		Name:    "Dual Stack IP",
		Default: false,
		Since:   features.Version{Major: 1, Minor: 14},
		Stage:   features.Alpha,
	}, features.WithIsEnabledFn(func(daemonConf *option.DaemonConfig) (bool, error) {
		return daemonConf.IPv4Enabled() && daemonConf.IPv6Enabled(), nil
	})),

	cell.Invoke(func(cfg exampleFeatureConfig) error {
		if !cfg.ExampleEnabled {
			return nil
		}
		return nil
	}),
)
