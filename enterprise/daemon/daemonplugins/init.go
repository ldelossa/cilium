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

package daemonplugins

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/enterprise/plugins"
	aggregation "github.com/cilium/cilium/enterprise/plugins/hubble-flow-aggregation"
	export "github.com/cilium/cilium/enterprise/plugins/hubble-flow-export"
	"github.com/cilium/cilium/pkg/hubble/observer"
	"github.com/cilium/cilium/pkg/option"
)

var DefaultPlugins = []plugins.Init{
	aggregation.New,
	export.New,
}

// Initialize a list of plugins from their initializers.
func Initialize(vp *viper.Viper, inits []plugins.Init) (plugins.Instances, error) {
	var res plugins.Instances

	for _, i := range inits {
		inst, err := i(vp)
		if err != nil {
			return nil, fmt.Errorf("failed to call plugin init: %w", err)
		}
		res = append(res, inst)
	}

	if err := InjectDependencies(res); err != nil {
		return nil, fmt.Errorf("failed to inject deps: %w", err)
	}

	return res, nil
}

// AddFlags to the root cilium-agent command.
func AddFlags(vp *viper.Viper, root *cobra.Command, list plugins.Instances) error {
	for _, i := range list {
		if adder, ok := i.(plugins.Flags); ok {
			fs := adder.AddAgentFlags()

			// iterate over all the flags, and add them to the actual root
			// command set.
			fs.VisitAll(func(f *pflag.Flag) {
				root.Flags().AddFlag(f)

				if !f.Hidden {
					option.BindEnv(vp, f.Name)
				}

				// Pick up the setting from viper if it's set.
				if vp.IsSet(f.Name) && vp.GetString(f.Name) != "" {
					if err := root.Flags().Set(f.Name, vp.GetString(f.Name)); err != nil {
						log.Fatalf("failed to set %s from viper: %s", f.Name, err)
					}
				}
			})
		}
	}

	// re-bind pflags to viper after all the plugins had a go
	if err := vp.BindPFlags(root.Flags()); err != nil {
		return fmt.Errorf("failed to bind pflags to viper: %w", err)
	}

	return nil
}

// AddServerOptions includes all the options from the list of plugins.
func AddServerOptions(list plugins.Instances) error {
	for _, i := range list {
		if so, ok := i.(plugins.ServerOptions); ok {
			observer.DefaultOptions = append(
				observer.DefaultOptions,
				so.ServerOptions()...,
			)
		}
	}

	return nil
}

// InjectDependencies into the plugins.
//
// After the list of plugins got initialized, each plugin is able to look at
// what else is available in the build and accept dependencies to modify it's
// behavior.
func InjectDependencies(list plugins.Instances) error {
	for _, i := range list {
		if da, ok := i.(plugins.DepAcceptor); ok {
			if err := da.AcceptDeps(list); err != nil {
				return fmt.Errorf("failed to inject deps: %w", err)
			}
		}
	}

	return nil
}
