// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

// Ensure build fails on versions of Go that are not supported by Hubble.
// This build tag should be kept in sync with the version specified in go.mod.
//go:build go1.18

package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	htemplate "github.com/cilium/cilium/hubble/cmd/common/template"
	"github.com/cilium/cilium/hubble/enterprise/plugins"
	aggregation "github.com/cilium/cilium/hubble/enterprise/plugins/hubble-flow-aggregation"
	login "github.com/cilium/cilium/hubble/enterprise/plugins/hubble-login"
)

func runCommandPlugins(cmd *cobra.Command, vp *viper.Viper) error {
	cmdInits := []plugins.Init{
		login.New,
		aggregation.New,
	}

	var instances []plugins.Instance
	for _, pinit := range cmdInits {
		instance, err := pinit()
		if err != nil {
			return fmt.Errorf("failed to initialize hubble plugin: %w", err)
		}
		instances = append(instances, instance)
	}

	err := AddCommands(cmd, vp, instances)
	if err != nil {
		return fmt.Errorf("error adding commands from plugins: %w", err)
	}
	err = AddFlags(cmd, vp, instances)
	if err != nil {
		return fmt.Errorf("error adding flags from plugins: %w", err)
	}
	return nil
}

// AddCommands is a helper function for the hubble generated code which takes a
// list of all hubble plugin instances and will include new sub-commands for
// plugins that implement the `hubble.AddCommands` interface.
//
// Your IDE may show this function as unused, but don't be fooled. This function
// is definitely used from the hubble generated hooks.
func AddCommands(
	cmd *cobra.Command,
	vp *viper.Viper,
	instances []plugins.Instance,
) error {
	for _, p := range instances {
		if cmdAdd, ok := p.(plugins.AddCommands); ok {
			for _, add := range cmdAdd.AddCommands() {
				sub, err := add(vp)
				if err != nil {
					return err
				}

				cmd.AddCommand(sub)
			}
		}
	}

	return nil
}

// AddFlags is a helper function for the hubble generated code which takes a
// list of all hubble plugin instances and will include new flags for
// plugins that implement the `plugins.AddFlags` interface.
//
// Your IDE may show this function as unused, but don't be fooled. This function
// is definitely used from the hubble generated hooks.
func AddFlags(
	rootCmd *cobra.Command,
	vp *viper.Viper,
	instances []plugins.Instance,
) error {
	for _, p := range instances {
		if flagsAdder, ok := p.(plugins.AddFlags); ok {
			for _, add := range flagsAdder.AddFlags() {
				newFlags, args, persistent, err := add()
				if err != nil {
					return err
				}

				cmd, err := findCommand(rootCmd, args)
				if err != nil {
					return err
				}

				if persistent {
					if err := checkFlagDuplicates(newFlags, cmd); err != nil {
						return err
					}
					cmd.PersistentFlags().AddFlagSet(newFlags)
					err = visitCommands(cmd, func(c *cobra.Command) error {
						if err := checkFlagDuplicates(newFlags, c); err != nil {
							return err
						}
						// Add the flags to the hubble --help for each child command
						htemplate.RegisterFlagSets(c, newFlags)
						return nil
					})
					if err != nil {
						return err
					}
				} else {
					if err := checkFlagDuplicates(newFlags, cmd); err != nil {
						return err
					}

					cmd.Flags().AddFlagSet(newFlags)
					// Add the flags to hubble --help for just the command configured
					htemplate.RegisterFlagSets(cmd, newFlags)
				}
				err = vp.BindPFlags(newFlags)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// checkFlagDuplicates verifies newFlags do not already exist in cmd's flags
func checkFlagDuplicates(newFlags *pflag.FlagSet, cmd *cobra.Command) error {
	var errs []error
	newFlags.VisitAll(func(f *pflag.Flag) {
		if cmd.Flags().Lookup(f.Name) != nil {
			err := fmt.Errorf("flag %s already defined for command %s", f.Name, cmd.Name())
			errs = append(errs, err)
			return
		}
	})
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	return nil
}

// visitCommands runs f on the cobra.Command specified, and recursively against
// all sub-commands
func visitCommands(cmd *cobra.Command, f func(*cobra.Command) error) error {
	if err := f(cmd); err != nil {
		return err
	}
	for _, subCmd := range cmd.Commands() {
		if err := visitCommands(subCmd, f); err != nil {
			return err
		}
	}
	return nil
}

// findCommand takes a cobra.Command and a command string and returns the
// cobra.Command for the given command string.
// The command string is the command plus any subcommands, the same as you
// would run it on the CLI. Eg: `command = hubble observe` will find the
// cobra.Command for `observe`, given the root cobra.Command for hubble CLI.
func findCommand(cmd *cobra.Command, args []string) (*cobra.Command, error) {
	// If the user specified the root command args, we'll accept it
	if len(args) == 1 && cmd.Name() == args[0] {
		return cmd, nil
	}
	if cmd.Name() == args[0] {
		// cmd.Find takes the args without the root command
		args = args[1:]
	}
	// Find the command the plugin wants to add flags to.
	cmd, _, err := cmd.Find(args)
	if err != nil {
		return nil, err
	}
	return cmd, nil
}
