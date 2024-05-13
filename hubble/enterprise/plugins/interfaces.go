//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package plugins

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Init signature for hubble plugin constructors.
type Init func() (Instance, error)

// Instance makes API slightly easier to read. It means any pointer to a hubble
// plugin type.
type Instance interface{}

// CommandInit is a signature required for those hubble plugins that wish to
// include a sub-command. Plugin instances use this signature via `AddCommands`
// interface.
type CommandInit func(vp *viper.Viper) (*cobra.Command, error)

// AddCommands allows a plugin to add commands to the `hubble` binary.
//
// In the future it's possible that sub-command adding is required, but for now
// that is not supported until a valid case.
type AddCommands interface {
	AddCommands() []CommandInit
}

// FlagsInit is a signature required for those hubble plugins that wish to
// include a sub-command. Plugin instances use this signature via `AddCommands`
// interface.
type FlagsInit func() (fs *pflag.FlagSet, args []string, persistent bool, err error)

// AddFlags allows a plugin to add flags to existing commands in the `hubble` binary.
type AddFlags interface {
	AddFlags() []FlagsInit
}
