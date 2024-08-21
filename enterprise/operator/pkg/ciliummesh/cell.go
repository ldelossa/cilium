// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package ciliummesh

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
)

const (
	// ciliumMeshEnabled is the name of the flag to enable Cilium Mesh feature
	ciliumMeshEnabled = "enable-cilium-mesh"
)

var Cell = cell.Module(
	"cilium-mesh",
	"Cilium Mesh",

	// provide locator pool
	cell.Provide(newCiliumMeshManager),
	cell.Config(defaultConfig),

	// Invoke an empty function to force its construction / starting.
	cell.Invoke(func(*CiliumMeshManager) {}),
)

// Config contains the configuration for the cilium mesh
type Config struct {
	Enabled bool `mapstructure:"enable-cilium-mesh"`
}

var defaultConfig = Config{
	Enabled: false,
}

// Flags implements cell.Flagger interface.
func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(ciliumMeshEnabled, cfg.Enabled, "Enable Cilium Mesh feature")
}
