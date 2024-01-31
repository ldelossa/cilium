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

import "github.com/cilium/hive/cell"

// Cell provides a module that does feature registration and feature
// gate checking tasks.
var Cell = cell.Module(
	"features",
	"Feature Checker",
	cell.Provide(func() None {
		return None{}
	}),
	cell.Config(defaultConf),
	cell.Provide(newGateChecker),
	cell.Provide(newRegistry),
)
