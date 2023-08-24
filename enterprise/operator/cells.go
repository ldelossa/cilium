//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"github.com/cilium/cilium/enterprise/operator/pkg/srv6/locatorpool"
	"github.com/cilium/cilium/operator/cmd"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var (
	EnterpriseOperator = cell.Module(
		"enterprise-operator",
		"Cilium Operator Enterprise",

		cmd.Operator,

		// enterprise-only cells here

		cell.Decorate(
			func(lc *cmd.LeaderLifecycle) hive.Lifecycle {
				return lc
			},

			// enterprise-only cells to be started after leader election here
			locatorpool.Cell,
		),
	)
)
