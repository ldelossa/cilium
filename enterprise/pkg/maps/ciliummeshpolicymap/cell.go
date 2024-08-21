//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ciliummeshpolicymap

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/types"
)

var Cell = cell.Module(
	"enterprise-ciliummesh-pol-maps",
	"Cilium Mesh Policy Map",

	cell.Config(Config{}),

	cell.Provide(
		newCiliumMeshPolicyParams,
	),
	cell.Invoke(func(l types.Loader, pw CiliumMeshPolicyWriter) {
		if pw != nil && l != nil {
			pw.registerLoader(l)
		}
	}),
)
