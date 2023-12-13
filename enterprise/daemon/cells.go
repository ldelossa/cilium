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
	"github.com/cilium/cilium/daemon/cmd"
	"github.com/cilium/cilium/enterprise/api/v1/server"
	"github.com/cilium/cilium/enterprise/pkg/api"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha"
	"github.com/cilium/cilium/enterprise/pkg/maps/egressmapha"
	"github.com/cilium/cilium/enterprise/pkg/mixedrouting"
	"github.com/cilium/cilium/enterprise/pkg/multinetwork"
	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	"github.com/cilium/cilium/enterprise/pkg/srv6/srv6manager"
	"github.com/cilium/cilium/pkg/hive/cell"

	cecm "github.com/cilium/cilium/enterprise/pkg/clustermesh"
	cemaps "github.com/cilium/cilium/enterprise/pkg/maps"
)

var (
	EnterpriseAgent = cell.Module(
		"enterprise-agent",
		"Cilium Agent Enterprise",

		cmd.Agent,

		// enterprise-only cells here
		ControlPlane,
		Datapath,
	)

	ControlPlane = cell.Module(
		"enterprise-controlplane",
		"Control Plane Enterprise",

		api.Cell,
		server.SpecCell,
		server.APICell,

		cecm.Cell,
		sidmanager.SIDManagerCell,
		srv6manager.Cell,
		egressmapha.Cell,
		egressgatewayha.Cell,
		egressgatewayha.PolicyCell,

		cell.Invoke(func(*egressgatewayha.Manager) {}),

		mixedrouting.Cell,

		multinetwork.Cell,
	)

	Datapath = cell.Module(
		"enterprise-datapath",
		"Datapath Enterprise",

		cemaps.Cell,
	)
)
