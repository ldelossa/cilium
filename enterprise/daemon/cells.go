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
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/daemon/cmd"
	"github.com/cilium/cilium/enterprise/api/v1/server"
	"github.com/cilium/cilium/enterprise/featurelist"
	"github.com/cilium/cilium/enterprise/pkg/api"
	"github.com/cilium/cilium/enterprise/pkg/bfd"
	"github.com/cilium/cilium/enterprise/pkg/bgpv1"
	"github.com/cilium/cilium/enterprise/pkg/ciliummesh"
	cecm "github.com/cilium/cilium/enterprise/pkg/clustermesh"
	"github.com/cilium/cilium/enterprise/pkg/egressgatewayha"
	"github.com/cilium/cilium/enterprise/pkg/features"
	"github.com/cilium/cilium/enterprise/pkg/fqdnha"
	cemaps "github.com/cilium/cilium/enterprise/pkg/maps"
	"github.com/cilium/cilium/enterprise/pkg/maps/egressmapha"
	"github.com/cilium/cilium/enterprise/pkg/mixedrouting"
	"github.com/cilium/cilium/enterprise/pkg/multicast"
	"github.com/cilium/cilium/enterprise/pkg/multinetwork"
	"github.com/cilium/cilium/enterprise/pkg/srv6/sidmanager"
	"github.com/cilium/cilium/enterprise/pkg/srv6/srv6manager"
	"github.com/cilium/cilium/pkg/promise"
)

var (
	EnterpriseAgent = cell.Module(
		"enterprise-agent",
		"Cilium Agent Enterprise",

		cmd.Agent,

		// Provide the endpoint API handlers the ability to create endpoints via the daemon.
		cell.Provide(func(dp promise.Promise[*cmd.Daemon]) promise.Promise[ciliummesh.EndpointCreator] {
			return promise.Map(dp, func(d *cmd.Daemon) ciliummesh.EndpointCreator { return d })
		}),

		// enterprise-only cells here
		ControlPlane,
		Datapath,

		features.Cell,
		featurelist.Cell,
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
		bgpv1.Cell,
		bfd.Cell,
		egressmapha.Cell,
		egressgatewayha.Cell,
		egressgatewayha.PolicyCell,
		cell.Invoke(func(*egressgatewayha.Manager) {}),

		ciliummesh.CiliumMeshCell,

		mixedrouting.Cell,

		multinetwork.Cell,

		multicast.Cell,

		fqdnha.Cell,
	)

	Datapath = cell.Module(
		"enterprise-datapath",
		"Datapath Enterprise",

		cemaps.Cell,
	)
)