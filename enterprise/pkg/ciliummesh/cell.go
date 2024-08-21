//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ciliummesh

import (
	"github.com/cilium/hive/cell"
)

var defaultConfig = Config{
	EnableCiliumMesh: false,
}

var (
	CiliumMeshCell = cell.Module(
		"cilium-mesh",
		"Cilium Mesh is the feature that connects your past legacy into the future",

		cell.Config(defaultConfig),

		cell.Provide(
			// Provide the MeshEndpoint resource watcher.
			NewIsovalentMeshEndpointResource,

			// Start the Cilium Mesh Controller.
			newCiliumMeshController,

			// Inject the extra datapath configs required for cilium mesh support.
			datapathNodeHeaderConfigProvider,
		),

		// Invoke an empty function to force its construction.
		cell.Invoke(func(*CiliumMeshController) {}),
	)
)
