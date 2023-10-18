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
	"fmt"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/enterprise/pkg/maps/ciliummeshpolicymap"
	dpcfgdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
)

const (
	ciliumMesh = "enable-cilium-mesh"
)

type Config struct {
	EnableCiliumMesh bool `mapstructure:"enable-cilium-mesh"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(ciliumMesh, def.EnableCiliumMesh, "Enables Cilium Mesh feature")
}

func datapathNodeHeaderConfigProvider(cfg Config) dpcfgdef.NodeFnOut {
	return dpcfgdef.NewNodeFnOut(func() (dpcfgdef.Map, error) {
		output := make(dpcfgdef.Map)
		if !cfg.EnableCiliumMesh {
			return output, nil
		}

		output["CILIUM_MESH_POLICY_MAP_SIZE"] = fmt.Sprintf("%d", ciliummeshpolicymap.MaxEntries)
		output["CILIUM_MESH_POLICY_MAP"] = ciliummeshpolicymap.MapName
		output["CILIUM_MESH"] = "1"

		return output, nil
	})
}
