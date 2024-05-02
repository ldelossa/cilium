//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package mixedrouting

import (
	"github.com/cilium/hive/cell"

	dpcfgdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/option"

	cemrcfg "github.com/cilium/cilium/enterprise/pkg/mixedrouting/config"
)

func datapathConfigProvider(cfg cemrcfg.Config, dcfg *option.DaemonConfig) (out struct {
	cell.Out

	tunnel.EnablerOut
	dpcfgdef.NodeOut
}) {
	// We need to enable the tunnel functionalities only when the fallback mode
	// is set to tunnel, and the primary routing mode of the given node is native.
	if !dcfg.TunnelingEnabled() && cfg.FallbackRoutingMode == cemrcfg.FallbackTunnel {
		out.EnablerOut = tunnel.NewEnabler(true)
		out.NodeDefines = dpcfgdef.Map{
			"TUNNEL_MODE": "1",
		}
	}

	return
}
