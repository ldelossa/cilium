// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vrf

import (
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/ebpf"
	vrfMaps "github.com/cilium/cilium/pkg/maps/vrf"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides VRF (Virtual Routing and Forwarding) support.
var Cell = cell.Module(
	"vrf",
	"Generic VRF suppport",
	cell.Config(defaultConfig),
	cell.Invoke(NewVRFSubsystem),
)

var defaultConfig = Config{
	EnableVRFs: false,
}

type Config struct {
	EnableVRFs bool
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-vrfs", c.EnableVRFs, "Enables VRF (Virtual Routing and Forwarding) support")
}

type VRFSubsystemParams struct {
	cell.In
	DaemonConfig *option.DaemonConfig
	Config       Config
}

// NewVRFSubystem will configure Cilium's generic VRF subsystem.
// This subsystem provides a mapping of IP hosts to VRFs they belong in.
//
// Other subsystems are free to use this, however in this initial implementation
// there is not split view of the subsystem. Only a single VRF subsystem exists
// and components must coordinate VRF allocation.
func NewVRFSubsystem(params VRFSubsystemParams, lc cell.Lifecycle) (bpf.MapOut[*vrfMaps.VRFMap4], bpf.MapOut[*vrfMaps.VRFMap6], defines.NodeOut) {
	var vrf4 *bpf.Map
	var vrf6 *bpf.Map

	nodeOut := defines.NodeOut{
		NodeDefines: defines.Map{
			"SRV6_VRF_MAP_SIZE": strconv.FormatUint(vrfMaps.MaxVRFEntries, 10),
		},
	}

	if !params.Config.EnableVRFs {
		return bpf.MapOut[*vrfMaps.VRFMap4]{}, bpf.MapOut[*vrfMaps.VRFMap6]{}, nodeOut
	}

	if params.DaemonConfig.EnableIPv4 {
		vrf4 = bpf.NewMap(
			vrfMaps.VRFMapName4,
			ebpf.LPMTrie,
			&vrfMaps.VRFKey4{},
			&vrfMaps.VRFValue{},
			vrfMaps.MaxVRFEntries,
			unix.BPF_F_NO_PREALLOC,
		)
	}

	if params.DaemonConfig.EnableIPv6 {
		vrf6 = bpf.NewMap(
			vrfMaps.VRFMapName6,
			ebpf.LPMTrie,
			&vrfMaps.VRFKey6{},
			&vrfMaps.VRFValue{},
			vrfMaps.MaxVRFEntries,
			unix.BPF_F_NO_PREALLOC,
		)
	}

	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			if vrf4 != nil {
				if err := vrf4.OpenOrCreate(); err != nil {
					return err
				}
			}
			if vrf6 != nil {
				if err := vrf6.OpenOrCreate(); err != nil {
					return err
				}
			}
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			if vrf4 != nil {
				vrf4.Close()
			}

			if vrf6 != nil {
				vrf6.Close()
			}
			return nil
		},
	})

	return bpf.NewMapOut(&vrfMaps.VRFMap4{Map: vrf4}), bpf.NewMapOut(&vrfMaps.VRFMap6{Map: vrf6}), nodeOut
}
