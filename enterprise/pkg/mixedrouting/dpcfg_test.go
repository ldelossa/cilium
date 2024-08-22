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
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dpcfgdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/option"

	cemrcfg "github.com/cilium/cilium/enterprise/pkg/mixedrouting/config"
)

func TestDatapathConfigProvider(t *testing.T) {
	tests := []struct {
		name string
		cfg  cemrcfg.Config
		dcfg *option.DaemonConfig

		assertProtoDisabled assert.BoolAssertionFunc
		assertTunnelMode    assert.ComparisonAssertionFunc
	}{
		{
			name:                "native routing, mixed routing mode not enabled",
			cfg:                 cemrcfg.Config{FallbackRoutingMode: cemrcfg.FallbackDisabled},
			dcfg:                &option.DaemonConfig{RoutingMode: option.RoutingModeNative},
			assertProtoDisabled: assert.True,
			assertTunnelMode:    assert.NotContains,
		},
		{
			name:                "native routing, mixed routing mode fallback native",
			cfg:                 cemrcfg.Config{FallbackRoutingMode: cemrcfg.FallbackNative},
			dcfg:                &option.DaemonConfig{RoutingMode: option.RoutingModeNative},
			assertProtoDisabled: assert.True,
			assertTunnelMode:    assert.NotContains,
		},
		{
			name:                "native routing, mixed routing mode fallback tunnel",
			cfg:                 cemrcfg.Config{FallbackRoutingMode: cemrcfg.FallbackTunnel},
			dcfg:                &option.DaemonConfig{RoutingMode: option.RoutingModeNative},
			assertProtoDisabled: assert.False,
			assertTunnelMode:    assert.Contains,
		},
		{
			name:                "tunnel routing, mixed routing mode not enabled",
			cfg:                 cemrcfg.Config{FallbackRoutingMode: cemrcfg.FallbackDisabled},
			dcfg:                &option.DaemonConfig{RoutingMode: option.RoutingModeTunnel},
			assertProtoDisabled: assert.False,
			assertTunnelMode:    assert.NotContains,
		},
		{
			name:                "tunnel routing, mixed routing mode fallback native",
			cfg:                 cemrcfg.Config{FallbackRoutingMode: cemrcfg.FallbackNative},
			dcfg:                &option.DaemonConfig{RoutingMode: option.RoutingModeTunnel},
			assertProtoDisabled: assert.False,
			assertTunnelMode:    assert.NotContains,
		},
		{
			name:                "tunnel routing, mixed routing mode fallback tunnel",
			cfg:                 cemrcfg.Config{FallbackRoutingMode: cemrcfg.FallbackTunnel},
			dcfg:                &option.DaemonConfig{RoutingMode: option.RoutingModeTunnel},
			assertProtoDisabled: assert.False,
			assertTunnelMode:    assert.NotContains,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				outProto tunnel.Protocol
				outDef   = dpcfgdef.Map{}
			)

			require.NoError(t, hive.New(cell.Group(
				tunnel.Cell,

				cell.Provide(
					datapathConfigProvider,
					func() cemrcfg.Config { return tt.cfg },
					func() *option.DaemonConfig { return tt.dcfg },
				),

				cell.Invoke(func(in struct {
					cell.In
					Tunnel           tunnel.Config
					NodeExtraDefines []dpcfgdef.Map `group:"header-node-defines"`
				}) {
					outProto = in.Tunnel.Protocol()
					for _, ned := range in.NodeExtraDefines {
						outDef.Merge(ned)
					}
				}),
			)).Populate(hivetest.Logger(t)))

			tt.assertProtoDisabled(t, outProto == tunnel.Disabled)
			tt.assertTunnelMode(t, outDef, "TUNNEL_MODE")
		})
	}
}
