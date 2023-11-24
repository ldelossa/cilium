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
	"context"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"

	cemrcfg "github.com/cilium/cilium/enterprise/pkg/mixedrouting/config"
)

func TestNodeStoreUpdate(t *testing.T) {
	tests := []struct {
		primary  string
		fallback cemrcfg.FallbackType
		proto    tunnel.Protocol
		expected string
	}{
		{
			primary:  option.RoutingModeNative,
			fallback: cemrcfg.FallbackDisabled,
			proto:    tunnel.VXLAN,
			expected: "native",
		},
		{
			primary:  option.RoutingModeNative,
			fallback: cemrcfg.FallbackNative,
			proto:    tunnel.VXLAN,
			expected: "native",
		},
		{
			primary:  option.RoutingModeNative,
			fallback: cemrcfg.FallbackTunnel,
			proto:    tunnel.VXLAN,
			expected: "native,tunnel/vxlan",
		},
		{
			primary:  option.RoutingModeTunnel,
			fallback: cemrcfg.FallbackDisabled,
			proto:    tunnel.Geneve,
			expected: "tunnel/geneve",
		},
		{
			primary:  option.RoutingModeTunnel,
			fallback: cemrcfg.FallbackNative,
			proto:    tunnel.Geneve,
			expected: "tunnel/geneve,native",
		},
		{
			primary:  option.RoutingModeTunnel,
			fallback: cemrcfg.FallbackTunnel,
			proto:    tunnel.Geneve,
			expected: "tunnel/geneve",
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v-%v-%v", tt.primary, tt.fallback, tt.proto), func(t *testing.T) {
			lns := node.NewTestLocalNodeStore(node.LocalNode{
				Node: types.Node{Annotations: map[string]string{"foo": "bar"}}})

			newManager(params{
				Logger:       logrus.StandardLogger(),
				DaemonConfig: &option.DaemonConfig{RoutingMode: tt.primary},
				Config:       cemrcfg.Config{FallbackRoutingMode: tt.fallback},
				Tunnel:       tunnel.NewTestConfig(tt.proto),
			}).configureLocalNode(lns)

			ln, _ := lns.Get(context.Background())
			require.Equal(t, "bar", ln.Annotations["foo"])
			require.Equal(t, tt.expected, ln.Annotations[SupportedRoutingModesKey])
		})
	}
}

func TestRoutingModeParsing(t *testing.T) {
	tests := []struct {
		in        routingModesType
		expectErr bool
	}{
		{in: nil, expectErr: true},
		{in: routingModesType{routingModeNative}},
		{in: routingModesType{routingModeVXLAN}},
		{in: routingModesType{routingModeGeneve}},
		{in: routingModesType{routingModeVXLAN, routingModeNative}},
		{in: routingModesType{routingModeGeneve, routingModeNative, routingModeGeneve}},
		{in: routingModesType{"foo"}, expectErr: true},
		{in: routingModesType{routingModeNative, "foo", routingModeGeneve}, expectErr: true},
	}

	for _, tt := range tests {
		name := tt.in.String()
		if name == "" {
			name = "empty"
		}

		t.Run(name, func(t *testing.T) {
			out, err := parseRoutingModes(tt.in.String())
			if tt.expectErr {
				require.Error(t, err)
				require.Empty(t, out)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.in, out)
			}
		})
	}
}

func TestToRoutingMode(t *testing.T) {
	const nat, tun = 1, 9
	require.Equal(t, routingModeNative, toRoutingMode(nat, tun, "whatever"))
	require.Equal(t, routingModeVXLAN, toRoutingMode(tun, tun, tunnel.VXLAN))
	require.Equal(t, routingModeGeneve, toRoutingMode(tun, tun, tunnel.Geneve))
	require.Panics(t, func() { toRoutingMode(tun, tun, tunnel.Disabled) })
	require.Panics(t, func() { toRoutingMode(tun, tun, "whatever") })
}
