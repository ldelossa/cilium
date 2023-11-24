//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"

	ipamopt "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/option"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		dcfg      *option.DaemonConfig
		assertion func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool
	}{
		{
			name:      "mixed routing mode disabled",
			cfg:       Config{},
			dcfg:      &option.DaemonConfig{IPAM: ipamopt.IPAMENI, NodePortMode: option.NodePortModeHybrid},
			assertion: assert.NoError,
		},
		{
			name:      "mixed routing mode invalid",
			cfg:       Config{FallbackRoutingMode: "foo"},
			dcfg:      &option.DaemonConfig{},
			assertion: assert.Error,
		},
		{
			name:      "mixed routing mode enabled, fallback native",
			cfg:       Config{FallbackRoutingMode: FallbackNative},
			dcfg:      &option.DaemonConfig{IPAM: ipamopt.IPAMKubernetes, NodePortMode: option.NodePortModeSNAT},
			assertion: assert.Error,
		},
		{
			name:      "mixed routing mode enabled, fallback tunnel",
			cfg:       Config{FallbackRoutingMode: FallbackTunnel},
			dcfg:      &option.DaemonConfig{IPAM: ipamopt.IPAMClusterPool, NodePortMode: option.NodePortModeSNAT},
			assertion: assert.NoError,
		},
		{
			name:      "mixed routing mode enabled, fallback tunnel, ENI mode",
			cfg:       Config{FallbackRoutingMode: FallbackTunnel},
			dcfg:      &option.DaemonConfig{IPAM: ipamopt.IPAMENI, NodePortMode: option.NodePortModeSNAT},
			assertion: assert.Error,
		},
		{
			name:      "mixed routing mode enabled, fallback tunnel, DSR enabled",
			cfg:       Config{FallbackRoutingMode: FallbackTunnel},
			dcfg:      &option.DaemonConfig{IPAM: ipamopt.IPAMKubernetes, NodePortMode: option.NodePortModeDSR},
			assertion: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.cfg.Validate(tt.dcfg))
		})
	}
}
