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
	"fmt"

	"github.com/spf13/pflag"

	ipamopt "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/option"
)

// FallbackType is the type of the possible values for the --fallback-routing-mode flag
type FallbackType string

const (
	// FallbackDisabled: mixed routing modes support is disabled.
	FallbackDisabled = FallbackType("")
	// FallbackNative: mixed routing mode support is enabled, and configured
	// to fallback to native routing in case of a mismatch.
	FallbackNative = FallbackType(option.RoutingModeNative)
	// FallbackTunnel: mixed routing mode support is enabled, and configured
	// to fallback to tunnel routing in case of a mismatch.
	FallbackTunnel = FallbackType(option.RoutingModeTunnel)

	fallbackRoutingModeFlag = "fallback-routing-mode"
)

// Config represents the mixed routing mode configuration.
type Config struct {
	FallbackRoutingMode FallbackType
}

// Flags implements the cell.Flagger interface, to register the given flags.
func (def Config) Flags(flags *pflag.FlagSet) {
	flags.String(fallbackRoutingModeFlag, string(def.FallbackRoutingMode),
		fmt.Sprintf("Enable fallback routing mode, used in case of mismatch between "+
			"source and destination node (supported: %s)", FallbackTunnel))
}

func (cfg Config) Validate(dcfg *option.DaemonConfig) error {
	switch cfg.FallbackRoutingMode {
	case FallbackDisabled:
		return nil
	case FallbackTunnel:
	case FallbackNative:
		return fmt.Errorf("currently, %s=%s is not supported", fallbackRoutingModeFlag, FallbackNative)
	default:
		return fmt.Errorf("invalid %s value %q, valid fallback modes are {%s}",
			fallbackRoutingModeFlag, cfg.FallbackRoutingMode, FallbackTunnel)
	}

	switch dcfg.IPAM {
	case ipamopt.IPAMKubernetes, ipamopt.IPAMClusterPool:
	default:
		return fmt.Errorf("currently, %s is not compatible with %s=%s",
			fallbackRoutingModeFlag, option.IPAM, dcfg.IPAM)
	}

	if dcfg.LoadBalancerUsesDSR() {
		return fmt.Errorf("currently, %s requires %s=%s",
			fallbackRoutingModeFlag, option.NodePortMode, option.NodePortModeSNAT)
	}

	// Additional known incompatibilities include:
	// * Egress Gateway: does not work in combination with Cluster Mesh.
	// * Overlapping PodCIDR: all clusters are required to be configured in tunnel mode.
	// They are not explicitly validated here, as already forbidden elsewhere.

	return nil
}
