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
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/datapath/tunnel"
)

// routingModeType represents the routing modes possibly supported by any node.
// It differentiates the tunnel protocol to allow providing better error messages
// in case of VXLAN/Geneve mismatches.
type routingModeType = string

// routingModesType represents the ordered list of routing modes supported by
// the given node.
type routingModesType []routingModeType

const (
	// RoutingPrefix is the common prefix for routing related annotations
	// used for enterprise-only functionalities.
	RoutingPrefix = "routing.isovalent.com"

	// SupportedRoutingModesKey is the key of the annotations added to CiliumNode resources
	// to convey the routing modes supported by the given node.
	SupportedRoutingModesKey = RoutingPrefix + "/supported"
)

const (
	// routingModeUnspec is the zero value for routingModeType, and represents
	// an unspecified routing mode.
	routingModeUnspec = routingModeType("")

	// routingModeNative specifies native routing mode.
	routingModeNative = routingModeType("native")
	// routingModeVXLAN specifies tunneling mode, with VXLAN protocol.
	routingModeVXLAN = routingModeType("tunnel/vxlan")
	// routingModeGeneve specifies tunneling mode, with Geneve protocol.
	routingModeGeneve = routingModeType("tunnel/geneve")

	// routingModesSeparator is the separator used to serialize routingModesType.
	routingModesSeparator = ","
)

// String returns the string representation of the routing modes (i.e., comma separated).
func (rm routingModesType) String() string { return strings.Join([]string(rm), routingModesSeparator) }

func parseRoutingModes(in string) (routingModesType, error) {
	if len(in) == 0 {
		return nil, errors.New("no routing mode specified")
	}

	modes := strings.Split(in, routingModesSeparator)
	for _, mode := range modes {
		switch mode {
		case routingModeNative, routingModeVXLAN, routingModeGeneve:
		default:
			return nil, fmt.Errorf("invalid routing mode %q", mode)
		}
	}

	return modes, nil
}

// toRoutingMode returns the routing mode representation, based on mode and protocol.
// We compare the routing mode against the given tunnel representation to avoid relying
// on the fact that both the primary and fallback modes are represented in the same way.
func toRoutingMode[T comparable](rm T, rmtun T, proto tunnel.Protocol) routingModeType {
	if rm == rmtun {
		switch proto {
		case tunnel.VXLAN:
			return routingModeVXLAN
		case tunnel.Geneve:
			return routingModeGeneve
		default:
			panic(fmt.Errorf("unexpected tunnel protocol %q", proto))
		}
	}
	return routingModeNative
}
