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
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/clustermesh"
	dpipc "github.com/cilium/cilium/pkg/datapath/ipcache"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ipcmap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/node"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/option"

	cemrcfg "github.com/cilium/cilium/enterprise/pkg/mixedrouting/config"
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

type manager struct {
	logger logrus.FieldLogger
	config cemrcfg.Config
	modes  routingModesType

	nodes     *nodeManager
	endpoints *endpointManager
}

type params struct {
	cell.In

	Logger logrus.FieldLogger

	Config       cemrcfg.Config
	DaemonConfig *option.DaemonConfig
	Tunnel       tunnel.Config

	NodeManager     nodemanager.NodeManager
	IPTablesManager *iptables.Manager
	IPCache         *ipcache.IPCache
}

func newManager(in params) *manager {
	mgr := manager{
		logger: in.Logger,
		config: in.Config,
	}

	mgr.modes = append(mgr.modes, toRoutingMode(in.DaemonConfig.RoutingMode, option.RoutingModeTunnel, in.Tunnel.Protocol()))
	if mgr.enabled() && (in.Config.FallbackRoutingMode == cemrcfg.FallbackTunnel) != (in.DaemonConfig.TunnelingEnabled()) {
		mgr.modes = append(mgr.modes, toRoutingMode(in.Config.FallbackRoutingMode, cemrcfg.FallbackTunnel, in.Tunnel.Protocol()))
	}

	if mgr.enabledWithFallback() {
		mgr.endpoints = &endpointManager{
			logger:     mgr.logger,
			debug:      in.DaemonConfig.Debug,
			modes:      mgr.modes,
			downstream: in.IPCache,
			prefixes:   newPrefixCache(),
		}
	}

	// The node manager must be used in its lightweight form when
	// mgr.enabledWithFallback() is false, as is only partially initialized.
	mgr.nodes = &nodeManager{
		logger:     mgr.logger,
		modes:      mgr.modes,
		downstream: in.NodeManager,
		ipsetter:   in.IPTablesManager,
		epmapper:   mgr.endpoints,
	}

	return &mgr
}

func (mgr *manager) configureLocalNode(lns *node.LocalNodeStore) {
	mgr.logger.WithField(logfields.RoutingModes, mgr.modes).Info("Supported routing modes configured")
	lns.Update(func(ln *node.LocalNode) {
		// Create a clone, so that we don't mutate the current annotations,
		// as LocalNodeStore.Update emits a shallow copy of the whole object.
		ln.Annotations = maps.Clone(ln.Annotations)
		ln.Annotations[SupportedRoutingModesKey] = mgr.modes.String()
	})
}

func (mgr *manager) setupNodeManager(dp datapath.Datapath, cm *clustermesh.ClusterMesh, nomgr nodemanager.NodeManager) {
	// We don't need to hook the extra logic if the local node is configured
	// with a single routing mode, as it will be always selected anyway.
	// However, we still inject the lightweight version of the node manager
	// to log an error message in case of mismatching routing modes.
	if !mgr.enabledWithFallback() {
		clustermesh.InjectCENodeObserver(cm, (*nodeManagerLight)(mgr.nodes))
		return
	}

	clustermesh.InjectCENodeObserver(cm, mgr.nodes)
	linuxdatapath.InjectCEEnableEncapsulation(dp, mgr.nodes.needsEncapsulation)

	// Note: the current approach works assuming that the fallback routing mode
	// is tunnel (the only supported configuration at the moment), by filtering
	// out the ipset insertions/deletions if the preferred routing mode towards
	// the given node is tunneling (and the local routing mode is set to native,
	// otherwise they would not have been inserted in the first place). To support
	// native routing fallback, instead, we should force the creation of the ipset
	// and manually insert the appropriate entries.
	nodemanager.InjectCEIPSetManager(nomgr, mgr.nodes)
}

func (mgr *manager) setupEndpointManager(cm *clustermesh.ClusterMesh, lst *dpipc.BPFListener) {
	// We don't need to hook the extra logic if the local node is configured
	// with a single routing mode, as it will be always selected anyway.
	if !mgr.enabledWithFallback() {
		return
	}

	clustermesh.InjectCEIPCache(cm, mgr.endpoints)
	dpipc.InjectCEMap(lst, &ipcmapwr{
		Map:     ipcmap.IPCacheMap(),
		mutator: mgr.endpoints.mutateRemoteEndpointInfo,
	})
}

// enabled returns whether mixed routing mode support is enabled.
func (mgr *manager) enabled() bool { return mgr.config.FallbackRoutingMode != cemrcfg.FallbackDisabled }

// enabledWithFallback returns whether mixed routing mode support is enabled,
// and the fallback routing mode is different from the primary one.
func (mgr *manager) enabledWithFallback() bool { return len(mgr.modes) > 1 }

// String returns the string representation of the routing modes (i.e., comma separated).
func (rm routingModesType) String() string { return strings.Join([]string(rm), routingModesSeparator) }

// primary returns the primary routing mode. It panics if no routing mode is set.
func (rm routingModesType) primary() routingModeType { return rm[0] }

// match returns the first routing mode that is present both in the local and
// in the remote list. An error is returned if no match is found. This is guaranteed
// to lead to a symmetric selection of the routing mode as long as every node is
// configured with a primary mode and exactly the same secondary mode (as in the
// current implementation). Differently, it could lead to different decisions on
// different nodes if associated with multiple secondary modes.
func (local routingModesType) match(remote routingModesType) (routingModeType, error) {
	for _, mode := range local {
		if slices.Contains(remote, mode) {
			return mode, nil
		}
	}

	return routingModeUnspec, fmt.Errorf("no matching routing mode found")
}

// parseRoutingModes parses a comma separated list of routing modes. In addition
// to the list of valid routing modes, it also returns unrecognized ones (if any),
// which can then be ignored (possibly emitting appropriate log messages). We
// avoid to fail hard to enable backward compatibility in case we would ever want
// to introduce a new routing mode in a subsequent release.
func parseRoutingModes(in string) (valid routingModesType, invalid []string) {
	if len(in) == 0 {
		return
	}

	for _, mode := range strings.Split(in, routingModesSeparator) {
		switch mode {
		case routingModeNative, routingModeVXLAN, routingModeGeneve:
			valid = append(valid, mode)
		default:
			invalid = append(invalid, mode)
		}
	}

	return
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

// needsEncapsulation returns whether tunnel encapsulation shall be used
// depending on the specified routing mode.
func needsEncapsulation(rm routingModeType) bool {
	return rm == routingModeVXLAN || rm == routingModeGeneve
}
