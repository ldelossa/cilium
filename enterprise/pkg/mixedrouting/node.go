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
	"net"
	"slices"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type endpointMapper interface {
	setMapping(hostIP net.IP, mode routingModeType)
	unsetMapping(hostIP net.IP)
}

type nodeManager struct {
	logger logrus.FieldLogger
	modes  routingModesType

	downstream store.NodeManager
	nodesCache lock.Map[nodeTypes.Identity, *nodeTypes.Node]

	epmapper endpointMapper
}

// NodeUpdated wraps the corresponding nodemanager.Manager method to observe node
// upsertions and perform the appropriate operations to implement mixed routing
// mode support.
func (nm *nodeManager) NodeUpdated(node nodeTypes.Node) {
	var (
		id      = node.Identity()
		mode    = nm.routingMode(&node, true /* verbose */)
		prev, _ = nm.nodesCache.Load(id)
		log     = nm.logger.WithFields(logrus.Fields{
			logfields.Node:        id.String(),
			logfields.RoutingMode: mode,
		})
	)

	// The matching routing mode changed wrt the one previously configured. Let's
	// trigger a synthetic node deletion event to handle all the required changes
	// (e.g., modify the node routes). This will disrupt all existing connections
	// towards that node, but that's expected as we are changing routing mode.
	if prev != nil && nm.routingMode(prev, false /* silent */) != mode {
		log.Warning("Preferred routing mode changed. " +
			"Expect connectivity disruption towards hosted endpoints")
		nm.NodeDeleted(*prev)
		prev = nil
	}

	log.Debug("Observed node upsertion")
	nm.nodesCache.Store(id, &node)

	nm.updateEndpointAssociations(prev, &node, log)

	nm.downstream.NodeUpdated(node)
}

// NodeDeleted wraps the corresponding nodemanager.Manager method to observe node
// deletions and perform the appropriate operations to implement mixed routing
// mode support.
func (nm *nodeManager) NodeDeleted(node nodeTypes.Node) {
	var (
		id  = node.Identity()
		log = nm.logger.WithFields(logrus.Fields{
			logfields.Node:        id.String(),
			logfields.RoutingMode: nm.routingMode(&node, false /* silent */),
		})
	)

	log.Debug("Observed node deletion")
	nm.nodesCache.Delete(id)

	nm.updateEndpointAssociations(&node, nil, log)

	nm.downstream.NodeDeleted(node)
}

func (nml *nodeManager) NodeSync() { nml.downstream.NodeSync() }

// needsEncapsulation returns whether tunnel encapsulation shall be used towards
// the given remote node. It fallbacks to the local primary mode when unknown.
func (nm *nodeManager) needsEncapsulation(node *nodeTypes.Node) bool {
	return needsEncapsulation(nm.routingMode(node, false /* silent */))
}

// ipsetFilter returns whether the insertion of the ipset entries for the given
// node should be filtered out (i.e., when the preferred routing mode towards
// the given node is tunneling).
func (nm *nodeManager) ipsetFilter(node *nodeTypes.Node) bool {
	return needsEncapsulation(nm.routingMode(node, false /* silent */))
}

// routingMode returns the routing mode selected towards the given remote node,
// depending on the local configuration and the advertized routing modes. In case
// of error, it outputs a log message (if verbose is true) and falls back to the
// local primary mode.
func (nm *nodeManager) routingMode(node *nodeTypes.Node, verbose bool) routingModeType {
	value, ok := node.Annotations[SupportedRoutingModesKey]
	if !ok {
		// The remote node does not specify any supported routing modes. Let's
		// default to the local primary routing mode for backward compatibility.
		return nm.modes.primary()
	}

	modes, invalid := parseRoutingModes(value)
	if len(invalid) > 0 && verbose {
		// Ignore possible unrecognized routing modes to enable backward compatibility
		// in case we would ever want to subsequently introduce a new routing mode.
		nm.logger.WithFields(logrus.Fields{
			logfields.Node:                node.Fullname(),
			logfields.RoutingModes:        modes,
			logfields.InvalidRoutingModes: logfields.Repr(invalid),
		}).Warning("Unknown routing modes found: they will be ignored")
	}

	mode, err := nm.modes.match(modes)
	if err != nil {
		mode = nm.modes.primary()
		if verbose {
			nm.logger.WithError(err).WithFields(logrus.Fields{
				logfields.Node:         node.Fullname(),
				logfields.RoutingModes: modes,
			}).Errorf("Failed to determine routing mode, falling back to %s. "+
				"Expect possible connectivity disruption", mode)
		}
	}

	return mode
}

// updateEndpointAssociations updates the mappings between Node{Internal,External}IP
// addresses and preferred routing mode, leveraged to appropriately customize the
// ipcache map skip_tunnel flag for each endpoint entry.
func (nm *nodeManager) updateEndpointAssociations(old, new *nodeTypes.Node, log logrus.FieldLogger) {
	var mode routingModeType
	if new != nil {
		mode = nm.routingMode(new, false /* silent */)
	}

	onAdded := func(ip net.IP) {
		log.WithField(logfields.IPAddr, ip.String()).
			Debug("Configured tunnel endpoint to routing mode association")
		nm.epmapper.setMapping(ip, mode)
	}

	onDeleted := func(ip net.IP) {
		log.WithField(logfields.IPAddr, ip.String()).
			Debug("Removed tunnel endpoint to routing mode association")
		nm.epmapper.unsetMapping(ip)
	}

	// Configure both internal and external addresses, as they are needed to
	// tune BPF masquerading (only for native routing clusters). Indeed,
	// while with iptables SNAT is skipped for pod to node traffic only
	// towards InternalIP addresses, the BPF counterpart skips it both for
	// InternalIP and ExternalIP addresses (cilium/cilium#17177). We need to
	// ensure that SNAT is performed towards both classes of addresses if the
	// preferred routing mode is tunnel, otherwise traffic will be dropped.
	// The address used to configure the host IP address in the CiliumEndpoint
	// and in the equivalent kvstore representation is retrieved through
	// GetCiliumEndpointNodeIP(), corresponding to the IPv4 InternalIP, with
	// fallback to the IPv4 ExternalIP. Hence, both cases are also covered.
	nm.forEachAddress(old, new, true /* Both InternalIPs and ExternalIPs */, onAdded, onDeleted)
}

// forEachAddress respectively executes the onAdded and onDeleted functions for
// each NodeInternalIP (and NodeExternalIP if includeExternalIPs is set) that is
// different between the old and the new node.
func (nm *nodeManager) forEachAddress(old, new *nodeTypes.Node, includeExternalIPs bool, onAdded, onDeleted func(net.IP)) {
	var (
		oldIPs []net.IP
		newIPs []net.IP
		filter = func(ip net.IP) bool { return ip == nil || ip.IsUnspecified() }
	)

	if old != nil {
		oldIPs = append(oldIPs, old.GetNodeInternalIPv4(), old.GetNodeInternalIPv6())
		if includeExternalIPs {
			oldIPs = append(oldIPs, old.GetExternalIP(false /* IPv4 */), old.GetExternalIP(true /* IPv6 */))
		}
	}

	if new != nil {
		newIPs = append(newIPs, new.GetNodeInternalIPv4(), new.GetNodeInternalIPv6())
		if includeExternalIPs {
			newIPs = append(newIPs, new.GetExternalIP(false /* IPv4 */), new.GetExternalIP(true /* IPv6 */))
		}

		// Drop the addresses that did not change.
		for i := range oldIPs {
			if oldIPs[i].Equal(newIPs[i]) {
				oldIPs[i], newIPs[i] = nil, nil
			}
		}
	}

	for _, ip := range slices.DeleteFunc(oldIPs, filter) {
		onDeleted(ip)
	}

	for _, ip := range slices.DeleteFunc(newIPs, filter) {
		onAdded(ip)
	}
}

// nodeManagerLight aliases nodeManager to provide lightweight wrappers of the
// NodeUpdated and NodeDeleted methods, that simply log an error message in case
// of mismatching routing modes. This is intended to be used when the local node
// supports a single routing mode, as that would be always selected anyway.
type nodeManagerLight nodeManager

func (nml *nodeManagerLight) NodeUpdated(node nodeTypes.Node) {
	// We only care about the side effect of emitting a log error message in
	// case the advertised routing modes are not compatible with the local one.
	_ = (*nodeManager)(nml).routingMode(&node, true /* verbose */)
	nml.downstream.NodeUpdated(node)
}

func (nml *nodeManagerLight) NodeDeleted(node nodeTypes.Node) {
	nml.downstream.NodeDeleted(node)
}

func (nml *nodeManagerLight) NodeSync() { nml.downstream.NodeSync() }
