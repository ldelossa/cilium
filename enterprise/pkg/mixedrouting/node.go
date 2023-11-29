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
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

type nodeManager struct {
	logger logrus.FieldLogger
	modes  routingModesType

	downstream store.NodeManager
	nodesCache lock.Map[nodeTypes.Identity, *nodeTypes.Node]
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
	}

	log.Debug("Observed node upsertion")
	nm.nodesCache.Store(id, &node)

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
	nm.downstream.NodeDeleted(node)
	nm.nodesCache.Delete(id)
}

// needsEncapsulation returns whether tunnel encapsulation shall be used towards
// the given remote node. It fallbacks to the local primary mode when unknown.
func (nm *nodeManager) needsEncapsulation(node *nodeTypes.Node) bool {
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
