// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-egress")

const (
	PolicyMapName = "cilium_egress_gw_policy_v4"
	CtMapName     = "cilium_egress_gw_ct_v4"

	MaxPolicyEntries = 1 << 14
	MaxCtEntries     = 1 << 18

	MaxGatewayNodes = 64
)

var (
	EgressPolicyMap *egressPolicyMap
	EgressCtMap     *egressCtMap
)

// ApplyEgressPolicy adds a new entry to the egress policy map.
// If a policy with the same key already exists, it will get replaced.
func ApplyEgressPolicy(sourceIP net.IP, destCIDR net.IPNet, egressIP net.IP, activeGatewayIPs, healthyGatewayIPs []net.IP) error {
	if len(activeGatewayIPs) > MaxGatewayNodes {
		return fmt.Errorf("cannot apply egress policy: too many gateways")
	}

	if err := EgressPolicyMap.Update(sourceIP, destCIDR, egressIP, activeGatewayIPs); err != nil {
		return fmt.Errorf("cannot apply egress policy: %w", err)
	}

	// When a policy is updated, its list of gateway nodes may change, which
	// means we may end up with CT entries for nodes that don't belong
	// anymore to the pool of egress gateways and so need to be removed.
	// removeExpiredCtEntries takes care of this.
	// Entries are deleted _after_ the policy is updated otherwise we may
	// end up creating entries which never get deleted.
	if err := removeExpiredCtEntries(sourceIP, destCIDR, healthyGatewayIPs); err != nil {
		log.WithError(err).Error("cannot remove egress CT entries")
	}

	return nil
}

// RemoveEgressPolicy removes an egress policy identified by the (source IP,
// destination CIDR) tuple.
// In addition to removing the policy, this function removes also all CT entries
// from the egress CT map which match the egress policy.
func RemoveEgressPolicy(sourceIP net.IP, destCIDR net.IPNet) error {
	_, err := EgressPolicyMap.Lookup(sourceIP, destCIDR)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("egress policy does not exist")
		}

		return fmt.Errorf("cannot lookup egress policy: %w", err)
	}

	if err := EgressPolicyMap.Delete(sourceIP, destCIDR); err != nil {
		return err
	}

	// Remove from the CT table all the connections that were directed to
	// the egress gateway(s) we just deleted.
	// Entries are deleted _after_ the policy is updated otherwise we may
	// end up creating entries which never get deleted.
	if err = removeExpiredCtEntries(sourceIP, destCIDR, []net.IP{}); err != nil {
		log.WithError(err).Error("cannot remove egress CT entries")
	}

	return nil
}

// InitEgressMaps initializes the egress policy and CT maps.
func InitEgressMaps() error {
	err := initEgressPolicyMap(PolicyMapName, true)
	if err != nil {
		return err
	}

	return initEgressCtMap(CtMapName, true)
}

// OpenEgressMaps initializes the egress policy and CT maps.
func OpenEgressMaps() error {
	err := initEgressPolicyMap(PolicyMapName, false)
	if err != nil {
		return err
	}

	return initEgressCtMap(CtMapName, false)
}
