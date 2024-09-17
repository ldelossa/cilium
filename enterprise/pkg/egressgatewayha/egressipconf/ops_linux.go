//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

//go:build linux

package egressipconf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/enterprise/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/garp"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
)

const (
	// RouteTableEgressGatewayIPAM is the default table ID to use for routing rules related to Egress Gateway IPAM.
	RouteTableEgressGatewayIPAM = 2050

	// RulePriorityEgressGatewayIPAM is the priority of the rule installed by Egress Gateway IPAM to route
	// SNATed traffic to the proper egress interface.
	RulePriorityEgressGatewayIPAM = 30
)

func (ops *ops) Update(ctx context.Context, _ statedb.ReadTxn, entry *tables.EgressIPEntry) error {
	if !entry.Addr.IsValid() {
		return fmt.Errorf("egress IP %s is not valid", entry.Addr)
	}

	iface, err := netlink.LinkByName(entry.Interface)
	if err != nil {
		return fmt.Errorf("failed to get device %s by name: %w", entry.Interface, err)
	}

	ops.logger.Debug("Adding address", "egress IP", entry.Addr, "interface", entry.Interface)

	if err := netlink.AddrAdd(iface, addrForEgressIP(entry.Addr)); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("failed to add egress IP %s to interface %s", entry.Addr, iface.Attrs().Name)
	}

	err = garp.SendOnInterfaceIdx(iface.Attrs().Index, entry.Addr)
	if err != nil {
		ops.logger.Warn("failed to send gratuitous arp reply", "egress IP", entry.Addr, "iface index", iface.Attrs().Index, "error", err)
	}

	ops.logger.Debug("Upserting rule", "egress IP", entry.Addr)

	if err := route.ReplaceRule(ruleForEgressIP(entry.Addr)); err != nil {
		return fmt.Errorf("failed to upsert rule for address %s: %w", entry.Addr, err)
	}

	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{
			Src:       entry.Addr.AsSlice(),
			LinkIndex: iface.Attrs().Index,
			Table:     RouteTableEgressGatewayIPAM,
			Protocol:  linux_defaults.RTProto,
		},
		netlink.RT_FILTER_SRC|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	if err != nil {
		return fmt.Errorf("failed to lookup existing routes for egress IP %s and interface %s", entry.Addr, iface.Attrs().Name)
	}

	// delete stale routes
	for _, r := range routes {
		dst := ipNetToPrefix(*r.Dst)
		found := false
		for _, dest := range entry.Destinations {
			if dest.String() == dst.String() {
				found = true
				break
			}
		}
		if !found {
			ops.logger.Debug("Deleting stale route", "egress IP", entry.Addr, "destination", r.Dst, "interface", iface.Attrs().Name)

			if err := route.DeleteV4(routeForEgressIP(entry.Addr, ipNetToPrefix(*r.Dst), iface)); err != nil && !errors.Is(err, syscall.ESRCH) {
				return fmt.Errorf("failed to delete route for egress IP %s and interface %s", entry.Addr, iface.Attrs().Name)
			}
		}
	}

	// add new routes
	for _, dest := range entry.Destinations {
		found := false
		for _, r := range routes {
			dst := ipNetToPrefix(*r.Dst)
			if dst.String() == dest.String() {
				found = true
				break
			}
		}
		if !found {
			ops.logger.Debug("Upserting route", "egress IP", entry.Addr, "destination", dest, "interface", iface.Attrs().Name)

			if err := route.Upsert(routeForEgressIP(entry.Addr, dest, iface)); err != nil {
				return fmt.Errorf("failed to append route for egress IP %s and interface %s", entry.Addr, iface.Attrs().Name)
			}
		}
	}

	return nil
}

func (ops *ops) Delete(ctx context.Context, _ statedb.ReadTxn, entry *tables.EgressIPEntry) error {
	iface, err := netlink.LinkByName(entry.Interface)
	if err != nil {
		return fmt.Errorf("failed to get device %s by name: %w", entry.Interface, err)
	}

	ops.logger.Debug("Deleting address", "egress IP", entry.Addr, "interface", entry.Interface)

	if err := netlink.AddrDel(iface, addrForEgressIP(entry.Addr)); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
		return fmt.Errorf("failed to delete egress IP %s to interface %s", entry.Addr, iface.Attrs().Name)
	}

	ops.logger.Debug("Deleting rule", "egress IP", entry.Addr)

	if err := route.DeleteRule(netlink.FAMILY_V4, ruleForEgressIP(entry.Addr)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to delete rule for address %s: %w", entry.Addr, err)
	}

	for _, dest := range entry.Destinations {
		ops.logger.Debug("Deleting route", "egress IP", entry.Addr, "destination", dest, "interface", iface.Attrs().Name)

		if err := route.DeleteV4(routeForEgressIP(entry.Addr, dest, iface)); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("failed to delete route for egress IP %s and interface %s: %w", entry.Addr, iface.Attrs().Name, err)
		}
	}

	return nil
}

func (ops *ops) Prune(ctx context.Context, txn statedb.ReadTxn, iter statedb.Iterator[*tables.EgressIPEntry]) error {
	rulesFilter, rulesMask := rulesFilter()
	rules, err := netlink.RuleListFiltered(netlink.FAMILY_V4, rulesFilter, rulesMask)
	if err != nil {
		return fmt.Errorf("failed to list egress-gateway IPAM rules: %w", err)
	}

	routesFilter, routesMask := routesFilter()
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, routesFilter, routesMask)
	if err != nil {
		return fmt.Errorf("failed to list egress-gateway IPAM routes: %w", err)
	}

	// build a map of in-use egressIP -> destinations:
	egressRoutes := make(map[netip.Addr][]netip.Prefix)
	statedb.ProcessEach(iter, func(entry *tables.EgressIPEntry, _ uint64) error {
		egressRoutes[entry.Addr] = append(egressRoutes[entry.Addr], entry.Destinations...)
		return nil
	})

	// prune rules and routes that are not part of the desired state (that is,
	// the stateDB current snapshot).
	// We avoid pruning IP addresses since we can't reliably identify Cilium-managed egress IPs.
	for _, rule := range rules {
		if rule.Src == nil {
			continue
		}

		prefix, ok := netipx.FromStdIPNet(rule.Src)
		if !ok {
			return fmt.Errorf("failed to convert netlink rule src")
		}
		addr := prefix.Masked().Addr()
		if _, ok := egressRoutes[addr]; ok {
			continue
		}

		ops.logger.Debug("Pruning rule", "egress IP", addr)

		if err := route.DeleteRule(netlink.FAMILY_V4, ruleForEgressIP(addr)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to delete rule for address %s while pruning: %w", addr, err)
		}
	}

	for _, r := range routes {
		if r.Dst == nil {
			continue
		}

		addr, ok := netipx.FromStdIP(r.Src)
		if !ok {
			return fmt.Errorf("failed to convert netlink route src")
		}

		inUse := false
		if _, ok := egressRoutes[addr]; ok {
			dst, ok := netipx.FromStdIPNet(r.Dst)
			if !ok {
				return fmt.Errorf("failed to convert netlink route dst")
			}
			inUse = slices.Contains(egressRoutes[addr], dst)
		}
		if inUse {
			continue
		}

		ops.logger.Debug("Pruning route", "egress IP", addr, "destination", r.Dst)

		if err := netlink.RouteDel(&netlink.Route{
			Dst:      r.Dst,
			Src:      addr.AsSlice(),
			Table:    RouteTableEgressGatewayIPAM,
			Protocol: linux_defaults.RTProto,
		}); err != nil {
			return fmt.Errorf("failed to delete route for egress IP %s while pruning: %w", addr, err)
		}
	}

	return nil
}

func newOps(logger *slog.Logger) *ops {
	return &ops{logger}
}

type ops struct {
	logger *slog.Logger
}

var _ reconciler.Operations[*tables.EgressIPEntry] = &ops{}

func addrForEgressIP(addr netip.Addr) *netlink.Addr {
	return &netlink.Addr{IPNet: netipx.AddrIPNet(addr)}
}

func ruleForEgressIP(addr netip.Addr) route.Rule {
	return route.Rule{
		Priority: RulePriorityEgressGatewayIPAM,
		From:     netipx.AddrIPNet(addr),
		Table:    RouteTableEgressGatewayIPAM,
		Protocol: linux_defaults.RTProto,
	}
}

func routeForEgressIP(addr netip.Addr, dest netip.Prefix, iface netlink.Link) route.Route {
	return route.Route{
		Prefix: prefixToIPNet(dest),
		Local:  addr.AsSlice(),
		Device: iface.Attrs().Name,
		Table:  RouteTableEgressGatewayIPAM,
		Proto:  linux_defaults.RTProto,
	}
}

func prefixToIPNet(prefix netip.Prefix) net.IPNet {
	prefix = prefix.Masked()
	return net.IPNet{
		IP:   prefix.Addr().AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}

func ipNetToPrefix(prefix net.IPNet) netip.Prefix {
	addr, _ := netip.AddrFromSlice(prefix.IP)
	cidr, _ := prefix.Mask.Size()
	return netip.PrefixFrom(addr, cidr)
}

func rulesFilter() (*netlink.Rule, uint64) {
	return &netlink.Rule{
		Priority: RulePriorityEgressGatewayIPAM,
		Table:    RouteTableEgressGatewayIPAM,
		Protocol: linux_defaults.RTProto,
	}, netlink.RT_FILTER_PRIORITY | netlink.RT_FILTER_TABLE | netlink.RT_FILTER_PROTOCOL
}

func routesFilter() (*netlink.Route, uint64) {
	return &netlink.Route{
		Table:    RouteTableEgressGatewayIPAM,
		Protocol: unix.RTPROT_KERNEL,
	}, netlink.RT_FILTER_TABLE | netlink.RT_FILTER_PROTOCOL
}
