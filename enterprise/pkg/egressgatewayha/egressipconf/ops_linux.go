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
	"net"
	"net/netip"
	"os"
	"syscall"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/enterprise/datapath/tables"
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

	if err := netlink.AddrAdd(iface, addrForEgressIP(entry.Addr)); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("failed to add egress IP %s to interface %s", entry.Addr, iface.Attrs().Name)
	}

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

	if err := netlink.AddrDel(iface, addrForEgressIP(entry.Addr)); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
		return fmt.Errorf("failed to delete egress IP %s to interface %s", entry.Addr, iface.Attrs().Name)
	}

	if err := route.DeleteRule(netlink.FAMILY_V4, ruleForEgressIP(entry.Addr)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to delete rule for address %s: %w", entry.Addr, err)
	}

	for _, dest := range entry.Destinations {
		if err := route.DeleteV4(routeForEgressIP(entry.Addr, dest, iface)); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("failed to delete route for egress IP %s and interface %s: %w", entry.Addr, iface.Attrs().Name, err)
		}
	}

	return nil
}

func (ops *ops) Prune(ctx context.Context, _ statedb.ReadTxn, iter statedb.Iterator[*tables.EgressIPEntry]) error {
	// addresses not in the table will never be pruned
	return nil
}

func newOps() *ops {
	return &ops{}
}

type ops struct{}

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
