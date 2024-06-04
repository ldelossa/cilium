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
	"github.com/cilium/cilium/pkg/defaults"
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

	if err := route.Upsert(routeForEgressIP(entry.Addr, iface)); err != nil {
		return fmt.Errorf("failed to append route for egress IP %s and interface %s", entry.Addr, iface.Attrs().Name)
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
		return fmt.Errorf("failed to upsert rule for address %s: %w", entry.Addr, err)
	}

	if err := route.DeleteV4(routeForEgressIP(entry.Addr, iface)); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("failed to delete route for egress IP %s and interface %s", entry.Addr, iface.Attrs().Name)
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

func routeForEgressIP(addr netip.Addr, iface netlink.Link) route.Route {
	return route.Route{
		Prefix: defaults.IPv4DefaultRoute,
		Local:  addr.AsSlice(),
		Device: iface.Attrs().Name,
		Table:  RouteTableEgressGatewayIPAM,
		Proto:  linux_defaults.RTProto,
	}
}
