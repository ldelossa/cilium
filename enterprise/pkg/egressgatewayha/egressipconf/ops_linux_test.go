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
	"net/netip"
	"testing"

	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"

	"github.com/cilium/cilium/enterprise/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestOps(t *testing.T) {
	testutils.PrivilegedTest(t)

	var (
		nlh *netlink.Handle
		err error
	)

	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		nlh, err = netlink.NewHandle()
		return err
	}))
	t.Cleanup(func() {
		ns.Close()
	})

	// Create a dummy device to test with
	err = nlh.LinkAdd(
		&netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: "dummy0",
			},
		},
	)
	require.NoError(t, err, "LinkAdd")
	link, err := nlh.LinkByName("dummy0")
	require.NoError(t, err, "LinkByName")
	require.NoError(t, err, nlh.LinkSetUp(link))
	ifIndex := link.Attrs().Index
	ifName := link.Attrs().Name

	egressIP := netip.MustParseAddr("192.168.1.50")

	ops := &ops{}

	// Initial Update()
	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, &tables.EgressIPEntry{
			Addr:      egressIP,
			Interface: ifName,
			Status:    reconciler.StatusPending(),
		})
	})
	require.NoError(t, err, "expected no error from initial update")

	// Egress IP should have been added to device
	nlAddrs, err := nlh.AddrList(link, netlink.FAMILY_V4)
	require.NoError(t, err, "netlink.AddrList")

	addrs := make([]netip.Addr, 0, len(nlAddrs))
	for _, nlAddr := range nlAddrs {
		addr, _ := netip.AddrFromSlice(nlAddr.IP)
		addrs = append(addrs, addr)
	}
	require.Containsf(t, addrs, egressIP, "egress IP %s not found in %s device", egressIP, ifName)

	// Source-based routing rule should have been installed for Egress IP
	rules, err := nlh.RuleListFiltered(
		netlink.FAMILY_V4,
		&netlink.Rule{
			Priority: RulePriorityEgressGatewayIPAM,
			Src:      netipx.AddrIPNet(egressIP),
			Table:    RouteTableEgressGatewayIPAM,
			Protocol: linux_defaults.RTProto,
		},
		netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_SRC|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	require.NoError(t, err, "RuleListFiltered")
	require.Equalf(t, 1, len(rules), "no rule found for egress IP %s", egressIP)

	// Route should have been installed for Egress IP
	routes, err := nlh.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{
			Dst:       &defaults.IPv4DefaultRoute,
			Src:       egressIP.AsSlice(),
			LinkIndex: ifIndex,
			Table:     RouteTableEgressGatewayIPAM,
			Protocol:  linux_defaults.RTProto,
		},
		netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_IIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	require.NoError(t, err, "RouteListFiltered")
	require.Equalf(t, 1, len(routes), "no route found for egress IP %s", egressIP)

	// Further Update() should not do anything
	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, &tables.EgressIPEntry{
			Addr:      egressIP,
			Interface: ifName,
			Status:    reconciler.StatusPending(),
		})
	})
	require.NoError(t, err, "expected no error from second update")

	// Non-existing devices return an error
	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, &tables.EgressIPEntry{
			Addr:      egressIP,
			Interface: "non-existent",
		})
	})
	require.Error(t, err, "expected error from update of non-existing device")

	// Delete()
	err = ns.Do(func() error {
		return ops.Delete(context.Background(), nil, &tables.EgressIPEntry{
			Addr:      egressIP,
			Interface: ifName,
			Status:    reconciler.StatusPending(),
		})
	})
	require.NoError(t, err, "expected no error from delete")

	// Egress IP should have been removed from device
	nlAddrs, err = nlh.AddrList(link, netlink.FAMILY_V4)
	require.NoError(t, err, "netlink.AddrList")

	addrs = make([]netip.Addr, 0, len(nlAddrs))
	for _, nlAddr := range nlAddrs {
		addr, _ := netip.AddrFromSlice(nlAddr.IP)
		addrs = append(addrs, addr)
	}
	require.NotContainsf(t, addrs, egressIP, "egress IP %s found in %s device after deletion", egressIP, ifName)

	// Source-based routing rule should have been removed for Egress IP
	rules, err = nlh.RuleListFiltered(
		netlink.FAMILY_V4,
		&netlink.Rule{
			Priority: RulePriorityEgressGatewayIPAM,
			Src:      netipx.AddrIPNet(egressIP),
			Table:    RouteTableEgressGatewayIPAM,
			Protocol: linux_defaults.RTProto,
		},
		netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_SRC|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	require.NoError(t, err, "RuleListFiltered")
	require.Equalf(t, 0, len(rules), "rule found for egress IP %s after deletion", egressIP)

	// Route should have been removed for Egress IP
	routes, err = nlh.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{
			Dst:       &defaults.IPv4DefaultRoute,
			Src:       egressIP.AsSlice(),
			LinkIndex: ifIndex,
			Table:     RouteTableEgressGatewayIPAM,
			Protocol:  linux_defaults.RTProto,
		},
		netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_IIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	require.NoError(t, err, "RouteListFiltered")
	require.Equalf(t, 0, len(routes), "route found for egress IP %s after deletion", egressIP)

	// Further Delete() should not do anything
	err = ns.Do(func() error {
		return ops.Delete(context.Background(), nil, &tables.EgressIPEntry{
			Addr:      egressIP,
			Interface: ifName,
			Status:    reconciler.StatusPending(),
		})
	})
	require.NoError(t, err, "expected no error from delete")

	// Non-existing devices return an error
	err = ns.Do(func() error {
		return ops.Delete(context.Background(), nil, &tables.EgressIPEntry{
			Addr:      egressIP,
			Interface: "non-existent",
		})
	})
	require.Error(t, err, "expected error from delete of non-existing device")
}
