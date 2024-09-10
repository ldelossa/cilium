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
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"

	"github.com/cilium/cilium/enterprise/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
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
	destinations := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("192.168.2.0/24")}

	ops := &ops{}

	// Initial Update()
	entry := &tables.EgressIPEntry{
		Addr:         egressIP,
		Interface:    ifName,
		Destinations: destinations,
		Status:       reconciler.StatusPending(),
	}

	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, entry)
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

	// Routes should have been installed for Egress IP
	dst_1, dst_2 := prefixToIPNet(destinations[0]), prefixToIPNet(destinations[1])

	routes, err := nlh.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{
			Dst:       &dst_1,
			Src:       egressIP.AsSlice(),
			LinkIndex: ifIndex,
			Table:     RouteTableEgressGatewayIPAM,
			Protocol:  linux_defaults.RTProto,
		},
		netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	require.NoError(t, err, "RouteListFiltered")
	require.Equalf(t, 1, len(routes), "no route found for egress IP %s and dest %s", egressIP, destinations[0])

	routes, err = nlh.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{
			Dst:       &dst_2,
			Src:       egressIP.AsSlice(),
			LinkIndex: ifIndex,
			Table:     RouteTableEgressGatewayIPAM,
			Protocol:  linux_defaults.RTProto,
		},
		netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	require.NoError(t, err, "RouteListFiltered")
	require.Equalf(t, 1, len(routes), "no route found for egress IP %s and dest %s", egressIP, destinations[1])

	// Further Update() with the same entry should not do anything
	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, entry)
	})
	require.NoError(t, err, "expected no error from second update")

	// Update() with a different list of destinations should update the routes
	updDests := []netip.Prefix{netip.MustParsePrefix("192.168.2.0/24"), netip.MustParsePrefix("192.168.3.0/24")}

	updEntry := &tables.EgressIPEntry{
		Addr:         entry.Addr,
		Interface:    entry.Interface,
		Destinations: updDests,
		Status:       reconciler.StatusPending(),
	}

	err = ns.Do(func() error {
		return ops.Update(context.Background(), nil, updEntry)
	})
	require.NoError(t, err, "expected no error from initial update")

	// Routes should have been installed for Egress IP
	updDst_1, updDst_2 := prefixToIPNet(updDests[0]), prefixToIPNet(updDests[1])

	routes, err = nlh.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{
			Dst:       &updDst_1,
			Src:       egressIP.AsSlice(),
			LinkIndex: ifIndex,
			Table:     RouteTableEgressGatewayIPAM,
			Protocol:  linux_defaults.RTProto,
		},
		netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	require.NoError(t, err, "RouteListFiltered")
	require.Equalf(t, 1, len(routes), "no route found for egress IP %s and dest %s", egressIP, updDests[0])

	routes, err = nlh.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{
			Dst:       &updDst_2,
			Src:       egressIP.AsSlice(),
			LinkIndex: ifIndex,
			Table:     RouteTableEgressGatewayIPAM,
			Protocol:  linux_defaults.RTProto,
		},
		netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	require.NoError(t, err, "RouteListFiltered")
	require.Equalf(t, 1, len(routes), "no route found for egress IP %s and dest %s", egressIP, updDests[1])

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

	// Routes should have been removed for Egress IP
	routes, err = nlh.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{
			Dst:       &updDst_1,
			Src:       egressIP.AsSlice(),
			LinkIndex: ifIndex,
			Table:     RouteTableEgressGatewayIPAM,
			Protocol:  linux_defaults.RTProto,
		},
		netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_IIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	require.NoError(t, err, "RouteListFiltered")
	require.Equalf(t, 0, len(routes), "route found for egress IP %s and dest %s after deletion", egressIP, updDests[0])

	routes, err = nlh.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{
			Dst:       &updDst_2,
			Src:       egressIP.AsSlice(),
			LinkIndex: ifIndex,
			Table:     RouteTableEgressGatewayIPAM,
			Protocol:  linux_defaults.RTProto,
		},
		netlink.RT_FILTER_DST|netlink.RT_FILTER_SRC|netlink.RT_FILTER_IIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	require.NoError(t, err, "RouteListFiltered")
	require.Equalf(t, 0, len(routes), "route found for egress IP %s and dest %s after deletion", egressIP, updDests[1])

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

func TestPrune(t *testing.T) {
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
	ifName := link.Attrs().Name
	ifIndex := link.Attrs().Index

	ops := &ops{}

	egressIP_1 := netip.MustParseAddr("192.168.1.50")
	destinations_1_1 := netip.MustParsePrefix("192.168.1.0/24")
	destinations_1_2 := netip.MustParsePrefix("192.168.2.0/24")
	egressIP_2 := netip.MustParseAddr("192.168.1.100")
	destinations_2_1 := netip.MustParsePrefix("192.168.3.0/24")
	destinations_2_2 := netip.MustParsePrefix("192.168.4.0/24")

	entries := []*tables.EgressIPEntry{
		{
			Addr:         egressIP_1,
			Interface:    ifName,
			Destinations: []netip.Prefix{destinations_1_1, destinations_1_2},
		},
		{
			Addr:         egressIP_2,
			Interface:    ifName,
			Destinations: []netip.Prefix{destinations_2_1, destinations_2_2},
		},
	}

	// call Update() to reconcile network config as specified in the entries
	for _, entry := range entries {
		err = ns.Do(func() error {
			return ops.Update(context.Background(), nil, entry)
		})
		require.NoError(t, err, "ops.Update")
	}

	// build a fake iterator containing entries for:
	//
	// <egressIP_2, destinations_2_1>
	// <egressIP_2, destinations_2_2>
	//
	// then call Prune
	err = ns.Do(func() error {
		return ops.Prune(context.Background(), nil, newFakeIterator(&tables.EgressIPEntry{
			Addr:         egressIP_2,
			Interface:    ifName,
			Destinations: []netip.Prefix{destinations_2_1, destinations_2_2},
		}))
	})
	require.NoError(t, err, "ops.Prune")

	// egress IPs should have been left untouched
	nlAddrs, err := nlh.AddrList(link, netlink.FAMILY_V4)
	require.NoError(t, err, "netlink.AddrList")
	addrs := make([]netip.Addr, 0, len(nlAddrs))
	for _, nlAddr := range nlAddrs {
		addr, _ := netip.AddrFromSlice(nlAddr.IP)
		addrs = append(addrs, addr)
	}
	require.ElementsMatch(t, addrs, []netip.Addr{egressIP_1, egressIP_2})

	// only the rule for egressIP_1 should have been deleted
	rules, err := nlh.RuleListFiltered(
		netlink.FAMILY_V4,
		&netlink.Rule{
			Priority: RulePriorityEgressGatewayIPAM,
			Table:    RouteTableEgressGatewayIPAM,
			Protocol: linux_defaults.RTProto,
		},
		netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	require.NoError(t, err, "RuleListFiltered")
	require.Len(t, rules, 1)
	require.Equal(t, netipx.AddrIPNet(egressIP_2), rules[0].Src)

	// only routes for egressIP_1 should have been deleted
	routes, err := nlh.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{
			LinkIndex: ifIndex,
			Table:     RouteTableEgressGatewayIPAM,
			Protocol:  linux_defaults.RTProto,
		},
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	require.NoError(t, err, "RouteListFiltered")
	require.Len(t, routes, 2)
	require.Equal(t, net.IP(egressIP_2.AsSlice()), routes[0].Src)
	require.Equal(t, net.IP(egressIP_2.AsSlice()), routes[1].Src)
	found := []*net.IPNet{routes[0].Dst, routes[1].Dst}
	require.ElementsMatch(t, []*net.IPNet{netipx.PrefixIPNet(destinations_2_1), netipx.PrefixIPNet(destinations_2_2)}, found)

	// call again Update() to reconcile network config as specified in the entries
	for _, entry := range entries {
		err = ns.Do(func() error {
			return ops.Update(context.Background(), nil, entry)
		})
		require.NoError(t, err, "ops.Update")
	}

	// build a fake iterator containing an entry for:
	//
	// <egressIP_1, destinations_1_1>
	//
	// then call Prune
	err = ns.Do(func() error {
		return ops.Prune(context.Background(), nil, newFakeIterator(
			&tables.EgressIPEntry{
				Addr:         egressIP_1,
				Interface:    ifName,
				Destinations: []netip.Prefix{destinations_1_1},
			}))
	})
	require.NoError(t, err, "ops.Prune")

	// egress IPs should have been left untouched
	nlAddrs, err = nlh.AddrList(link, netlink.FAMILY_V4)
	require.NoError(t, err, "netlink.AddrList")
	addrs = make([]netip.Addr, 0, len(nlAddrs))
	for _, nlAddr := range nlAddrs {
		addr, _ := netip.AddrFromSlice(nlAddr.IP)
		addrs = append(addrs, addr)
	}
	require.ElementsMatch(t, addrs, []netip.Addr{egressIP_1, egressIP_2})

	// only the rule for egressIP_2 should have been deleted
	rules, err = nlh.RuleListFiltered(
		netlink.FAMILY_V4,
		&netlink.Rule{
			Priority: RulePriorityEgressGatewayIPAM,
			Table:    RouteTableEgressGatewayIPAM,
			Protocol: linux_defaults.RTProto,
		},
		netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	require.NoError(t, err, "RuleListFiltered")
	require.Len(t, rules, 1)
	require.Equal(t, netipx.AddrIPNet(egressIP_1), rules[0].Src)

	// only routes for:
	//
	// <egressIP_1, destination_1_2>
	// <egressIP_2, destination_2_2>
	// <egressIP_2, destination_2_2>
	//
	// should have been deleted
	routes, err = nlh.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{
			LinkIndex: ifIndex,
			Table:     RouteTableEgressGatewayIPAM,
			Protocol:  linux_defaults.RTProto,
		},
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	require.NoError(t, err, "RouteListFiltered")
	require.Len(t, routes, 1)
	require.Equal(t, net.IP(egressIP_1.AsSlice()), routes[0].Src)
	require.Equal(t, netipx.PrefixIPNet(destinations_1_1), routes[0].Dst)

	// build a fake empty iterator and call Prune
	err = ns.Do(func() error {
		return ops.Prune(context.Background(), nil, newFakeIterator())
	})
	require.NoError(t, err, "ops.Prune")

	// egress IPs should have been left untouched
	nlAddrs, err = nlh.AddrList(link, netlink.FAMILY_V4)
	require.NoError(t, err, "netlink.AddrList")
	addrs = make([]netip.Addr, 0, len(nlAddrs))
	for _, nlAddr := range nlAddrs {
		addr, _ := netip.AddrFromSlice(nlAddr.IP)
		addrs = append(addrs, addr)
	}
	require.ElementsMatch(t, addrs, []netip.Addr{egressIP_1, egressIP_2})

	// all rules should have been deleted
	rules, err = nlh.RuleListFiltered(
		netlink.FAMILY_V4,
		&netlink.Rule{
			Priority: RulePriorityEgressGatewayIPAM,
			Table:    RouteTableEgressGatewayIPAM,
			Protocol: linux_defaults.RTProto,
		},
		netlink.RT_FILTER_PRIORITY|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	require.NoError(t, err, "RuleListFiltered")
	require.Empty(t, rules)

	// all routes should have been deleted
	routes, err = nlh.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{
			LinkIndex: ifIndex,
			Table:     RouteTableEgressGatewayIPAM,
			Protocol:  linux_defaults.RTProto,
		},
		netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL,
	)
	require.NoError(t, err, "RouteListFiltered")
	require.Empty(t, routes)
}

type fakeIterator struct {
	objs []*tables.EgressIPEntry
}

func newFakeIterator(objs ...*tables.EgressIPEntry) *fakeIterator {
	return &fakeIterator{objs: objs}
}

func (i *fakeIterator) Next() (*tables.EgressIPEntry, statedb.Revision, bool) {
	if len(i.objs) == 0 {
		return nil, 0, false
	}
	obj := i.objs[0]
	i.objs = i.objs[1:]
	return obj, 0, true
}
