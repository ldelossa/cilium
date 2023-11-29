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
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/slices"
)

type op string

const (
	opUpsert = op("upsert")
	opDelete = op("delete")
)

type fakeNodeEntry struct {
	op   op
	node nodeTypes.Node
}

type fakeNodeDownstream struct {
	ops      []fakeNodeEntry
	ipsetter nodemanager.CEIPSetManager
	nodeIPs  []string
}

func newFakeNodeDownstream(ipsetter nodemanager.CEIPSetManager) *fakeNodeDownstream {
	return &fakeNodeDownstream{ipsetter: ipsetter}
}

func (fd *fakeNodeDownstream) clear() { fd.ops = nil }

func (fd *fakeNodeDownstream) NodeUpdated(node nodeTypes.Node) {
	fd.ops = append(fd.ops, fakeNodeEntry{opUpsert, node})

	// Simulate the behavior of the real NodeUpdated implementation.
	var ipscache []string
	for _, addr := range node.IPAddresses {
		if addr.Type == addressing.NodeInternalIP {
			ipscache = append(ipscache, addr.IP.String())
			fd.ipsetter.AddToNodeIpset(addr.IP)
		}
	}

	for _, addr := range slices.Diff(fd.nodeIPs, ipscache) {
		fd.ipsetter.RemoveFromNodeIpset(net.ParseIP(addr))
	}

	fd.nodeIPs = ipscache
}

func (fd *fakeNodeDownstream) NodeDeleted(node nodeTypes.Node) {
	fd.ops = append(fd.ops, fakeNodeEntry{opDelete, node})
	for _, addr := range node.IPAddresses {
		if addr.Type == addressing.NodeInternalIP {
			fd.ipsetter.RemoveFromNodeIpset(addr.IP)
		}
	}
	fd.nodeIPs = nil
}

type fakeIPSetter map[string]struct{}

func newFakeIPSetter() fakeIPSetter                    { return make(map[string]struct{}) }
func (fis fakeIPSetter) AddToNodeIpset(ip net.IP)      { fis[ip.String()] = struct{}{} }
func (fis fakeIPSetter) RemoveFromNodeIpset(ip net.IP) { delete(fis, ip.String()) }

func newNode(name string, id uint32, modes routingModesType, internalIPs []string) *nodeTypes.Node {
	annotations := make(map[string]string)
	if len(modes) > 0 {
		annotations[SupportedRoutingModesKey] = modes.String()
	}

	addresses := []nodeTypes.Address{
		{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("10.255.0.1")},
		{Type: addressing.NodeExternalIP, IP: net.ParseIP("2001::beef")},
	}

	for _, ip := range internalIPs {
		addresses = append(addresses, nodeTypes.Address{Type: addressing.NodeInternalIP, IP: net.ParseIP(ip)})
	}

	return &nodeTypes.Node{Name: name, NodeIdentity: id, Annotations: annotations, IPAddresses: addresses}
}

func TestNodeManager(t *testing.T) {
	mgr := nodeManager{
		logger:   logging.DefaultLogger,
		modes:    routingModesType{routingModeNative, routingModeVXLAN},
		ipsetter: newFakeIPSetter(),
	}
	fd := newFakeNodeDownstream(&mgr)
	mgr.downstream = fd

	ips1 := []string{"10.1.2.3", "fd00::1234"}
	ips2 := []string{"10.1.2.3", "fd00::6789"}

	no1 := *newNode("foo", 1, []routingModeType{routingModeVXLAN}, ips1)
	no2 := *newNode("foo", 2, []routingModeType{routingModeVXLAN}, ips2)
	no3 := *newNode("foo", 3, []routingModeType{routingModeNative}, ips2)
	no4 := *newNode("foo", 4, []routingModeType{routingModeNative}, ips1)

	// Simulate the presence of a stale ipset entry
	mgr.ipsetter.AddToNodeIpset(net.ParseIP("10.1.2.3"))

	mgr.NodeUpdated(no1)
	require.Len(t, fd.ops, 1, "Insertion should propagate to downstream")
	require.Equal(t, fakeNodeEntry{opUpsert, no1}, fd.ops[0], "Insertion should propagate to downstream")
	require.Empty(t, mgr.ipsetter.(fakeIPSetter), "ipset not configured correctly")
	fd.clear()

	mgr.NodeUpdated(no2)
	require.Len(t, fd.ops, 1, "Update should propagate to downstream")
	require.Equal(t, fakeNodeEntry{opUpsert, no2}, fd.ops[0], "Update should propagate to downstream")
	require.Empty(t, mgr.ipsetter.(fakeIPSetter), "ipset not configured correctly")
	fd.clear()

	mgr.NodeUpdated(no3)
	require.Len(t, fd.ops, 2, "Routing mode change should trigger deletion followed by insertion")
	require.Equal(t, fakeNodeEntry{opDelete, no2}, fd.ops[0], "Routing mode change should trigger deletion followed by insertion")
	require.Equal(t, fakeNodeEntry{opUpsert, no3}, fd.ops[1], "Routing mode change should trigger deletion followed by insertion")
	require.ElementsMatch(t, maps.Keys(mgr.ipsetter.(fakeIPSetter)), ips2, "ipset not configured correctly")
	fd.clear()

	mgr.NodeUpdated(no4)
	require.Len(t, fd.ops, 1, "Update should propagate to downstream")
	require.Equal(t, fakeNodeEntry{opUpsert, no4}, fd.ops[0], "Update should propagate to downstream")
	require.ElementsMatch(t, maps.Keys(mgr.ipsetter.(fakeIPSetter)), ips1, "ipset not configured correctly")
	fd.clear()

	mgr.NodeUpdated(no2)
	require.Len(t, fd.ops, 2, "Routing mode change should trigger deletion followed by insertion")
	require.Equal(t, fakeNodeEntry{opDelete, no4}, fd.ops[0], "Routing mode change should trigger deletion followed by insertion")
	require.Equal(t, fakeNodeEntry{opUpsert, no2}, fd.ops[1], "Routing mode change should trigger deletion followed by insertion")
	require.Empty(t, mgr.ipsetter.(fakeIPSetter), "ipset not configured correctly")
	fd.clear()

	mgr.NodeDeleted(no2)
	require.Len(t, fd.ops, 1, "Deletion should propagate to downstream")
	require.Equal(t, fakeNodeEntry{opDelete, no2}, fd.ops[0], "Deletion should propagate to downstream")
	require.Empty(t, mgr.ipsetter.(fakeIPSetter), "ipset not configured correctly")
	fd.clear()
}

func TestNodeManagerNeedsEncapsulation(t *testing.T) {
	tests := []struct {
		local    routingModesType
		remote   routingModesType
		expected bool
	}{
		{
			local:    routingModesType{routingModeVXLAN, routingModeNative},
			expected: true,
		},
		{
			local:    routingModesType{routingModeNative},
			remote:   routingModesType{routingModeNative},
			expected: false,
		},
		{
			local:    routingModesType{routingModeNative, routingModeVXLAN},
			remote:   routingModesType{routingModeVXLAN},
			expected: true,
		},
		{
			local:    routingModesType{routingModeNative},
			remote:   routingModesType{routingModeGeneve, routingModeNative},
			expected: false,
		},
		{
			// No match is found. Although this is an error, we fallback to the
			// local primary mode, which is tunneling in this case.
			local:    routingModesType{routingModeGeneve},
			remote:   routingModesType{routingModeNative},
			expected: true,
		},
		{
			// Invalid routing mode. Although this is an error, we fallback to
			// the local primary mode, which is native in this case.
			local:    routingModesType{routingModeNative},
			remote:   routingModesType{"incorrect"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s|%s", tt.local, tt.remote), func(t *testing.T) {
			mgr := nodeManager{logger: logging.DefaultLogger, modes: tt.local}
			require.Equal(t, tt.expected, mgr.needsEncapsulation(newNode("foo", 0, tt.remote, nil)))
		})
	}
}
