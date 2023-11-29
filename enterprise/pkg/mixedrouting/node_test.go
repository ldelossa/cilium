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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/logging"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
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
	ops []fakeNodeEntry
}

func newFakeNodeDownstream() *fakeNodeDownstream {
	return &fakeNodeDownstream{}
}

func (fd *fakeNodeDownstream) clear() { fd.ops = nil }

func (fd *fakeNodeDownstream) NodeUpdated(node nodeTypes.Node) {
	fd.ops = append(fd.ops, fakeNodeEntry{opUpsert, node})
}

func (fd *fakeNodeDownstream) NodeDeleted(node nodeTypes.Node) {
	fd.ops = append(fd.ops, fakeNodeEntry{opDelete, node})
}

func newNode(name string, id uint32, modes routingModesType) *nodeTypes.Node {
	annotations := make(map[string]string)
	if len(modes) > 0 {
		annotations[SupportedRoutingModesKey] = modes.String()
	}

	return &nodeTypes.Node{Name: name, NodeIdentity: id, Annotations: annotations}
}

func TestNodeManager(t *testing.T) {
	fd := newFakeNodeDownstream()
	mgr := nodeManager{
		logger:     logging.DefaultLogger,
		modes:      routingModesType{routingModeNative, routingModeVXLAN},
		downstream: fd,
	}

	no1 := *newNode("foo", 1, []routingModeType{routingModeVXLAN})
	no2 := *newNode("foo", 2, []routingModeType{routingModeVXLAN})
	no3 := *newNode("foo", 3, []routingModeType{routingModeNative})

	mgr.NodeUpdated(no1)
	require.Len(t, fd.ops, 1, "Insertion should propagate to downstream")
	require.Equal(t, fakeNodeEntry{opUpsert, no1}, fd.ops[0], "Insertion should propagate to downstream")
	fd.clear()

	mgr.NodeUpdated(no2)
	require.Len(t, fd.ops, 1, "Update should propagate to downstream")
	require.Equal(t, fakeNodeEntry{opUpsert, no2}, fd.ops[0], "Update should propagate to downstream")
	fd.clear()

	mgr.NodeUpdated(no3)
	require.Len(t, fd.ops, 2, "Routing mode change should trigger deletion followed by insertion")
	require.Equal(t, fakeNodeEntry{opDelete, no2}, fd.ops[0], "Routing mode change should trigger deletion followed by insertion")
	require.Equal(t, fakeNodeEntry{opUpsert, no3}, fd.ops[1], "Routing mode change should trigger deletion followed by insertion")
	fd.clear()

	mgr.NodeUpdated(no2)
	require.Len(t, fd.ops, 2, "Routing mode change should trigger deletion followed by insertion")
	require.Equal(t, fakeNodeEntry{opDelete, no3}, fd.ops[0], "Routing mode change should trigger deletion followed by insertion")
	require.Equal(t, fakeNodeEntry{opUpsert, no2}, fd.ops[1], "Routing mode change should trigger deletion followed by insertion")
	fd.clear()

	mgr.NodeDeleted(no2)
	require.Len(t, fd.ops, 1, "Deletion should propagate to downstream")
	require.Equal(t, fakeNodeEntry{opDelete, no2}, fd.ops[0], "Deletion should propagate to downstream")
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
			require.Equal(t, tt.expected, mgr.needsEncapsulation(newNode("foo", 0, tt.remote)))
		})
	}
}
