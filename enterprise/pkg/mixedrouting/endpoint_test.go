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
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging"
	ipcmap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/types"
)

type fakeEPEntry struct {
	op       op
	prefix   string
	hostIP   net.IP
	hostKey  uint8
	k8sMeta  *ipcache.K8sMetadata
	identity ipcache.Identity
}

type fakeEPDownstream struct {
	ops []fakeEPEntry
}

func (fed *fakeEPDownstream) Upsert(prefix string, hostIP net.IP, hostKey uint8,
	k8sMeta *ipcache.K8sMetadata, identity ipcache.Identity) (bool, error) {
	fed.ops = append(fed.ops, fakeEPEntry{opUpsert, prefix, hostIP, hostKey, k8sMeta, identity})
	return false, nil
}

func (fed *fakeEPDownstream) Delete(prefix string, _ source.Source) bool {
	fed.ops = append(fed.ops, fakeEPEntry{op: opDelete, prefix: prefix})
	return false
}

func (fed *fakeEPDownstream) sort() {
	sort.SliceStable(fed.ops, func(i, j int) bool {
		return fed.ops[i].prefix < fed.ops[j].prefix
	})
}

func (fed *fakeEPDownstream) clear() { fed.ops = nil }

func TestEndpointManager(t *testing.T) {
	var fed fakeEPDownstream
	mgr := endpointManager{
		logger: logging.DefaultLogger, debug: true,
		downstream: &fed,
		prefixes:   newPrefixCache(),
	}

	tep1 := net.ParseIP("172.18.0.1")
	tep2 := net.ParseIP("172.18.0.2")
	tep3 := net.ParseIP("172.18.0.3")

	meta1 := ipcache.K8sMetadata{Namespace: "foo"}
	meta2 := ipcache.K8sMetadata{Namespace: "bar"}
	meta3 := ipcache.K8sMetadata{Namespace: "baz"}

	id1 := ipcache.Identity{ID: 1}
	id2 := ipcache.Identity{ID: 2}
	id3 := ipcache.Identity{ID: 3}

	// The upsertion of an entry associated with no tunnel endpoint should propagate immediately.
	mgr.Upsert("10.0.0.1", net.IPv4zero, 91, &meta1, id1)
	require.Len(t, fed.ops, 1, "Upsertion should have been propagated to downstream")
	require.Equal(t, fakeEPEntry{opUpsert, "10.0.0.1", net.IPv4zero, 91, &meta1, id1}, fed.ops[0])
	fed.clear()

	// The upsertion of an entry associated with a known tunnel endpoint should propagate immediately.
	mgr.setMapping(tep1, routingModeVXLAN)
	mgr.Upsert("10.0.0.2", tep1, 92, &meta2, id2)
	require.Len(t, fed.ops, 1, "Upsertion should have been propagated to downstream")
	require.Equal(t, fakeEPEntry{opUpsert, "10.0.0.2", tep1, 92, &meta2, id2}, fed.ops[0])
	fed.clear()

	// The upsertion of entries not associated with any known tunnel endpoint should be buffered.
	mgr.Upsert("10.0.0.3", tep2, 93, &meta3, id3)
	mgr.Upsert("10.0.0.4", tep2, 94, &meta1, id2)
	mgr.Upsert("10.0.0.5", tep2, 99, &meta1, id3)
	mgr.Upsert("10.0.0.6", tep3, 96, &meta2, id3)
	mgr.Delete("10.0.0.4", source.KVStore)
	mgr.Upsert("10.0.0.5", tep2, 95, &meta1, id3)
	require.Len(t, fed.ops, 0, "Upsertions should have been buffered")

	// The configuration of a tunnel endpoint mapping should trigger the upsertion of buffered entries.
	mgr.setMapping(tep2, routingModeNative)
	require.Len(t, fed.ops, 2, "Upsertions should have been propagated to downstream")
	fed.sort() // Ensure deterministic order as spilled out from map.
	require.Equal(t, fakeEPEntry{opUpsert, "10.0.0.3", tep2, 93, &meta3, id3}, fed.ops[0])
	require.Equal(t, fakeEPEntry{opUpsert, "10.0.0.5", tep2, 95, &meta1, id3}, fed.ops[1])
	fed.clear()

	// The change of the routing mode should trigger a synthetic deletion+upsertion event.
	mgr.setMapping(tep2, routingModeGeneve)
	require.Len(t, fed.ops, 4, "Synthetic upsertions and deletions should have been generated")
	fed.sort() // Ensure deterministic order as spilled out from map.
	require.Equal(t, fakeEPEntry{op: opDelete, prefix: "10.0.0.3"}, fed.ops[0])
	require.Equal(t, fakeEPEntry{opUpsert, "10.0.0.3", tep2, 93, &meta3, id3}, fed.ops[1])
	require.Equal(t, fakeEPEntry{op: opDelete, prefix: "10.0.0.5"}, fed.ops[2])
	require.Equal(t, fakeEPEntry{opUpsert, "10.0.0.5", tep2, 95, &meta1, id3}, fed.ops[3])
	fed.clear()

	// A no-op change of the routing mode should not trigger events.
	mgr.setMapping(tep2, routingModeVXLAN)
	require.Len(t, fed.ops, 0, "Synthetic upsertions and deletions should not have been generated")

	// A tunnel endpoint change for an existing prefix should propagate if known.
	mgr.Upsert("10.0.0.3", tep1, 93, &meta3, id3)
	require.Len(t, fed.ops, 1, "Upsertion should have been propagated to downstream")
	require.Equal(t, fakeEPEntry{opUpsert, "10.0.0.3", tep1, 93, &meta3, id3}, fed.ops[0])
	fed.clear()

	// A tunnel endpoint change for an existing prefix should trigger a synthetic
	// deletion if not known, while buffering the upsertion event...
	mgr.Upsert("10.0.0.5", tep3, 95, &meta1, id3)
	require.Len(t, fed.ops, 1, "A synthetic deletion should have been propagated to downsteam")
	require.Equal(t, fakeEPEntry{op: opDelete, prefix: "10.0.0.5"}, fed.ops[0])
	fed.clear()

	// ... which should be emitted when the mapping is eventually configured.
	mgr.setMapping(tep3, routingModeNative)
	require.Len(t, fed.ops, 2, "Upsertion should have been propagated to downstream")
	fed.sort() // Ensure deterministic order as spilled out from map.
	require.Equal(t, fakeEPEntry{opUpsert, "10.0.0.5", tep3, 95, &meta1, id3}, fed.ops[0])
	require.Equal(t, fakeEPEntry{opUpsert, "10.0.0.6", tep3, 96, &meta2, id3}, fed.ops[1])
	fed.clear()

	// Unsetting mappings should not trigger any event propagation
	mgr.unsetMapping(tep1)
	mgr.unsetMapping(tep3)
	require.Len(t, fed.ops, 0, "No event should have been propagated to downstream")

	// And a subsequent reconfiguration should trigger deletions+upsertions for known entries.
	mgr.setMapping(tep1, routingModeGeneve)
	require.Len(t, fed.ops, 4, "Synthetic upsertions and deletions should have been generated")
	fed.sort() // Ensure deterministic order as spilled out from map.
	require.Equal(t, fakeEPEntry{op: opDelete, prefix: "10.0.0.2"}, fed.ops[0])
	require.Equal(t, fakeEPEntry{opUpsert, "10.0.0.2", tep1, 92, &meta2, id2}, fed.ops[1])
	require.Equal(t, fakeEPEntry{op: opDelete, prefix: "10.0.0.3"}, fed.ops[2])
	require.Equal(t, fakeEPEntry{opUpsert, "10.0.0.3", tep1, 93, &meta3, id3}, fed.ops[3])
	fed.clear()

	// The deletion of an entry previously propagated should propagate immediately.
	mgr.Delete("10.0.0.1", source.KVStore)
	mgr.Delete("10.0.0.2", source.KVStore)
	require.Len(t, fed.ops, 2, "Deletion should have been propagated to downstream")
	require.Equal(t, fakeEPEntry{op: opDelete, prefix: "10.0.0.1"}, fed.ops[0])
	require.Equal(t, fakeEPEntry{op: opDelete, prefix: "10.0.0.2"}, fed.ops[1])
	fed.clear()
}

func TestEndpointManagerMutateRemoteEndpointInfo(t *testing.T) {
	const (
		tunnelSkipFlagUnset = ipcmap.RemoteEndpointInfoFlags(0)
		tunnelSkipFlagSet   = ipcmap.RemoteEndpointInfoFlags(1)
	)

	te := types.IPv4(net.ParseIP("10.255.0.1").To4())
	tests := []struct {
		name     string
		key      ipcmap.Key
		rei      ipcmap.RemoteEndpointInfo
		primary  routingModeType
		init     func(em *endpointManager)
		expected ipcmap.RemoteEndpointInfoFlags
	}{
		{
			name:     "Tunnel endpoint match, should unset",
			key:      ipcmap.NewKey(net.ParseIP("10.0.0.4"), net.CIDRMask(32, 32), 0),
			rei:      ipcmap.RemoteEndpointInfo{TunnelEndpoint: te, Flags: tunnelSkipFlagSet},
			primary:  routingModeNative,
			init:     func(em *endpointManager) { em.setMapping(net.ParseIP("10.255.0.1"), routingModeVXLAN) },
			expected: tunnelSkipFlagUnset,
		},
		{
			name:     "Tunnel endpoint match, should set",
			key:      ipcmap.NewKey(net.ParseIP("10.0.0.4"), net.CIDRMask(32, 32), 0),
			rei:      ipcmap.RemoteEndpointInfo{TunnelEndpoint: te, Flags: tunnelSkipFlagUnset},
			primary:  routingModeGeneve,
			init:     func(em *endpointManager) { em.setMapping(net.ParseIP("10.255.0.1"), routingModeNative) },
			expected: tunnelSkipFlagSet,
		},
		{
			name:     "Prefix match (single IP), IPv4",
			key:      ipcmap.NewKey(net.ParseIP("10.0.0.4"), net.CIDRMask(32, 32), 0),
			rei:      ipcmap.RemoteEndpointInfo{TunnelEndpoint: types.IPv4{}, Flags: tunnelSkipFlagSet},
			primary:  routingModeNative,
			init:     func(em *endpointManager) { em.setMapping(net.ParseIP("10.0.0.4"), routingModeGeneve) },
			expected: tunnelSkipFlagUnset,
		},
		{
			name:     "Prefix match (single IP), IPv6",
			key:      ipcmap.NewKey(net.ParseIP("fd00::4"), net.CIDRMask(128, 128), 0),
			rei:      ipcmap.RemoteEndpointInfo{TunnelEndpoint: types.IPv4{}, Flags: tunnelSkipFlagUnset},
			primary:  routingModeVXLAN,
			init:     func(em *endpointManager) { em.setMapping(net.ParseIP("fd00::4"), routingModeNative) },
			expected: tunnelSkipFlagSet,
		},
		{
			name:     "Prefix match, should default to primary",
			key:      ipcmap.NewKey(net.ParseIP("10.0.0.4"), net.CIDRMask(30, 32), 0),
			rei:      ipcmap.RemoteEndpointInfo{TunnelEndpoint: types.IPv4{}, Flags: tunnelSkipFlagUnset},
			primary:  routingModeNative,
			init:     func(em *endpointManager) { em.setMapping(net.ParseIP("10.0.0.4"), routingModeVXLAN) },
			expected: tunnelSkipFlagSet,
		},
		{
			name:    "No match, should default to primary",
			key:     ipcmap.NewKey(net.ParseIP("10.0.0.4"), net.CIDRMask(30, 32), 0),
			rei:     ipcmap.RemoteEndpointInfo{TunnelEndpoint: te, Flags: tunnelSkipFlagSet},
			primary: routingModeGeneve,
			init: func(em *endpointManager) {
				em.setMapping(net.ParseIP("10.0.0.1"), routingModeGeneve)
				em.setMapping(net.ParseIP("10.0.0.4"), routingModeGeneve)
				em.unsetMapping(net.ParseIP("10.0.0.4"))
			},
			expected: tunnelSkipFlagUnset,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			em := endpointManager{
				logger: logging.DefaultLogger, debug: true,
				modes: routingModesType{tt.primary},
			}

			tt.init(&em)
			em.mutateRemoteEndpointInfo(&tt.key, &tt.rei)
			require.Equal(t, tt.expected, tt.rei.Flags)
		})
	}
}
