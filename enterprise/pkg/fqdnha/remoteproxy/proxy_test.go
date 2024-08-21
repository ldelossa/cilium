//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package remoteproxy

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/cilium/dns"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	dnsproxypb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
)

type mockFQDNProxyClient struct {
	removed map[uint32]struct{}

	allowed map[string]*dnsproxypb.L7Rules
}

func newMockFQDNProxyClient() *mockFQDNProxyClient {
	return &mockFQDNProxyClient{
		removed: map[uint32]struct{}{},
		allowed: map[string]*dnsproxypb.L7Rules{},
	}
}

func (m *mockFQDNProxyClient) UpdateAllowed(
	ctx context.Context,
	in *dnsproxypb.FQDNRules,
	opts ...grpc.CallOption,
) (*dnsproxypb.Empty, error) {
	k := fmt.Sprintf("%d:%d:%d", in.EndpointID, in.DestProto, in.DestPort)
	if in.Rules == nil {
		delete(m.allowed, k)
	} else {
		m.allowed[k] = in.Rules
	}
	return nil, nil
}

func (m *mockFQDNProxyClient) RemoveRestoredRules(
	ctx context.Context,
	in *dnsproxypb.EndpointID,
	opts ...grpc.CallOption,
) (*dnsproxypb.Empty, error) {
	m.removed[in.EndpointID] = struct{}{}
	return nil, nil
}

func (m *mockFQDNProxyClient) GetRules(
	ctx context.Context,
	in *dnsproxypb.EndpointID,
	opts ...grpc.CallOption,
) (*dnsproxypb.RestoredRules, error) {
	return nil, nil
}

// Test that a client that connects never misses a single update, even if it disconnects and reconnects.
//
// This also ensures that we dump and load our state correctly, as we only intercept proxy updates
// after agent restarts.
func TestConnectionLifecycle(t *testing.T) {
	var remoteProxy *RemoteFQDNProxy

	localProxy, err := dnsproxy.StartDNSProxy(dnsproxy.DNSProxyConfig{
		Address: "127.0.0.2",
		IPv4:    false,
		IPv6:    false,
	},
		func(ip netip.Addr) (endpoint *endpoint.Endpoint, isHost bool, err error) { return nil, false, nil },
		nil,
		nil,
		func(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr string, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
			return nil
		},
	)

	require.Nil(t, err)
	t.Cleanup(localProxy.Cleanup)

	cs := mockCachedSelector("selector-string")

	allowExampleCom := policy.L7DataMap{
		cs: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{{
					MatchName: "example.com",
				}},
			},
		},
	}

	addRule := func(epID uint64, port uint16) {
		t.Helper()
		err := localProxy.UpdateAllowed(epID, restore.MakeV2PortProto(port, 17), allowExampleCom)
		require.Nil(t, err)
		if remoteProxy == nil {
			return
		}
		err = remoteProxy.UpdateAllowed(epID, restore.MakeV2PortProto(port, 17), allowExampleCom)
		require.Nil(t, err)
	}

	addRule(1, 35)
	addRule(2, 35)
	addRule(1, 35) // overwrites
	addRule(2, 36)

	require.Len(t, localProxy.DumpRules(), 3)

	// Initialize the remote prxy
	remoteProxy = newRemoteFQDNProxy()
	remoteProxy.local = localProxy

	// Add another endpoint, with installed but disconnected
	// remote proxy. Ensure we don't block.
	addRule(3, 35)
	require.Len(t, localProxy.DumpRules(), 4)

	// Now, we have connected to a remote proxy.
	mock := newMockFQDNProxyClient()
	remoteProxy.onConnect(nil, mock)

	// Ensure the remote proxy has all already-existing rules.
	// Note that updates are queued and applied asynchronously, so we must wait
	require.Eventually(t, func() bool {
		return len(mock.allowed) == 4 && len(mock.removed) == 3
	}, time.Second, 10*time.Millisecond)

	// Add another rule
	addRule(4, 35)
	require.Eventually(t, func() bool {
		return len(mock.allowed) == 5 && len(mock.removed) == 3
	}, time.Second, 10*time.Millisecond)

	// Check that RemoveRestored works
	remoteProxy.RemoveRestoredRules(15)
	require.Eventually(t, func() bool {
		return len(mock.allowed) == 5 && len(mock.removed) == 4
	}, time.Second, 10*time.Millisecond)

	// Disconnect, ensure that we do not block
	remoteProxy.onDisconnect()

	addRule(5, 35)
	require.Len(t, localProxy.DumpRules(), 6)
}

// TestDumpRules ensures that Dumprules in enterprise_getallrules.go matches
// ruleToMsg
func TestDumpRules(t *testing.T) {
	localProxy, err := dnsproxy.StartDNSProxy(dnsproxy.DNSProxyConfig{
		Address: "127.0.0.2",
		IPv4:    false,
		IPv6:    false,
	},
		func(ip netip.Addr) (endpoint *endpoint.Endpoint, isHost bool, err error) { return nil, false, nil },
		nil,
		nil,
		func(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr string, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
			return nil
		},
	)

	require.Nil(t, err)
	t.Cleanup(localProxy.Cleanup)

	epID := uint64(5)
	portProto := restore.MakeV2PortProto(53, 17)

	cs := mockCachedSelector("selector-string")
	allowExampleCom := policy.L7DataMap{
		cs: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{{
					MatchName: "example.com",
				}},
			},
		},
	}
	err = localProxy.UpdateAllowed(epID, portProto, allowExampleCom)
	require.Nil(t, err)

	dump := localProxy.DumpRules()
	require.Len(t, dump, 1)
	require.Equal(t, ruleToMsg(epID, portProto, allowExampleCom), dump[0])

}

func CheckUpdate(t *testing.T, expected fqdnRuleKey, got fqdnRuleKey) error {
	t.Helper()

	if got.endpointID != expected.endpointID {
		return fmt.Errorf("expected endpoint id %d, got %d", expected.endpointID, got.endpointID)
	}
	if got.destPortProto != expected.destPortProto {
		return fmt.Errorf("expected destination port %d, got %d", expected.destPortProto, got.destPortProto)
	}
	return nil
}

type mockCachedSelector string

func (m mockCachedSelector) GetSelections() identity.NumericIdentitySlice {
	return []identity.NumericIdentity{1, 2, 3}
}
func (m mockCachedSelector) GetMetadataLabels() labels.LabelArray    { panic("not impl") }
func (m mockCachedSelector) Selects(_ identity.NumericIdentity) bool { panic("not impl") }
func (m mockCachedSelector) IsWildcard() bool                        { panic("not impl") }
func (m mockCachedSelector) IsNone() bool                            { panic("not impl") }
func (m mockCachedSelector) String() string                          { return string(m) }
