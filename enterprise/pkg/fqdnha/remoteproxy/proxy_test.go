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
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc"

	"github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"

	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/u8proto"
)

type mockFQDNProxyClient struct {
	updateAllowedHandler func(msg *dnsproxy.FQDNRules) error
}

func (m *mockFQDNProxyClient) UpdateAllowed(
	ctx context.Context,
	in *dnsproxy.FQDNRules,
	opts ...grpc.CallOption,
) (*dnsproxy.Empty, error) {
	return nil, m.updateAllowedHandler(in)
}

func (m *mockFQDNProxyClient) RemoveRestoredRules(
	ctx context.Context,
	in *dnsproxy.EndpointID,
	opts ...grpc.CallOption,
) (*dnsproxy.Empty, error) {
	return nil, nil
}

func (m *mockFQDNProxyClient) GetRules(
	ctx context.Context,
	in *dnsproxy.EndpointID,
	opts ...grpc.CallOption,
) (*dnsproxy.RestoredRules, error) {
	return nil, nil
}

func TestUpdateAllowedOrdering(t *testing.T) {
	portProto := uint32(restore.MakeV2PortProto(8080, uint8(u8proto.UDP)))
	re.InitRegexCompileLRU(1000)
	updates := []fqdnRuleKey{
		{
			endpointID:    1,
			destPortProto: portProto,
		},
		{
			endpointID:    2,
			destPortProto: portProto,
		},
		{
			endpointID:    3,
			destPortProto: portProto,
		},
		{
			endpointID:    4,
			destPortProto: portProto,
		},
		{
			endpointID:    5,
			destPortProto: portProto,
		},
	}
	step := 0
	testErrs := make(chan error)

	proxy := newRemoteFQDNProxy()
	proxy.client = &mockFQDNProxyClient{
		updateAllowedHandler: func(msg *dnsproxy.FQDNRules) error {
			if msg.EndpointID != updates[step].endpointID {
				testErrs <- fmt.Errorf("expected endpoint id %d, got %d", updates[step].endpointID, msg.EndpointID)
				return errors.New("UpdateAllowed failed")
			}
			pp := restore.PortProto(updates[step].destPortProto)
			if msg.DestPort != uint32(pp.Port()) {
				testErrs <- fmt.Errorf("expected destination port %d, got %d", pp.Port(), msg.DestPort)
				return errors.New("UpdateAllowed failed")
			}

			if msg.DestProto != uint32(pp.Protocol()) {
				testErrs <- fmt.Errorf("expected destination protocol %d, got %d", pp.Protocol(), msg.DestProto)
				return errors.New("UpdateAllowed failed")
			}

			if len(msg.Rules.SelectorRegexMapping) != 1 || msg.Rules.SelectorRegexMapping["foo=bar"] != "^(?:[-a-zA-Z0-9_]*[.]cilium[.]io[.]|foo[.]cilium[.]io[.])$" {
				testErrs <- fmt.Errorf("unexpected selector regex mappings")
				return errors.New("UpdatedAllowed failed (unexpected policy regex)")
			}

			step++
			if step == len(updates) {
				// end the test
				close(testErrs)
			}

			return nil
		},
	}
	t.Cleanup(proxy.Cleanup)
	dnsRules := &policy.PerSelectorPolicy{L7Rules: api.L7Rules{
		DNS: []api.PortRuleDNS{
			{MatchPattern: "*.cilium.io"},
			{MatchPattern: "foo.cilium.io"},
		},
	}}
	dm := policy.L7DataMap{
		mockCachedSelector("foo=bar"): dnsRules,
	}
	for _, upd := range updates {
		if err := proxy.UpdateAllowed(upd.endpointID, restore.PortProto(upd.destPortProto), dm); err != nil {
			t.Fatal(err)
		}
	}

	err := <-testErrs
	if err != nil {
		t.Fatal(err)
	}
}

func TestUpdateAllowedOrderingWithRetries(t *testing.T) {
	portProto := uint32(restore.MakeV2PortProto(8080, uint8(u8proto.UDP)))
	updates := []fqdnRuleKey{
		{
			endpointID:    1,
			destPortProto: portProto,
		},
		{
			endpointID:    2,
			destPortProto: portProto,
		},
		{
			endpointID:    3,
			destPortProto: portProto,
		},
	}
	step := 0
	testErrs := make(chan error)

	proxy := newRemoteFQDNProxy()
	proxy.client = &mockFQDNProxyClient{
		updateAllowedHandler: func(msg *dnsproxy.FQDNRules) error {
			// increase step here to take into account intentional failures too
			step++
			switch step {
			case 1:
				if err := CheckUpdate(t, updates[0], msgKey(msg)); err != nil {
					testErrs <- err
					return errors.New("UpdateAllowed failed")
				}
			case 2:
				if err := CheckUpdate(t, updates[1], msgKey(msg)); err != nil {
					testErrs <- err
					return errors.New("UpdateAllowed failed")
				}
				return errors.New("intentional failure to trigger a retry")
			case 3:
				if err := CheckUpdate(t, updates[1], msgKey(msg)); err != nil {
					testErrs <- err
					return errors.New("UpdateAllowed failed")
				}
			case 4:
				if err := CheckUpdate(t, updates[2], msgKey(msg)); err != nil {
					testErrs <- err
					return errors.New("UpdateAllowed failed")
				}
				// end the test
				close(testErrs)
			default:
				return errors.New("unexpected call to UpdatedAllowed")
			}

			return nil
		},
	}
	t.Cleanup(proxy.Cleanup)

	for _, upd := range updates {
		if err := proxy.UpdateAllowed(upd.endpointID, restore.PortProto(upd.destPortProto), nil); err != nil {
			t.Fatal(err)
		}
	}

	err := <-testErrs
	if err != nil {
		t.Fatal(err)
	}
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
