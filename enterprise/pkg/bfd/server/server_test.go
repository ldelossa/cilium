//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package server

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/stream"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	testTimeout = 5 * time.Second
)

var (
	testIf1Name     = "bfd-test1"
	testIf1IPv4Addr = netip.MustParsePrefix("172.16.100.1/24")
	testIf1IPv6Addr = netip.MustParsePrefix("fc00::100/64")

	testIf2Name     = "bfd-test2"
	testIf2IPv4Addr = netip.MustParsePrefix("172.16.100.2/24")
	testIf2IPv6Addr = netip.MustParsePrefix("fc00::101/64")
)

func Test_BFDServer(t *testing.T) {
	testutils.PrivilegedTest(t)

	logger := log.StandardLogger()
	logger.SetLevel(log.DebugLevel)

	err := setupLinks()
	t.Cleanup(func() {
		teardownLinks()
	})
	require.NoError(t, err)

	slowDesiredMinTxInterval = uint32(50 * time.Millisecond / time.Microsecond) // 50ms to speed up the tests

	steps := []struct {
		description   string
		s1Peers       []types.BFDPeerConfig
		s2Peers       []types.BFDPeerConfig
		s1UpdatePeers []types.BFDPeerConfig
	}{
		{
			description: "single session IPv4, both active mode",
			s1Peers: []types.BFDPeerConfig{
				{
					LocalAddress:     testIf1IPv4Addr.Addr(),
					PeerAddress:      testIf2IPv4Addr.Addr(),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      false,
				},
			},
			s2Peers: []types.BFDPeerConfig{
				{
					LocalAddress:     testIf2IPv4Addr.Addr(),
					PeerAddress:      testIf1IPv4Addr.Addr(),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      false,
				},
			},
		},
		{
			description: "single session IPv6, s1 active mode",
			s1Peers: []types.BFDPeerConfig{
				{
					LocalAddress:     testIf1IPv6Addr.Addr(),
					PeerAddress:      testIf2IPv6Addr.Addr(),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      false,
				},
			},
			s2Peers: []types.BFDPeerConfig{
				{
					LocalAddress:     testIf2IPv6Addr.Addr(),
					PeerAddress:      testIf1IPv6Addr.Addr(),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      true,
				},
			},
		},
		{
			description: "single session, update",
			s1Peers: []types.BFDPeerConfig{
				{
					LocalAddress:     testIf1IPv4Addr.Addr(),
					PeerAddress:      testIf2IPv4Addr.Addr(),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      false,
				},
			},
			s1UpdatePeers: []types.BFDPeerConfig{
				{
					LocalAddress:     testIf1IPv4Addr.Addr(),
					PeerAddress:      testIf2IPv4Addr.Addr(),
					ReceiveInterval:  15 * time.Millisecond,
					TransmitInterval: 15 * time.Millisecond,
					DetectMultiplier: 2,
					PassiveMode:      false,
				},
			},
			s2Peers: []types.BFDPeerConfig{
				{
					LocalAddress:     testIf2IPv4Addr.Addr(),
					PeerAddress:      testIf1IPv4Addr.Addr(),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      false,
				},
			},
		},
		{
			description: "Multiple sessions, mixed active mode",
			s1Peers: []types.BFDPeerConfig{
				{
					LocalAddress:     netip.MustParseAddr("127.0.0.101"),
					PeerAddress:      netip.MustParseAddr("127.0.0.201"),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      false,
				},
				{
					LocalAddress:     netip.MustParseAddr("127.0.0.102"),
					PeerAddress:      netip.MustParseAddr("127.0.0.202"),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      true,
				},
				{
					LocalAddress:     netip.MustParseAddr("127.0.0.103"),
					PeerAddress:      netip.MustParseAddr("127.0.0.203"),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      false,
				},
			},
			s2Peers: []types.BFDPeerConfig{
				{
					LocalAddress:     netip.MustParseAddr("127.0.0.201"),
					PeerAddress:      netip.MustParseAddr("127.0.0.101"),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      true,
				},
				{
					LocalAddress:     netip.MustParseAddr("127.0.0.202"),
					PeerAddress:      netip.MustParseAddr("127.0.0.102"),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      false,
				},
				{
					LocalAddress:     netip.MustParseAddr("127.0.0.203"),
					PeerAddress:      netip.MustParseAddr("127.0.0.103"),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      true,
				},
			},
		},
		{
			description: "Multiple sessions, multihop, different minimum TTL",
			s1Peers: []types.BFDPeerConfig{
				{
					LocalAddress:     netip.MustParseAddr("127.0.0.101"),
					PeerAddress:      netip.MustParseAddr("127.0.0.201"),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      false,
					Multihop:         true,
					MinimumTTL:       250,
				},
				{
					LocalAddress:     netip.MustParseAddr("127.0.0.101"),
					PeerAddress:      netip.MustParseAddr("127.0.0.202"),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      true,
					Multihop:         true,
					MinimumTTL:       240,
				},
			},
			s2Peers: nil,
		},
		{
			description: "single session IPv4, echo mode",
			s1Peers: []types.BFDPeerConfig{
				{
					PeerAddress:          testIf2IPv4Addr.Addr(),
					Interface:            testIf2Name,
					ReceiveInterval:      50 * time.Millisecond,
					TransmitInterval:     50 * time.Millisecond,
					DetectMultiplier:     3,
					PassiveMode:          false,
					EchoReceiveInterval:  10 * time.Millisecond,
					EchoTransmitInterval: 10 * time.Millisecond,
				},
			},
			s2Peers: []types.BFDPeerConfig{
				{
					PeerAddress:          testIf1IPv4Addr.Addr(),
					Interface:            testIf1Name,
					ReceiveInterval:      50 * time.Millisecond,
					TransmitInterval:     50 * time.Millisecond,
					DetectMultiplier:     3,
					PassiveMode:          false,
					EchoReceiveInterval:  10 * time.Millisecond,
					EchoTransmitInterval: 10 * time.Millisecond,
				},
			},
		},
		{
			description: "single session IPv6, echo mode",
			s1Peers: []types.BFDPeerConfig{
				{
					PeerAddress:          testIf2IPv6Addr.Addr(),
					Interface:            testIf2Name,
					ReceiveInterval:      50 * time.Millisecond,
					TransmitInterval:     50 * time.Millisecond,
					DetectMultiplier:     3,
					PassiveMode:          false,
					EchoReceiveInterval:  10 * time.Millisecond,
					EchoTransmitInterval: 10 * time.Millisecond,
				},
			},
			s2Peers: []types.BFDPeerConfig{
				{
					PeerAddress:          testIf1IPv6Addr.Addr(),
					Interface:            testIf1Name,
					ReceiveInterval:      50 * time.Millisecond,
					TransmitInterval:     50 * time.Millisecond,
					DetectMultiplier:     3,
					PassiveMode:          false,
					EchoReceiveInterval:  10 * time.Millisecond,
					EchoTransmitInterval: 10 * time.Millisecond,
				},
			},
		},
	}

	for _, step := range steps {
		t.Run(step.description, func(t *testing.T) {
			testCtx, cancel := context.WithTimeout(context.Background(), testTimeout)
			t.Cleanup(func() {
				cancel()
			})

			// Start server 1
			s1 := NewBFDServer(log.StandardLogger())
			go s1.Run(testCtx)
			ch1 := stream.ToChannel[types.BFDPeerStatus](context.Background(), s1)

			// add server 1 peers
			for _, peer := range step.s1Peers {
				err := s1.AddPeer(&peer)
				require.NoError(t, err)
				assertStateTransition(t, ch1, types.BFDStateDown)
			}

			// Start server 2
			s2 := NewBFDServer(log.StandardLogger())
			go s2.Run(testCtx)
			ch2 := stream.ToChannel[types.BFDPeerStatus](context.Background(), s2)

			// add server 2 peers
			for _, peer := range step.s2Peers {
				err := s2.AddPeer(&peer)
				require.NoError(t, err)
				assertStateTransition(t, ch2, types.BFDStateDown)
			}

			if step.s2Peers != nil {
				// all sessions should transition into Up state (may transit via Init)
				for range step.s1Peers {
					assertEventualState(t, ch1, types.BFDStateUp, types.BFDDiagnosticNoDiagnostic)
				}
				for range step.s2Peers {
					assertEventualState(t, ch2, types.BFDStateUp, types.BFDDiagnosticNoDiagnostic)
				}
			}

			// update peers
			for _, peer := range step.s1UpdatePeers {
				err := s1.UpdatePeer(&peer)
				require.NoError(t, err)
			}

			// delete the peers on server 1
			for _, peer := range step.s1Peers {
				err := s1.DeletePeer(&peer)
				require.NoError(t, err)
			}

			// all sessions on server 2 should go down
			for _, peer := range step.s2Peers {
				if peer.EchoTransmitInterval > 0 {
					assertEventualState(t, ch2, types.BFDStateDown, types.BFDDiagnosticEchoFunctionFailed)
				} else {
					assertEventualState(t, ch2, types.BFDStateDown, types.BFDDiagnosticControlDetectionTimeExpired)
				}
			}
		})
	}
}

func setupLinks() error {
	teardownLinks() // cleanup leftovers, e.g. in case of a killed test

	err := netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: testIf1Name,
		},
		PeerName: testIf2Name,
	})
	if err != nil {
		return err
	}
	err = setupLinkIPs(testIf1Name, testIf1IPv4Addr, testIf1IPv6Addr)
	if err != nil {
		return err
	}
	err = setupLinkIPs(testIf2Name, testIf2IPv4Addr, testIf2IPv6Addr)
	if err != nil {
		return err
	}
	return nil
}

func setupLinkIPs(name string, ips ...netip.Prefix) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		addr := &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   ip.Addr().AsSlice(),
				Mask: net.CIDRMask(ip.Bits(), ip.Addr().BitLen()),
			},
		}
		if ip.Addr().Is6() {
			addr.Flags = unix.IFA_F_NODAD // disable duplicate address detection so that we can use the address immediately
		}
		err = netlink.AddrAdd(l, addr)
		if err != nil {
			return err
		}
	}
	return netlink.LinkSetUp(l)
}

func teardownLinks() {
	teardownLink(testIf1Name)
	teardownLink(testIf2Name)
}

func teardownLink(name string) error {
	return netlink.LinkDel(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
	})
}

func assertStateTransition(t *testing.T, ch <-chan types.BFDPeerStatus, expState types.BFDState) {
	select {
	case e := <-ch:
		require.Equal(t, expState.String(), e.Local.State.String())
	case <-inctimer.After(5 * time.Duration(slowDesiredMinTxInterval) * time.Microsecond):
		require.Failf(t, "missed state change", "%s expected", expState)
	}
}

func assertEventualState(t *testing.T, ch <-chan types.BFDPeerStatus, expState types.BFDState, expDiagnostic types.BFDDiagnostic) {
	for {
		select {
		case e := <-ch:
			if expState == e.Local.State && expDiagnostic == e.Local.Diagnostic {
				return
			}
		case <-inctimer.After(5 * time.Duration(slowDesiredMinTxInterval) * time.Microsecond):
			require.Failf(t, "missed state change", "%s (%s) expected", expState, expDiagnostic)
		}
	}
}
