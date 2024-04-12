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

	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/inctimer"
)

const (
	testTimeout = 5 * time.Second
)

func Test_BFDServer(t *testing.T) {
	slowDesiredMinTxInterval = uint32(50 * time.Millisecond / time.Microsecond) // 50ms to speed up the tests
	logger := log.StandardLogger()
	logger.SetLevel(log.DebugLevel)

	localIPv6Addr := firstLocalIPv6Addr()

	var steps = []struct {
		description   string
		s1Peers       []types.BFDPeerConfig
		s2Peers       []types.BFDPeerConfig
		s1UpdatePeers []types.BFDPeerConfig
	}{
		{
			description: "single session IPv4, both active mode",
			s1Peers: []types.BFDPeerConfig{
				{
					LocalAddress:     netip.MustParseAddr("127.0.0.100"),
					PeerAddress:      netip.MustParseAddr("127.0.0.200"),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      false,
				},
			},
			s2Peers: []types.BFDPeerConfig{
				{
					LocalAddress:     netip.MustParseAddr("127.0.0.200"),
					PeerAddress:      netip.MustParseAddr("127.0.0.100"),
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
					LocalAddress:     localIPv6Addr,
					PeerAddress:      netip.MustParseAddr("::1"),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      false,
				},
			},
			s2Peers: []types.BFDPeerConfig{
				{
					LocalAddress:     netip.MustParseAddr("::1"),
					PeerAddress:      localIPv6Addr,
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      true,
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
			description: "single session, update",
			s1Peers: []types.BFDPeerConfig{
				{
					LocalAddress:     netip.MustParseAddr("127.0.0.100"),
					PeerAddress:      netip.MustParseAddr("127.0.0.200"),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      false,
				},
			},
			s1UpdatePeers: []types.BFDPeerConfig{
				{
					LocalAddress:     netip.MustParseAddr("127.0.0.100"),
					PeerAddress:      netip.MustParseAddr("127.0.0.200"),
					ReceiveInterval:  15 * time.Millisecond,
					TransmitInterval: 15 * time.Millisecond,
					DetectMultiplier: 2,
					PassiveMode:      false,
				},
			},
			s2Peers: []types.BFDPeerConfig{
				{
					LocalAddress:     netip.MustParseAddr("127.0.0.200"),
					PeerAddress:      netip.MustParseAddr("127.0.0.100"),
					ReceiveInterval:  20 * time.Millisecond,
					TransmitInterval: 20 * time.Millisecond,
					DetectMultiplier: 3,
					PassiveMode:      false,
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
	}

	for _, step := range steps {
		t.Run(step.description, func(t *testing.T) {
			if step.s1Peers[0].LocalAddress.IsUnspecified() {
				t.Skip("no local IP address") // skips the IPv6 test if there is no local IPv6 address detected
			}

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
					assertEventualState(t, ch1, types.BFDStateUp)
				}
				for range step.s2Peers {
					assertEventualState(t, ch2, types.BFDStateUp)
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
			for range step.s2Peers {
				assertEventualState(t, ch2, types.BFDStateDown)
			}
		})
	}
}

func firstLocalIPv6Addr() netip.Addr {
	ifaces, err := net.Interfaces()
	if err != nil {
		return netip.IPv6Unspecified()
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			switch ipAddr := a.(type) {
			case *net.IPNet:
				if ipAddr.IP.To4() == nil && !ipAddr.IP.IsLoopback() && !ipAddr.IP.IsLinkLocalUnicast() {
					if res, ok := netip.AddrFromSlice(ipAddr.IP); ok {
						return res
					}
				}
			}
		}
	}
	return netip.IPv6Unspecified()
}

func assertStateTransition(t *testing.T, ch <-chan types.BFDPeerStatus, expState types.BFDState) {
	select {
	case e := <-ch:
		require.Equal(t, expState.String(), e.Local.State.String())
	case <-time.After(5 * time.Duration(slowDesiredMinTxInterval) * time.Microsecond):
		require.Failf(t, "missed state change", "%s expected", expState)
	}
}

func assertEventualState(t *testing.T, ch <-chan types.BFDPeerStatus, expState types.BFDState) {
	for {
		select {
		case e := <-ch:
			if expState == e.Local.State {
				return
			}
		case <-inctimer.After(5 * time.Duration(slowDesiredMinTxInterval) * time.Microsecond):
			require.Failf(t, "missed state change", "%s expected", expState)
		}
	}
}
