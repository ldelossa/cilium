//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package types

import (
	"context"
	"fmt"
	"net/netip"
	"time"
)

// BFDServer manages multiple BFD peers of a system.
type BFDServer interface {
	// Run starts the BFD server and keeps it running (blocks) until the provided context is cancelled.
	Run(ctx context.Context)

	// AddPeer adds a new BFD peer with the given config to the server.
	// A new BFD session is automatically started with a network connection
	// matching the provided configuration is created.
	AddPeer(peer *BFDPeerConfig) error

	// UpdatePeer updates an existing BFD peer with the configuration parameters.
	// Note that connection-related configuration (peer address, interface, local port, TTL etc.)
	// can not be changed, and changes in these parameters will be ignored.
	UpdatePeer(peer *BFDPeerConfig) error

	// DeletePeer removes a peer from the server. The BFD session will be stopped
	// and the related network connection will be closed.
	DeletePeer(peer *BFDPeerConfig) error

	// Observe allows observing BFD peer status updates. Implements stream.Observable[BFDPeerStatus] interface.
	// Status notification is delivered for all session state changes, as well as for changes
	// in timer parameters on a local or remote system.
	Observe(ctx context.Context, next func(BFDPeerStatus), complete func(error))
}

// BFDPeerConfig holds configuration of a BFD peering.
type BFDPeerConfig struct {
	// PeerAddress is the IP address of the BFD peer.
	// Supports IPv4 and IPv6 addresses. If a link-local IPv6 address is used, Interface must be specified.
	PeerAddress netip.Addr

	// Interface is a name of a network interface to which this session is bound to.
	// If not specified / empty, the actual interface is auto-selected by the system using the routing table entries,
	// and no other session with the same PeerAddress can exist on the node.
	Interface string

	// LocalAddress is the local IP address used for the BFD peering.
	// It must match the IP address configured for this node on the remote peer.
	// If not specified, it is auto-selected by the system using the routing table entries and/or
	// the IP address on the egress interface towards the peer.
	LocalAddress netip.Addr

	// EchoSourceAddress defines the IP address used as the source address when sending Echo packets.
	// If not configured, the LocalAddress will be used if configured, or the auto-detected IP address
	// of the egress interface will be used, which has the following limitations:
	//  - The detection of the source address happens during the session setup, and it does not
	//    automatically update upon interface address changes (session re-creation would be needed),
	//  - Per RFC 5881, the Echo source address should not be part of the subnet bound to the interface
	//    over which the BFD Echo packet is being transmitted, and it should not be an IPv6 link-local address
	//    to preclude the remote system from generating ICMP or Neighbor Discovery Redirect messages.
	// These limitations can be achieved by configuring an explicit EchoSourceAddress, which can be
	// any IP address that conforms the above requirements, and does not need to be applied on the node.
	EchoSourceAddress netip.Addr

	// Multihop enables BFD for Multihop Paths mode (RFC 5883) for this session.
	Multihop bool

	// MinimumTTL controls the minimum expected Time To Live (TTL) value for an incoming BFD control packet.
	// This value only affects multihop sessions, it is ignored for non-multihop sessions.
	// Please note that if multiple multihop sessions with the same LocalAddress & Interface use different
	// MinimumTTL value, the lowest configured value will be used.
	MinimumTTL uint8

	// If true, this system will take passive role in session initialization - it will not begin sending
	// BFD packets for this session until it has received a BFD packet from the remote peer for it.
	PassiveMode bool

	// DetectMultiplier defines the BFD Detection time multiplier (RFC 5880, section 4.1).
	// The negotiated transmit interval, multiplied by this value, provides the
	// Detection Time for the receiving system.
	DetectMultiplier uint8

	// ReceiveInterval defines the BFD Required Min RX Interval (RFC 5880, section 4.1).
	// This is the minimum interval between received BFD Control packets that this
	// system is capable of supporting, less any jitter applied by the sender.
	ReceiveInterval time.Duration

	// TransmitInterval defines the BFD Desired Min TX Interval (RFC 5880, section 4.1).
	// This is the minimum interval that the local system would like to use when
	// transmitting BFD Control packets, less any jitter applied.
	TransmitInterval time.Duration

	// EchoReceiveInterval defines the BFD Required Min Echo RX Interval (RFC 5880, section 4.1).
	// This is the minimum interval between received BFD Echo packets that this
	// system is capable of supporting, less any jitter applied by the sender.
	// Non-zero value enables the Echo Function in the direction towards the local system,
	// if the peer is configured to send Echo packets.
	// Zero value disables the Echo function in the direction towards the local system.
	EchoReceiveInterval time.Duration

	// EchoTransmitInterval defines the minimum interval that the local system would like to use when
	// transmitting BFD Echo packets, less any jitter applied.
	// Non-zero value enables the Echo Function in the direction towards the remote system.
	// Zero value disables the Echo function in the direction towards the remote system.
	EchoTransmitInterval time.Duration
}

// BFDPeerStatus represents current status of a BFD peering.
type BFDPeerStatus struct {
	// PeerAddress is the IP address of the BFD peer.
	PeerAddress netip.Addr

	// Interface is the name of a network interface to which this session is bound to.
	Interface string

	// LastStateChangeTime is the timestamp of the last BFD session state transition.
	LastStateChange time.Time

	// Local holds session status as perceived by the local system.
	Local BFDSessionStatus

	// Remote holds session status as perceived by the remote system.
	Remote BFDSessionStatus
}

// BFDSessionStatus holds BFD session status as perceived by the given (local or remote) system.
type BFDSessionStatus struct {
	// State is the last known state of the BFD peering session on the given system.
	State BFDState

	// Discriminator is the unique ID used to identify the session on the given system.
	Discriminator uint32

	// Diagnostic is a diagnostic string specifying the given system's reason
	// for the last change in session state as defined in RFC 5880, section 4.1.
	Diagnostic BFDDiagnostic

	// DetectMultiplier holds the value of the BFD Detection time multiplier.
	DetectMultiplier uint8

	// ReceiveInterval holds the value of the BFD Required Min Echo RX Interval.
	ReceiveInterval time.Duration

	// TransmitInterval holds the value of the BFD Desired Min TX Interval.
	TransmitInterval time.Duration

	// EchoReceiveInterval holds the value of the BFD Required Min Echo RX Interval.
	EchoReceiveInterval time.Duration

	// EchoTransmitInterval defines the minimum interval that the given system would like to use when
	// transmitting BFD Echo packets, less any jitter applied.
	EchoTransmitInterval time.Duration
}

// BFDState is the current BFD session state as seen by the transmitting system,
// as defined in RFC 5880, section 4.1.
type BFDState uint8

const (
	BFDStateAdminDown BFDState = iota
	BFDStateDown
	BFDStateInit
	BFDStateUp
)

func (s BFDState) String() string {
	str, found := map[BFDState]string{
		BFDStateAdminDown: "AdminDown",
		BFDStateDown:      "Down",
		BFDStateInit:      "Init",
		BFDStateUp:        "Up",
	}[s]
	if found {
		return str
	}
	return fmt.Sprintf("Invalid (%d)", s)
}

// BFDDiagnostic is a diagnostic code specifying the local system's reason for the
// last change in session state, as defined in RFC 5880, section  4.1.
type BFDDiagnostic uint16

const (
	BFDDiagnosticNoDiagnostic BFDDiagnostic = iota
	BFDDiagnosticControlDetectionTimeExpired
	BFDDiagnosticEchoFunctionFailed
	BFDDiagnosticNeighborSignaledSessionDown
	BFDDiagnosticForwardingPlaneReset
	BFDDiagnosticPathDown
	BFDDiagnosticConcatenatedPathDown
	BFDDiagnosticAdministrativelyDown
	BFDDiagnosticReverseConcatenatedPathDown
)

func (d BFDDiagnostic) String() string {
	str, found := map[BFDDiagnostic]string{
		BFDDiagnosticNoDiagnostic:                "No Diagnostic",
		BFDDiagnosticControlDetectionTimeExpired: "Control Detection Time Expired",
		BFDDiagnosticEchoFunctionFailed:          "Echo Function Failed",
		BFDDiagnosticNeighborSignaledSessionDown: "Neighbor Signaled Session Down",
		BFDDiagnosticForwardingPlaneReset:        "Forwarding Plane Reset",
		BFDDiagnosticPathDown:                    "Path Down",
		BFDDiagnosticConcatenatedPathDown:        "Concatenated Path Down",
		BFDDiagnosticAdministrativelyDown:        "Administratively Down",
		BFDDiagnosticReverseConcatenatedPathDown: "Reverse Concatenated Path Down",
	}[d]
	if !found {
		return fmt.Sprintf("Reserved (%d)", d)
	}
	return str
}
