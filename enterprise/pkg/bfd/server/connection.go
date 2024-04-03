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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

const (
	// socket option value for IPV6_MINHOPCOUNT (include/uapi/linux/in6.h)
	ipv6MinHopCountOpt = 73

	// RFC 5881 5.  TTL/Hop Limit Issues
	//  If BFD authentication is not in use on a session, all BFD Control
	//  packets for the session MUST be sent with a Time to Live (TTL) or Hop
	//  Limit value of 255.
	//  If BFD authentication is in use on a session, all BFD Control packets
	//  MUST be sent with a TTL or Hop Limit value of 255.
	bfdTTLValue = 255

	// RFC 9435 3.2.  DSCPs Used for Network Control Traffic
	// DSCP CS6 is recommended for local network control traffic. This
	// includes routing protocols and OAM traffic that are essential to
	// network operation administration, control, and management.
	cs6ToSValue = 0xc0 // Type of Service (ToS) value for CS6 DSCP

	// readBufferSize is a buffer size large enough to accommodate any incoming BFD packet
	readBufferSize = 128
)

// bfdConnection represents a network connection to a BFD peer, it manages sending and receiving
// of BFD packets (including packet encapsulation and decapsulation).
type bfdConnection interface {
	// Read reads decapsulates a BFD packet from the underlying connection.
	// It blocks until a packet is received.
	// Remote peer's address is returned along with the received BFD packet.
	Read() (*ControlPacket, netip.AddrPort, error)

	// Write writes a BFD packet into the underlying connection.
	Write(*ControlPacket) error

	// Close closes the connection.
	// Any blocked Read or Write operations will be unblocked and return errors.
	Close() error

	// LocalAddrPort returns the local address and port of the underlying network connection.
	LocalAddrPort() netip.AddrPort

	// RemoteAddrPort returns the remote peer's address and port of the underlying network connection.
	RemoteAddrPort() netip.AddrPort

	// UpdateMinTTL updates the minimum expected TTL (Time To Live) value on the connection.
	UpdateMinTTL(minTTL int) error
}

var _ bfdConnection = (*bfdControlConnection)(nil)

// bfdControlConnection represents a connection handling sending and receiving of BFD Control packets.
type bfdControlConnection struct {
	*net.UDPConn

	readBuffer  []byte
	writeBuffer gopacket.SerializeBuffer

	localAddrPort  netip.AddrPort
	remoteAddrPort netip.AddrPort
	ifName         string
}

// createServerConnection creates a new UDP server (listener) connection with provided parameters.
func createServerConnection(listenAddrPort netip.AddrPort, ifName string, minTTL int) (*bfdControlConnection, error) {
	network := "udp4"
	if listenAddrPort.Addr().Is6() {
		network = "udp6"
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var optErr error
			err := c.Control(func(fd uintptr) {
				if listenAddrPort.Addr().Is4() {
					optErr = unix.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MINTTL, minTTL)
				} else {
					optErr = unix.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6MinHopCountOpt, minTTL)
				}
				if ifName != "" {
					errors.Join(optErr, unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifName))
				}
				if optErr != nil {
					return
				}
			})
			if err != nil {
				return err
			}
			return optErr
		},
	}

	conn, err := lc.ListenPacket(context.Background(), network, listenAddrPort.String())
	if err != nil {
		return nil, fmt.Errorf("listen error: %w", err)
	}

	return &bfdControlConnection{
		UDPConn:       conn.(*net.UDPConn),
		localAddrPort: listenAddrPort,
		ifName:        ifName,
		writeBuffer:   gopacket.NewSerializeBuffer(),
	}, nil
}

// createClientConnection creates a new UDP client (dial) connection with provided parameters.
func createClientConnection(localAddrPort, remoteAddrPort netip.AddrPort, ifName string) (*bfdControlConnection, error) {
	network := "udp4"
	if remoteAddrPort.Addr().Is6() {
		network = "udp6"
	}

	d := net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			var optErr error
			err := c.Control(func(fd uintptr) {
				if remoteAddrPort.Addr().Is4() {
					optErr = errors.Join(
						unix.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, bfdTTLValue),
						unix.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, cs6ToSValue),
					)
				} else {
					optErr = errors.Join(
						unix.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, bfdTTLValue),
						unix.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, cs6ToSValue),
					)
				}
				if ifName != "" {
					optErr = errors.Join(optErr, unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifName))
				}
			})
			if err != nil {
				return err
			}
			return optErr
		},
		LocalAddr: net.UDPAddrFromAddrPort(localAddrPort),
	}

	conn, err := d.Dial(network, remoteAddrPort.String())
	if err != nil {
		return nil, fmt.Errorf("dial error: %w", err)
	}

	return &bfdControlConnection{
		UDPConn:        conn.(*net.UDPConn),
		localAddrPort:  localAddrPort,
		remoteAddrPort: remoteAddrPort,
		ifName:         ifName,
		writeBuffer:    gopacket.NewSerializeBuffer(),
	}, nil
}

// Read reads and decapsulates a BFD packet from the underlying connection.
// It blocks until a packet is received.
// Remote peer's address is returned along with the received BFD packet.
func (conn *bfdControlConnection) Read() (*ControlPacket, netip.AddrPort, error) {
	if conn.readBuffer == nil {
		conn.readBuffer = make([]byte, readBufferSize)
	}

	n, addr, err := conn.ReadFromUDP(conn.readBuffer)
	if n == 0 && err != nil {
		return nil, addr.AddrPort(), fmt.Errorf("UDP read error: %w", err)
	}

	pkt := gopacket.NewPacket(conn.readBuffer[:n], layers.LayerTypeBFD, gopacket.Default)
	if pkt.ErrorLayer() != nil {
		return nil, addr.AddrPort(), fmt.Errorf("BFD packet parsing error: %w", pkt.ErrorLayer().Error())
	}

	cp := &ControlPacket{}
	if bfdLayer := pkt.Layer(layers.LayerTypeBFD); bfdLayer != nil {
		cp.BFD = bfdLayer.(*layers.BFD)
	} else {
		return nil, addr.AddrPort(), fmt.Errorf("invalid BFD packet")
	}

	return cp, addr.AddrPort(), nil
}

// Write writes a BFD packet into the underlying connection.
func (conn *bfdControlConnection) Write(pkt *ControlPacket) error {
	err := conn.writeBuffer.Clear()
	if err != nil {
		return fmt.Errorf("error clearing write buffer: %w", err)
	}

	err = pkt.SerializeTo(conn.writeBuffer, gopacket.SerializeOptions{})
	if err != nil {
		return fmt.Errorf("BFD packet serizalization error: %w", err)
	}

	_, err = conn.UDPConn.Write(conn.writeBuffer.Bytes())
	if err != nil {
		return fmt.Errorf("UDP write error: %w", err)
	}

	return nil
}

// LocalAddrPort returns the local address and port of the underlying network connection.
func (conn *bfdControlConnection) LocalAddrPort() netip.AddrPort {
	return conn.localAddrPort
}

// RemoteAddrPort returns the remote peer's address and port of the underlying network connection.
func (conn *bfdControlConnection) RemoteAddrPort() netip.AddrPort {
	return conn.remoteAddrPort
}

// UpdateMinTTL updates the minimum expected TTL (Time To Live) value on the connection.
func (conn *bfdControlConnection) UpdateMinTTL(minTTL int) error {
	sc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optErr error
	err = sc.Control(func(fd uintptr) {
		if conn.localAddrPort.Addr().Is4() {
			optErr = unix.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MINTTL, minTTL)
		} else {
			optErr = unix.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6MinHopCountOpt, minTTL)
		}
	})
	if optErr != nil {
		return optErr
	}
	return err
}
