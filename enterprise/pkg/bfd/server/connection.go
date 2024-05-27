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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/lock"
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

// bfdServerConnection represents a server connection handler for BFD peers.
// It handles receiving of BFD packets (including packet decapsulation) potentially
// for multiple BFD sessions sharing the same listen interface / address / port configuration.
type bfdServerConnection interface {
	// Read reads and decapsulates a BFD packet from the underlying connection.
	// It blocks until a packet is received.
	// Remote peer's address is returned along with the received BFD packet.
	Read() (*ControlPacket, netip.AddrPort, error)

	// Close closes the connection.
	// Any blocked Read or Write operations will be unblocked and return errors.
	Close() error

	// LocalAddrPort returns the local address and port of the underlying network connection.
	LocalAddrPort() netip.AddrPort

	// UpdateMinTTL updates the minimum expected TTL (Time To Live) value on the connection.
	UpdateMinTTL(minTTL int) error
}

// bfdClientConnection represents a client connection handler for BFD peers.
// It allows sending of BFD packets (including packet encapsulation) to a specific remote peer.
type bfdClientConnection interface {
	// Write writes a BFD packet into the underlying connection.
	Write(*ControlPacket) error

	// Close closes the connection.
	// Any blocked Read or Write operations will be unblocked and return errors.
	Close() error

	// Reset resets the connection to the initial state.
	Reset()

	// LocalAddrPort returns the local address and port of the underlying network connection.
	LocalAddrPort() netip.AddrPort

	// RemoteAddrPort returns the remote peer's address and port of the underlying network connection.
	RemoteAddrPort() netip.AddrPort
}

// bfdServerConn provides a server connection handler for BFD peers.
// It handles receiving of BFD packets (including packet decapsulation) potentially
// for multiple BFD sessions sharing the same listen interface / address / port configuration.
// It can be used for both Control packet and Echo packet connections.
type bfdServerConn struct {
	*net.UDPConn

	readBuffer []byte

	localAddrPort netip.AddrPort
	ifName        string
}

// createServerConnection creates a new UDP server (listener) connection with provided parameters.
func createServerConnection(listenAddrPort netip.AddrPort, ifName string, minTTL int) (*bfdServerConn, error) {
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
					optErr = errors.Join(optErr, unix.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifName))
				}
				// set SO_REUSEPORT to allow for interface-bind and non-interface-bind listeners at the same time
				optErr = errors.Join(optErr, unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1))
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

	return &bfdServerConn{
		UDPConn:       conn.(*net.UDPConn),
		localAddrPort: listenAddrPort,
		ifName:        ifName,
	}, nil
}

// Read reads and decapsulates a BFD packet from the underlying connection.
// It blocks until a packet is received.
// Remote peer's address is returned along with the received BFD packet.
func (conn *bfdServerConn) Read() (*ControlPacket, netip.AddrPort, error) {
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

// LocalAddrPort returns the local address and port of the underlying network connection.
func (conn *bfdServerConn) LocalAddrPort() netip.AddrPort {
	return conn.localAddrPort
}

// UpdateMinTTL updates the minimum expected TTL (Time To Live) value on the connection.
func (conn *bfdServerConn) UpdateMinTTL(minTTL int) error {
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

// bfdControlClientConn provides a Control packet client connection handler for BFD peers.
// It allows sending of BFD Control packets (including packet encapsulation) to a specific remote peer.
type bfdControlClientConn struct {
	*net.UDPConn

	writeBuffer gopacket.SerializeBuffer

	localAddrPort  netip.AddrPort
	remoteAddrPort netip.AddrPort
	ifName         string
}

// createControlClientConnection creates a new UDP client connection for Control packets.
func createControlClientConnection(localAddrPort, remoteAddrPort netip.AddrPort, ifName string) (*bfdControlClientConn, error) {
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

	return &bfdControlClientConn{
		UDPConn:        conn.(*net.UDPConn),
		localAddrPort:  localAddrPort,
		remoteAddrPort: remoteAddrPort,
		ifName:         ifName,
		writeBuffer:    gopacket.NewSerializeBuffer(),
	}, nil
}

// Write writes a BFD packet into the underlying connection.
func (conn *bfdControlClientConn) Write(pkt *ControlPacket) error {
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

// Reset resets the connection to the initial state.
func (conn *bfdControlClientConn) Reset() {
	// no reset necessary for this type of connection
}

// LocalAddrPort returns the local address and port of the underlying network connection.
func (conn *bfdControlClientConn) LocalAddrPort() netip.AddrPort {
	return conn.localAddrPort
}

// RemoteAddrPort returns the remote peer's address and port of the underlying network connection.
func (conn *bfdControlClientConn) RemoteAddrPort() netip.AddrPort {
	return conn.remoteAddrPort
}

// bfdEchoClientConn provides a Echo packet client connection handler for BFD peers.
// It allows sending of BFD Echo packets (including packet encapsulation) to a specific remote peer.
type bfdEchoClientConn struct {
	lock.Mutex

	ifName  string
	ifIndex int
	fd      int

	writeBuffer gopacket.SerializeBuffer

	localAddrPort     netip.AddrPort
	remoteAddrPort    netip.AddrPort
	peerAddr          netip.Addr
	peerLinkLayerAddr net.HardwareAddr
}

// createEchoClientConnection creates a new client connection for Echo packets.
func createEchoClientConnection(localAddrPort, remoteAddrPort netip.AddrPort, peerAddr netip.Addr, ifName string) (*bfdEchoClientConn, error) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("interface lookup failed: %w", err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, 0) // protocol == 0 -> no packets are received
	if err != nil {
		return nil, err
	}

	return &bfdEchoClientConn{
		ifName:         ifName,
		ifIndex:        iface.Index,
		fd:             fd,
		localAddrPort:  localAddrPort,
		remoteAddrPort: remoteAddrPort,
		peerAddr:       peerAddr,
		writeBuffer:    gopacket.NewSerializeBuffer(),
	}, nil
}

// Write writes a BFD packet into the underlying connection.
func (conn *bfdEchoClientConn) Write(pkt *ControlPacket) error {
	conn.Lock()
	defer conn.Unlock()

	if conn.fd == -1 {
		return errors.New("invalid file descriptor")
	}
	var pktLayers []gopacket.SerializableLayer

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(conn.localAddrPort.Port()),
		DstPort: layers.UDPPort(conn.remoteAddrPort.Port()),
	}

	if conn.peerAddr.Is4() {
		ipv4 := &layers.IPv4{
			SrcIP:    conn.localAddrPort.Addr().AsSlice(),
			DstIP:    conn.remoteAddrPort.Addr().AsSlice(),
			Version:  4,
			TTL:      255,
			Protocol: layers.IPProtocolUDP,
			TOS:      cs6ToSValue,
		}
		err := udp.SetNetworkLayerForChecksum(ipv4)
		if err != nil {
			return fmt.Errorf("BFD Echo packet creation error: %w", err)
		}
		pktLayers = append(pktLayers, ipv4)
	} else {
		ipv6 := &layers.IPv6{
			SrcIP:        conn.localAddrPort.Addr().AsSlice(),
			DstIP:        conn.remoteAddrPort.Addr().AsSlice(),
			Version:      6,
			HopLimit:     255,
			NextHeader:   layers.IPProtocolUDP,
			TrafficClass: cs6ToSValue,
		}
		err := udp.SetNetworkLayerForChecksum(ipv6)
		if err != nil {
			return fmt.Errorf("BFD Echo packet creation error: %w", err)
		}
		pktLayers = append(pktLayers, ipv6)
	}

	// serialize the packet
	pktLayers = append(pktLayers, udp, pkt)
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	err := gopacket.SerializeLayers(conn.writeBuffer, opts, pktLayers...)
	if err != nil {
		return fmt.Errorf("BFD Echo packet serizalization error: %w", err)
	}

	if len(conn.peerLinkLayerAddr) == 0 {
		// We are only looking up the remote MAC if it is not yet cached. As it is practically
		// impossible for peer's MAC address to change without BFD session going Down, we can
		// safely cache it, assuming that connection Reset() is called whenever Echo packet transmit
		// is re-started after the session was Down.
		// Note that echo packet transmission is allowed only when the BFD session is Up.
		err = conn.lookupPeerLinkLayerAddr()
		if err != nil {
			return fmt.Errorf("remote link layer address lookup failed: %w", err)
		}
	}

	// compose link layer destination address
	addr := syscall.SockaddrLinklayer{
		Ifindex: conn.ifIndex,
	}
	if conn.peerAddr.Is4() {
		addr.Protocol = hostToNetShort(syscall.ETH_P_IP)
	} else {
		addr.Protocol = hostToNetShort(syscall.ETH_P_IPV6)
	}
	copy(addr.Addr[:], conn.peerLinkLayerAddr)
	addr.Halen = uint8(len(conn.peerLinkLayerAddr))

	// send the packet
	err = syscall.Sendto(conn.fd, conn.writeBuffer.Bytes(), 0, &addr)
	if err != nil {
		return fmt.Errorf("packet sending error: %w", err)
	}

	return nil
}

// Close closes the underlying network connection.
func (conn *bfdEchoClientConn) Close() error {
	conn.Lock()
	defer conn.Unlock()

	err := syscall.Close(conn.fd)
	conn.fd = -1
	return err
}

// Reset resets the connection to the initial state.
func (conn *bfdEchoClientConn) Reset() {
	conn.Lock()
	defer conn.Unlock()

	conn.peerLinkLayerAddr = nil // reset the link layer address, so that it is refreshed upon next Write
}

// LocalAddrPort returns the local address and port of the underlying network connection.
func (conn *bfdEchoClientConn) LocalAddrPort() netip.AddrPort {
	return conn.localAddrPort
}

// RemoteAddrPort returns the remote peer's address and port of the underlying network connection.
func (conn *bfdEchoClientConn) RemoteAddrPort() netip.AddrPort {
	return conn.remoteAddrPort
}

// lookupPeerLinkLayerAddr looks up remote peer's link layer address in the IP neighbour table.
func (conn *bfdEchoClientConn) lookupPeerLinkLayerAddr() error {
	ipFamily := netlink.FAMILY_V4
	if conn.peerAddr.Is6() {
		ipFamily = netlink.FAMILY_V6
	}

	neigh, err := netlink.NeighList(conn.ifIndex, ipFamily)
	if err != nil {
		return fmt.Errorf("failed to list IP neighbors: %w", err)
	}

	conn.peerLinkLayerAddr = net.HardwareAddr{}
	for _, n := range neigh {
		if n.IP.Equal(conn.peerAddr.AsSlice()) {
			conn.peerLinkLayerAddr = n.HardwareAddr
			break
		}
	}
	if len(conn.peerLinkLayerAddr) == 0 {
		return fmt.Errorf("neighbor entry for %v not found", conn.peerAddr)
	}
	return nil
}

// hostToNetShort converts a 16-bit integer from host to network byte order
func hostToNetShort(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}
