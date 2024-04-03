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
	"math/rand/v2"
	"net/netip"

	"github.com/cilium/stream"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	// RFC 5881, 4. Encapsulation
	// BFD Control packets MUST be transmitted in UDP packets with
	// destination port 3784, within an IPv4 or IPv6 packet.
	singleHopServerPort = 3784

	// RFC 5883, 5. Encapsulation
	// The encapsulation of BFD Control packets for multihop application in
	// IPv4 and IPv6 is identical to that defined in [BFD-1HOP], except that
	// the UDP destination port MUST have a value of 4784.
	multiHopServerPort = 4784

	// sessionStatusUpdateChannelSize is a size of the channel used to deliver session status updates
	// to subscribed observers (using Observe). If observers are slow in consuming the updates, it may get filled,
	// in which case it behaves as a ring buffer - the oldest event is removed when adding a new one.
	sessionStatusUpdateChannelSize = 100

	// receivedPacketsChannelSize is the buffer size of the packet channel used to deliver packets
	// from the listeners to the server. As the processing of the incoming packets involves
	// only de-multixplexing across multiple session channels, normally it should not get filled.
	receivedPacketsChannelSize = 100

	// maxSourcePortAllocationAttempts is the count of maximum connection source port allocation attempts.
	// Each attempts selects a random port from the pre-defined port range, and checks whether it is
	// already used by another session or another application on the system.
	// If no free source port can be allocated in this amount of attempts, an error is returned.
	maxSourcePortAllocationAttempts = 1000
)

// addrPortInterface holds network address + port + network interface information.
type addrPortInterface struct {
	netip.AddrPort
	ifName string
}

// addrInterface holds network address + network interface information.
type addrInterface struct {
	netip.Addr
	ifName string
}

// BFDServer manages multiple BFD peers of a system.
type BFDServer struct {
	logger log.FieldLogger

	// stopChan is used to stop the server processing
	stopChan chan struct{}

	// listeners mapped by the listen address + port + interface
	listeners   map[addrPortInterface]*bfdListener
	listenersMu lock.Mutex

	// channel used to deliver packets from listeners to the server
	receivedPacketsCh chan *receivedPacket

	// sessions managed by this server
	sessionsByDiscr      map[uint32]*bfdSession        // sessions mapped by our local discriminator
	sessionsByPeerAddrIf map[addrInterface]*bfdSession // sessions mapped by peer address + interface
	sessionsBySrcPort    map[uint16]*bfdSession        // sessions mapped by source port
	sessionsMu           lock.RWMutex

	// channel used to deliver session status updates
	statusUpdateCh chan types.BFDPeerStatus

	// multicast observable allowing to observe session status updates
	mcast       stream.Observable[types.BFDPeerStatus]
	mcastCancel func()
}

// NewBFDServer creates a new BFD server.
// It does not start any listeners until a peer is added.
func NewBFDServer(logger log.FieldLogger) *BFDServer {
	statusUpdateCh := make(chan types.BFDPeerStatus, sessionStatusUpdateChannelSize)
	mcast, connect := stream.ToMulticast(stream.FromChannel(statusUpdateCh))
	ctx, mcastCancel := context.WithCancel(context.Background())
	connect(ctx)
	return &BFDServer{
		logger:               logger,
		stopChan:             make(chan struct{}),
		listeners:            make(map[addrPortInterface]*bfdListener),
		receivedPacketsCh:    make(chan *receivedPacket, receivedPacketsChannelSize),
		sessionsByDiscr:      make(map[uint32]*bfdSession),
		sessionsByPeerAddrIf: make(map[addrInterface]*bfdSession),
		sessionsBySrcPort:    make(map[uint16]*bfdSession),
		statusUpdateCh:       statusUpdateCh,
		mcast:                mcast,
		mcastCancel:          mcastCancel,
	}
}

// Start tarts the BFD server
func (s *BFDServer) Start() error {
	go s.processReceivedPackets()
	return nil
}

// AddPeer adds a new BFD peer with the given config to the server.
// A new BFD session is automatically started with a network connection matching the provided configuration.
func (s *BFDServer) AddPeer(cfg *types.BFDPeerConfig) error {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	if err := s.validatePeerConfig(cfg); err != nil {
		return err
	}

	l := s.logger.WithFields(log.Fields{
		types.PeerAddressField:   cfg.PeerAddress,
		types.InterfaceNameField: cfg.Interface,
	})
	l.Debug("Adding BFD peer")

	peerAddrIf := addrInterface{Addr: cfg.PeerAddress, ifName: cfg.Interface}
	if _, exists := s.sessionsByPeerAddrIf[peerAddrIf]; exists {
		return fmt.Errorf("peer with (address: %s, interface: %s) already exists", cfg.PeerAddress, cfg.Interface)
	}

	// allocate new local discriminator for the session
	var localDiscriminator uint32
	for {
		localDiscriminator = rand.Uint32()
		if _, found := s.sessionsByDiscr[localDiscriminator]; !found {
			break
		}
	}

	// ensure a listener exists for this session's params
	err := s.ensureListener(cfg)
	if err != nil {
		return err
	}

	// create a client connection for this session
	outConn, sourcePort, err := s.createClientConnection(cfg)
	if err != nil {
		s.releaseListener(cfg)
		return err
	}

	// start a new BFD session
	session, err := newBFDSession(l, cfg, outConn, localDiscriminator, s.statusUpdateCh)
	if err != nil {
		s.releaseListener(cfg)
		outConn.Close()
		return fmt.Errorf("error creating BFD session: %w", err)
	}
	session.start()

	s.sessionsByDiscr[localDiscriminator] = session
	s.sessionsByPeerAddrIf[peerAddrIf] = session
	s.sessionsBySrcPort[sourcePort] = session

	return nil
}

// UpdatePeer updates an existing BFD peer with the configuration parameters.
// Note that connection-related configuration (peer address, interface, local port, TTL etc.)
// can not be changed, and changes in these parameters will be ignored.
func (s *BFDServer) UpdatePeer(cfg *types.BFDPeerConfig) error {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	if err := s.validatePeerConfig(cfg); err != nil {
		return err
	}

	s.logger.WithFields(log.Fields{
		types.PeerAddressField:   cfg.PeerAddress,
		types.InterfaceNameField: cfg.Interface,
	}).Debug("Updating BFD peer")

	peerAddrIf := addrInterface{Addr: cfg.PeerAddress, ifName: cfg.Interface}
	session, exists := s.sessionsByPeerAddrIf[peerAddrIf]
	if !exists {
		return fmt.Errorf("peer with (address: %s, interface: %s) does not exist", cfg.PeerAddress, cfg.Interface)
	}

	return session.update(cfg)
}

// DeletePeer removes a peer from the server. The BFD session will be stopped
// and the related network connection will be closed.
func (s *BFDServer) DeletePeer(cfg *types.BFDPeerConfig) error {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	s.logger.WithFields(log.Fields{
		types.PeerAddressField:   cfg.PeerAddress,
		types.InterfaceNameField: cfg.Interface,
	}).Debug("Deleting BFD peer")

	peerAddrIf := addrInterface{Addr: cfg.PeerAddress, ifName: cfg.Interface}
	session, exists := s.sessionsByPeerAddrIf[peerAddrIf]
	if !exists {
		return fmt.Errorf("peer with (address: %s, interface: %s) does not exist", cfg.PeerAddress, cfg.Interface)
	}

	session.stop()
	delete(s.sessionsByDiscr, session.local.discriminator)
	delete(s.sessionsByPeerAddrIf, peerAddrIf)
	delete(s.sessionsBySrcPort, session.outConn.LocalAddrPort().Port())

	session.outConn.Close()
	s.releaseListener(cfg)

	return nil
}

// Stop stops the BFD server by stopping all its BFD sessions and closing their network connections.
func (s *BFDServer) Stop() {
	s.logger.Info("Stopping BFD server")

	s.sessionsMu.Lock()
	for _, sess := range s.sessionsByDiscr {
		sess.stop()
	}
	s.sessionsMu.Unlock()

	s.listenersMu.Lock()
	for _, l := range s.listeners {
		l.stop()
	}
	s.listenersMu.Unlock()
	s.mcastCancel()
	close(s.stopChan)
}

// Observe allows observing BFD peer status updates. Implements stream.Observable[BFDPeerStatus] interface.
func (s *BFDServer) Observe(ctx context.Context, next func(types.BFDPeerStatus), complete func(error)) {
	s.mcast.Observe(ctx, next, complete)
}

func (s *BFDServer) validatePeerConfig(cfg *types.BFDPeerConfig) error {
	if cfg.PeerAddress.IsUnspecified() {
		return fmt.Errorf("PeerAddress not specified")
	}
	if cfg.ReceiveInterval == 0 {
		return fmt.Errorf("ReceiveInterval is zero")
	}
	if cfg.TransmitInterval == 0 {
		return fmt.Errorf("TransmitInterval is zero")
	}
	if cfg.DetectMultiplier == 0 {
		return fmt.Errorf("DetectMultiplier is zero")
	}
	return nil
}

// createClientConnection creates a new client connection for a session.
// It allocates an unused source port for it. It is the responsibility of the caller to
// tie the allocated port with the session once it is created.
func (s *BFDServer) createClientConnection(cfg *types.BFDPeerConfig) (conn bfdConnection, sourcePort uint16, err error) {
	attempts := 0
	for {
		// find a port not used by any other session
		for {
			// RFC 5881, 4.  Encapsulation
			// The source port MUST be in the range 49152 through 65535.
			sourcePort = uint16(rand.Uint32N(65535-49152) + 49152)
			if _, found := s.sessionsBySrcPort[sourcePort]; !found {
				break // found available port
			}
			// port used for another session, retry
			attempts++
			if attempts >= maxSourcePortAllocationAttempts {
				err = fmt.Errorf("unable to allocate a free source port (%d attempts)", attempts)
				return
			}
		}

		// create a new client connection
		localAddr := netip.AddrPortFrom(cfg.LocalAddress, sourcePort)
		remoteAddr := netip.AddrPortFrom(cfg.PeerAddress, bfdServerPort(cfg.Multihop))
		conn, err = createClientConnection(localAddr, remoteAddr, cfg.Interface)

		if err != nil {
			if errors.Is(err, unix.EADDRINUSE) {
				continue // allocated port is already in use, retry with a different one
			} else {
				err = fmt.Errorf("error creating client connection: %w", err)
				return
			}
		}
		return // connected using the allocated source port
	}
}

// ensureListener starts a new server listener for the given BFD peering,
// if a matching listener does not already exist.
func (s *BFDServer) ensureListener(peerCfg *types.BFDPeerConfig) error {
	s.listenersMu.Lock()
	defer s.listenersMu.Unlock()

	listenAddr := s.getListenAddress(peerCfg)
	listenAddrIface := addrPortInterface{AddrPort: listenAddr, ifName: peerCfg.Interface}
	minTTL := s.getMinTTL(peerCfg)

	if l, ok := s.listeners[listenAddrIface]; ok {
		// listener already found, increment the session count
		l.sessionCnt += 1

		// if minimum TTL does not match with the existing, use the lower value
		if minTTL < l.minTTL {
			err := l.updateMinTTL(minTTL)
			if err != nil {
				return err
			}
		}
		return nil
	}

	// start a new server listener
	l, err := newBFDListener(s.logger, s.receivedPacketsCh, listenAddr, peerCfg.Interface, minTTL)
	if err != nil {
		return fmt.Errorf("error creating BFD listener: %w", err)
	}
	l.start()
	l.sessionCnt = 1

	s.listeners[listenAddrIface] = l
	return nil
}

// releaseListener stops the server listener if there is no other peering that is using it.
func (s *BFDServer) releaseListener(peerCfg *types.BFDPeerConfig) {
	s.listenersMu.Lock()
	defer s.listenersMu.Unlock()

	listenAddr := s.getListenAddress(peerCfg)
	listenAddrIface := addrPortInterface{AddrPort: listenAddr, ifName: peerCfg.Interface}

	if l, ok := s.listeners[listenAddrIface]; ok {
		l.sessionCnt -= 1
		if l.sessionCnt == 0 {
			l.stop()
			delete(s.listeners, listenAddrIface)
		}
	}
}

// getListenAddress returns listen address and port that should be used for the given BFD peering.
func (s *BFDServer) getListenAddress(peerCfg *types.BFDPeerConfig) netip.AddrPort {
	port := bfdServerPort(peerCfg.Multihop)
	if peerCfg.LocalAddress.IsValid() {
		return netip.AddrPortFrom(peerCfg.LocalAddress, port)
	}
	if peerCfg.PeerAddress.Is4() {
		return netip.AddrPortFrom(netip.IPv4Unspecified(), port)
	}
	return netip.AddrPortFrom(netip.IPv6Unspecified(), port)
}

func bfdServerPort(multihop bool) uint16 {
	if multihop {
		return multiHopServerPort
	}
	return singleHopServerPort
}

func (s *BFDServer) getMinTTL(peerCfg *types.BFDPeerConfig) int {
	// For multi-hop, we use configured minimum TTL
	if peerCfg.Multihop {
		return int(peerCfg.MinimumTTL)
	}

	// RFC 5881 5.  TTL/Hop Limit Issues
	//  If BFD authentication is not in use on a session, all BFD Control
	//  packets for the session MUST be sent with a Time to Live (TTL) or Hop
	//  Limit value of 255.  All received BFD Control packets that are
	//  demultiplexed to the session MUST be discarded if the received TTL or
	//  Hop Limit is not equal to 255.
	//
	//  If BFD authentication is in use on a session, all BFD Control packets
	//  MUST be sent with a TTL or Hop Limit value of 255.  All received BFD
	//  Control packets that are demultiplexed to the session MAY be
	//  discarded if the received TTL or Hop Limit is not equal to 255.
	return 255
}

// processReceivedPackets reads packets received from the listeners and de-multiplexes them between sessions.
func (s *BFDServer) processReceivedPackets() {
	for {
		select {
		case pkt := <-s.receivedPacketsCh:
			s.demultiplexPacket(pkt)
		case <-s.stopChan:
			return
		}
	}
}

// demultiplexPacket de-multiplexes a received packet to a matching session.
func (s *BFDServer) demultiplexPacket(inPkt *receivedPacket) {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	if inPkt.pkt == nil {
		return
	}
	if inPkt.pkt.YourDiscriminator == 0 {
		// If the Your Discriminator field is zero, the session MUST be
		// selected based on some combination of other fields, possibly
		// including source addressing information, the My Discriminator
		// field, and the interface over which the packet was received.  The
		// exact method of selection is application specific and is thus
		// outside the scope of this specification.  If a matching session is
		// not found, a new session MAY be created, or the packet MAY be
		// discarded.  This choice is outside the scope of this
		// specification.

		for _, session := range s.sessionsByDiscr {
			// check if the packet matches with the session, and if yes, deliver it to the session
			if matched := s.matchPktWithSession(inPkt, session); matched {
				s.deliverPacket(inPkt.pkt, session)
				break
			}
		}
	} else {
		// If the Your Discriminator field is nonzero, it MUST be used to
		// select the session with which this BFD packet is associated. If
		// no session is found, the packet MUST be discarded.

		session := s.sessionsByDiscr[uint32(inPkt.pkt.YourDiscriminator)]
		if session != nil {
			s.deliverPacket(inPkt.pkt, session)
		}
	}
}

// matchPktWithSession tries to match a packet with unset YourDiscriminator with a provided session.
// If the packet can be matched with the session, the remote.discriminator value on the session is set,
// (which wires the session with the paket's MyDiscriminator value) and the return value is true.
func (s *BFDServer) matchPktWithSession(inPkt *receivedPacket, session *bfdSession) bool {
	session.Lock()
	defer session.Unlock()

	if session.remote.discriminator != 0 && session.remote.discriminator != uint32(inPkt.pkt.MyDiscriminator) {
		return false // session is already using a different remote discriminator
	}

	if session.peerAddress != inPkt.remoteAddr {
		return false // session is for a different remote address
	}

	if session.outConn.RemoteAddrPort().Port() != inPkt.localPort {
		return false // session is for a different server port
	}

	if session.networkInterface != "" && session.networkInterface != inPkt.ifName {
		return false // session is bound to a different interface
	}

	// found a matching session for this packet, assign MyDiscriminator to remote.discriminator
	session.remote.discriminator = uint32(inPkt.pkt.MyDiscriminator)

	return true
}

// deliverPacket delivers an incoming packet to the given session
func (s *BFDServer) deliverPacket(pkt *ControlPacket, session *bfdSession) {
	// do not block if the session's packet channel is full, drop the packet & warn
	select {
	case session.inPacketsCh <- pkt:
	default:
		s.logger.WithField(types.DiscriminatorField, session.local.discriminator).Warn(
			"BFD session's packet channel full, dropping incoming BFD packet. Consider using higher ReceiveInterval.")
	}
}
