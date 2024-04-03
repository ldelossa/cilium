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
	"errors"
	"fmt"
	"net"
	"net/netip"

	log "github.com/sirupsen/logrus"

	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
)

// bfdListener represents a BFD server listener with a specific
// listener address, port and (optionally) network interface.
type bfdListener struct {
	logger log.FieldLogger

	connection bfdConnection
	pktCh      chan<- *receivedPacket

	listenAddrPortIf netip.AddrPort
	ifName           string
	minTTL           int

	sessionCnt uint32 // count of sessions using this listener
}

// receivedPacket represent a single BFD control packet and its metadata received from a listener connection.
type receivedPacket struct {
	pkt        *ControlPacket
	remoteAddr netip.Addr
	ifName     string
	localPort  uint16
}

// newBFDListener creates a new BFD server listener with underlying network connection.
func newBFDListener(l log.FieldLogger, pktCh chan<- *receivedPacket, listenAddrPort netip.AddrPort, ifName string, minTTL int) (*bfdListener, error) {

	logger := l.WithFields(log.Fields{
		types.ListenAddressField: listenAddrPort,
		types.InterfaceNameField: ifName,
	})
	logger.Info("Starting BFD listener")

	// create a new server connection
	conn, err := createServerConnection(listenAddrPort, ifName, minTTL)
	if err != nil {
		return nil, fmt.Errorf("error creating BFD server connection: %w", err)
	}

	listener := &bfdListener{
		pktCh:            pktCh,
		logger:           logger,
		connection:       conn,
		listenAddrPortIf: listenAddrPort,
		ifName:           ifName,
		minTTL:           minTTL,
	}
	return listener, nil
}

// start starts reading from the underlying connection and delivering packets to the server.
func (l *bfdListener) start() {
	go l.listen()
}

// stop closes the underlying network connection and stops the listener routine.
func (l *bfdListener) stop() {
	l.logger.Info("Stopping BFD listener")
	l.connection.Close()
}

// listen reads from the listener's connection delivers the received BFD packets to the server.
func (l *bfdListener) listen() {
	for {
		pkt, remoteAddr, err := l.connection.Read()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				l.logger.Info("BFD listener connection closed")
				break
			}
			l.logger.WithError(err).Error("BFD listener read error")
			continue // continue reading next packets
		}
		if !pkt.isValid() {
			continue
		}
		// deliver the packet to the server
		l.pktCh <- &receivedPacket{
			pkt:        pkt,
			remoteAddr: remoteAddr.Addr(),
			ifName:     l.ifName,
			localPort:  l.listenAddrPortIf.Port(),
		}
	}
}

// updateMinTTL updates minimum TTL value on a listener connection.
func (l *bfdListener) updateMinTTL(minTTL int) error {
	l.logger.WithField(types.MinimumTTLField, minTTL).Info("Updating minimum TTL on BFD listener")
	err := l.connection.UpdateMinTTL(minTTL)
	if err != nil {
		return fmt.Errorf("error updating minimum TTL: %w", err)
	}
	return nil
}
