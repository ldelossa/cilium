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
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
)

type fakeControlConn struct {
	localAddrPort  netip.AddrPort
	remoteAddrPort netip.AddrPort
	inPkt          chan *ControlPacket
	outPkt         chan *ControlPacket
}

func (conn *fakeControlConn) Read() (*ControlPacket, netip.AddrPort, error) {
	pkt := <-conn.inPkt
	return pkt, conn.remoteAddrPort, nil
}

func (conn *fakeControlConn) Write(pkt *ControlPacket) error {
	conn.outPkt <- pkt
	return nil
}

func (conn *fakeControlConn) LocalAddrPort() netip.AddrPort {
	return conn.localAddrPort
}

func (conn *fakeControlConn) RemoteAddrPort() netip.AddrPort {
	return conn.remoteAddrPort
}

func (conn *fakeControlConn) UpdateMinTTL(minTTL int) error {
	return nil
}

func (conn *fakeControlConn) Close() error {
	return nil
}

type testFixture struct {
	conn     *fakeControlConn
	statusCh chan types.BFDPeerStatus

	sessionCfg          *types.BFDPeerConfig
	session             *bfdSession
	localDiscriminator  uint32
	remoteDiscriminator uint32
}

func newTestFixture(t *testing.T) *testFixture {
	slowDesiredMinTxInterval = uint32(50 * time.Millisecond / time.Microsecond) // 50ms to speed up the tests
	logger := log.StandardLogger()
	logger.SetLevel(log.DebugLevel)

	f := &testFixture{
		localDiscriminator:  12345,
		remoteDiscriminator: 56789,
	}

	f.conn = &fakeControlConn{
		inPkt:  make(chan *ControlPacket, 10),
		outPkt: make(chan *ControlPacket, 10),
	}
	f.sessionCfg = &types.BFDPeerConfig{
		ReceiveInterval:  10 * time.Millisecond,
		TransmitInterval: 11 * time.Millisecond,
		DetectMultiplier: 3,
	}
	f.statusCh = make(chan types.BFDPeerStatus, 10)

	s, err := newBFDSession(logger, f.sessionCfg, f.conn, f.localDiscriminator, f.statusCh)
	require.NoError(t, err)
	f.session = s

	return f
}

func Test_BFDSessionStateMachine(t *testing.T) {
	f := newTestFixture(t)
	f.session.start()

	assertStateTransition(t, f.statusCh, types.BFDStateDown)

	// RFC 5880 6.2.  BFD State Machine
	//
	//                             +--+
	//                             |  | UP, ADMIN DOWN, TIMER
	//                             |  V
	//                     DOWN  +------+  INIT
	//              +------------|      |------------+
	//              |            | DOWN |            |
	//              |  +-------->|      |<--------+  |
	//              |  |         +------+         |  |
	//              |  |                          |  |
	//              |  |               ADMIN DOWN,|  |
	//              |  |ADMIN DOWN,          DOWN,|  |
	//              |  |TIMER                TIMER|  |
	//              V  |                          |  V
	//            +------+                      +------+
	//       +----|      |                      |      |----+
	//   DOWN|    | INIT |--------------------->|  UP  |    |INIT, UP
	//       +--->|      | INIT, UP             |      |<---+
	//            +------+                      +------+

	// L: Down (R: Up) -> Down
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, 0, layers.BFDStateUp)
	outPkt := waitEgressPacketWithState(t, f.conn, layers.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: AdminDown) -> Down
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, 0, layers.BFDStateAdminDown)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: none) -> Down
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: Down) -> Init
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateInit)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateInit)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Init (R: Down) -> Init
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateInit)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Init (R: none-timeout) -> Down
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticControlDetectionTimeExpired, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, 0, outPkt.YourDiscriminator)

	// L: Down (R: none) -> Down
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticControlDetectionTimeExpired, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, 0, outPkt.YourDiscriminator)

	// L: Down (R: Down) -> Init
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateInit)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateInit)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Init (R: AdminDown) -> Down
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateAdminDown)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticNeighborSignaledSessionDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: none) -> Down
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticNeighborSignaledSessionDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: Down) -> Init
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateInit)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateInit)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Init (R: Init) -> Up
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateInit)
	assertStateTransition(t, f.statusCh, types.BFDStateUp)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateUp)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, f.sessionCfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Up (R: Init) -> Up
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateInit)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateUp)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, f.sessionCfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Up (R: Up) -> Up
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateUp)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, f.sessionCfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Up (R: none-timeout) -> Down
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticControlDetectionTimeExpired, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, 0, outPkt.YourDiscriminator)

	// L: Down (R: none) -> Down
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticControlDetectionTimeExpired, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, 0, outPkt.YourDiscriminator)

	// L: Down (R: Init) -> Up
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateInit)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateUp)
	assertStateTransition(t, f.statusCh, types.BFDStateUp)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, f.sessionCfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Up (R: Down) -> Down
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticNeighborSignaledSessionDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: Init) -> Up
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateInit)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateUp)
	assertStateTransition(t, f.statusCh, types.BFDStateUp)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, f.sessionCfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Up (R: AdminDown) -> Down
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateAdminDown)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticNeighborSignaledSessionDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: none) -> Down
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticNeighborSignaledSessionDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: Down) -> Init
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateInit)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateInit)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Init (R: Up) -> Up
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	assertStateTransition(t, f.statusCh, types.BFDStateUp)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateUp)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, f.sessionCfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Up, set AdminDown -> AdminDown
	f.session.setAdminDown()
	assertStateTransition(t, f.statusCh, types.BFDStateAdminDown)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateAdminDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticAdministrativelyDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: AdminDown (R: Down) -> AdminDown
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateAdminDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticAdministrativelyDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: AdminDown (R: none) -> AdminDown
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateAdminDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticAdministrativelyDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: AdminDown, set AdminUp -> Down
	f.session.setAdminUp()
	assertStateTransition(t, f.statusCh, types.BFDStateDown)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: Down) -> Init
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateInit)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateInit)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Init, set AdminDown -> AdminDown
	f.session.setAdminDown()
	assertStateTransition(t, f.statusCh, types.BFDStateAdminDown)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateAdminDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticAdministrativelyDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: AdminDown (R: Init) -> AdminDown
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateInit)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateAdminDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticAdministrativelyDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: AdminDown, set AdminUp -> Down
	f.session.setAdminUp()
	assertStateTransition(t, f.statusCh, types.BFDStateDown)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down, set AdminDown -> AdminDown
	f.session.setAdminDown()
	assertStateTransition(t, f.statusCh, types.BFDStateAdminDown)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateAdminDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticAdministrativelyDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: AdminDown (R: Down) -> AdminDown
	f.session.inPacketsCh <- createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateAdminDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticAdministrativelyDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	f.session.stop()
}

func Test_BFDSessionUpdate(t *testing.T) {
	f := newTestFixture(t)
	f.session.start()

	assertStateTransition(t, f.statusCh, types.BFDStateDown)

	// L: Down (R: Init) -> Up
	remotePkt := createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateInit)
	f.session.inPacketsCh <- remotePkt
	waitEgressPacketWithState(t, f.conn, layers.BFDStateUp)
	assertStateTransition(t, f.statusCh, types.BFDStateUp)
	require.EqualValues(t, remotePkt.DesiredMinTxInterval, f.session.remote.desiredMinTxInterval)
	require.EqualValues(t, remotePkt.RequiredMinRxInterval, f.session.remote.requiredMinRxInterval)
	require.EqualValues(t, remotePkt.MyDiscriminator, f.session.remote.discriminator)

	// L: Up (R: Up) -> Up
	remotePkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	remotePkt.Final = true // end Poll sequence after moving to Up
	f.session.inPacketsCh <- remotePkt
	waitEgressPacketWithState(t, f.conn, layers.BFDStateUp)
	require.EqualValues(t, remotePkt.DesiredMinTxInterval, f.session.remote.desiredMinTxInterval)
	require.EqualValues(t, remotePkt.RequiredMinRxInterval, f.session.remote.requiredMinRxInterval)
	require.EqualValues(t, remotePkt.MyDiscriminator, f.session.remote.discriminator)

	// Remote initiates Poll sequence -> send Final
	remotePkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	remotePkt.DesiredMinTxInterval = 20000
	remotePkt.RequiredMinRxInterval = 25000
	remotePkt.DetectMultiplier = 5
	remotePkt.Poll = true
	f.session.inPacketsCh <- remotePkt
	outPkt := waitEgressPacketWithState(t, f.conn, layers.BFDStateUp)
	require.False(t, outPkt.Poll)
	require.True(t, outPkt.Final)
	require.EqualValues(t, remotePkt.DesiredMinTxInterval, f.session.remote.desiredMinTxInterval)
	require.EqualValues(t, remotePkt.RequiredMinRxInterval, f.session.remote.requiredMinRxInterval)
	require.EqualValues(t, remotePkt.DetectMultiplier, f.session.remote.detectMultiplier)

	// Remote continues in Poll sequence -> send Final
	f.session.inPacketsCh <- remotePkt
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateUp)
	require.False(t, outPkt.Poll)
	require.True(t, outPkt.Final)
	require.EqualValues(t, remotePkt.DesiredMinTxInterval, f.session.remote.desiredMinTxInterval)
	require.EqualValues(t, remotePkt.RequiredMinRxInterval, f.session.remote.requiredMinRxInterval)
	require.EqualValues(t, remotePkt.DetectMultiplier, f.session.remote.detectMultiplier)

	// Remote terminates Poll sequence -> send Poll & Final cleared
	remotePkt.Poll = false
	f.session.inPacketsCh <- remotePkt
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateUp)
	require.False(t, outPkt.Poll)
	require.False(t, outPkt.Final)
	require.EqualValues(t, remotePkt.DesiredMinTxInterval, f.session.remote.desiredMinTxInterval)
	require.EqualValues(t, remotePkt.RequiredMinRxInterval, f.session.remote.requiredMinRxInterval)
	require.EqualValues(t, remotePkt.DetectMultiplier, f.session.remote.detectMultiplier)

	// Session update from our side -> send Poll
	cfg := f.sessionCfg
	cfg.ReceiveInterval = 30 * time.Millisecond
	cfg.TransmitInterval = 35 * time.Millisecond
	cfg.DetectMultiplier = 4
	err := f.session.update(cfg)
	require.NoError(t, err)
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateUp)
	require.True(t, outPkt.Poll)
	require.False(t, outPkt.Final)
	require.EqualValues(t, f.session.local.desiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, f.session.local.requiredMinRxInterval, outPkt.RequiredMinRxInterval)
	require.EqualValues(t, cfg.DetectMultiplier, outPkt.DetectMultiplier)
	require.NotEqualValues(t, cfg.ReceiveInterval/time.Microsecond, outPkt.RequiredMinRxInterval)
	require.NotEqualValues(t, cfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.NotEqualValues(t, f.session.local.configuredDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.NotEqualValues(t, f.session.local.configuredRequiredMinRxInterval, outPkt.RequiredMinRxInterval)

	// Remote replies without Final -> resend Poll
	f.session.inPacketsCh <- remotePkt
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateUp)
	require.True(t, outPkt.Poll)
	require.False(t, outPkt.Final)
	require.EqualValues(t, f.session.local.desiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, f.session.local.requiredMinRxInterval, outPkt.RequiredMinRxInterval)
	require.EqualValues(t, cfg.DetectMultiplier, outPkt.DetectMultiplier)
	require.NotEqualValues(t, cfg.ReceiveInterval/time.Microsecond, outPkt.RequiredMinRxInterval)
	require.NotEqualValues(t, cfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.NotEqualValues(t, f.session.local.configuredDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.NotEqualValues(t, f.session.local.configuredRequiredMinRxInterval, outPkt.RequiredMinRxInterval)

	// Remote replies with Final -> send Poll & Final cleared (Poll sequence terminated, new values applied)
	remotePkt.Final = true
	f.session.inPacketsCh <- remotePkt
	outPkt = waitEgressPacketWithState(t, f.conn, layers.BFDStateUp)
	require.False(t, outPkt.Poll)
	require.False(t, outPkt.Final)
	require.EqualValues(t, f.session.local.desiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, f.session.local.requiredMinRxInterval, outPkt.RequiredMinRxInterval)
	require.EqualValues(t, cfg.DetectMultiplier, outPkt.DetectMultiplier)
	require.EqualValues(t, cfg.ReceiveInterval/time.Microsecond, outPkt.RequiredMinRxInterval)
	require.EqualValues(t, cfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, f.session.local.configuredDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, f.session.local.configuredRequiredMinRxInterval, outPkt.RequiredMinRxInterval)

	f.session.stop()
}

func createTestControlPacket(myDiscriminator, yourDiscriminator uint32, state layers.BFDState) *ControlPacket {
	pkt := &ControlPacket{
		&layers.BFD{
			Version:               1,
			MyDiscriminator:       layers.BFDDiscriminator(myDiscriminator),
			YourDiscriminator:     layers.BFDDiscriminator(yourDiscriminator),
			RequiredMinRxInterval: 10000,
			DesiredMinTxInterval:  10000,
			DetectMultiplier:      3,
			State:                 state,
		},
	}
	if pkt.State != layers.BFDStateUp {
		pkt.DesiredMinTxInterval = layers.BFDTimeInterval(slowDesiredMinTxInterval)
	}
	return pkt
}

func waitEgressPacketWithState(t *testing.T, conn *fakeControlConn, expState layers.BFDState) *ControlPacket {
	timer := time.NewTimer(5 * time.Duration(slowDesiredMinTxInterval) * time.Microsecond)
	for {
		select {
		case pkt := <-conn.outPkt:
			if expState == pkt.State {
				return pkt
			}
		case <-timer.C:
			require.Failf(t, "missed state change", "%s expected", expState)
		}
	}
}
