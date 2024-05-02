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
	defer f.session.stop()

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
	inPkt := createTestControlPacket(f.remoteDiscriminator, 0, layers.BFDStateUp)
	f.session.inPacketsCh <- inPkt
	outPkt := waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: AdminDown) -> Down
	inPkt = createTestControlPacket(f.remoteDiscriminator, 0, layers.BFDStateAdminDown)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: none) -> Down
	outPkt = waitEgressPacketWithState(t, f.session, nil, layers.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: Down) -> Init
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateInit)
	assertStateTransition(t, f.statusCh, types.BFDStateInit)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Init (R: Down) -> Init
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateInit)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Init (R: none-timeout) -> Down
	outPkt = waitEgressPacketWithState(t, f.session, nil, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticControlDetectionTimeExpired, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, 0, outPkt.YourDiscriminator)

	// L: Down (R: none) -> Down
	outPkt = waitEgressPacketWithState(t, f.session, nil, layers.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticControlDetectionTimeExpired, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, 0, outPkt.YourDiscriminator)

	// L: Down (R: Down) -> Init
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateInit)
	assertStateTransition(t, f.statusCh, types.BFDStateInit)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Init (R: AdminDown) -> Down
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateAdminDown)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticNeighborSignaledSessionDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: none) -> Down
	outPkt = waitEgressPacketWithState(t, f.session, nil, layers.BFDStateDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticNeighborSignaledSessionDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: Down) -> Init
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateInit)
	assertStateTransition(t, f.statusCh, types.BFDStateInit)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Init (R: Init) -> Up
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateInit)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	assertEventualState(t, f.statusCh, types.BFDStateUp)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, f.sessionCfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Up (R: Init) -> Up
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateInit)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, f.sessionCfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Up (R: Up) -> Up
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, f.sessionCfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Up (R: none-timeout) -> Down
	outPkt = waitEgressPacketWithState(t, f.session, nil, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticControlDetectionTimeExpired, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, 0, outPkt.YourDiscriminator)

	// L: Down (R: none) -> Down
	outPkt = waitEgressPacketWithState(t, f.session, nil, layers.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticControlDetectionTimeExpired, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, 0, outPkt.YourDiscriminator)

	// L: Down (R: Init) -> Up
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateInit)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	assertStateTransition(t, f.statusCh, types.BFDStateUp)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, f.sessionCfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Up (R: Down) -> Down
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticNeighborSignaledSessionDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: Init) -> Up
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateInit)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	assertEventualState(t, f.statusCh, types.BFDStateUp)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, f.sessionCfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Up (R: AdminDown) -> Down
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateAdminDown)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticNeighborSignaledSessionDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: none) -> Down
	outPkt = waitEgressPacketWithState(t, f.session, nil, layers.BFDStateDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticNeighborSignaledSessionDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: Down) -> Init
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateInit)
	assertStateTransition(t, f.statusCh, types.BFDStateInit)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Init (R: Up) -> Up
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	assertStateTransition(t, f.statusCh, types.BFDStateUp)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, f.sessionCfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Up, set AdminDown -> AdminDown
	f.session.setAdminDown()
	outPkt = waitEgressPacketWithState(t, f.session, nil, layers.BFDStateAdminDown)
	assertStateTransition(t, f.statusCh, types.BFDStateAdminDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticAdministrativelyDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: AdminDown (R: Down) -> AdminDown
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateAdminDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticAdministrativelyDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: AdminDown (R: none) -> AdminDown
	outPkt = waitEgressPacketWithState(t, f.session, nil, layers.BFDStateAdminDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticAdministrativelyDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: AdminDown, set AdminUp -> Down
	f.session.setAdminUp()
	outPkt = waitEgressPacketWithState(t, f.session, nil, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down (R: Down) -> Init
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateInit)
	assertStateTransition(t, f.statusCh, types.BFDStateInit)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Init, set AdminDown -> AdminDown
	f.session.setAdminDown()
	outPkt = waitEgressPacketWithState(t, f.session, nil, layers.BFDStateAdminDown)
	assertStateTransition(t, f.statusCh, types.BFDStateAdminDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticAdministrativelyDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: AdminDown (R: Init) -> AdminDown
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateInit)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateAdminDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticAdministrativelyDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: AdminDown, set AdminUp -> Down
	f.session.setAdminUp()
	outPkt = waitEgressPacketWithState(t, f.session, nil, layers.BFDStateDown)
	assertStateTransition(t, f.statusCh, types.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticNoDiagnostic, outPkt.Diagnostic)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: Down, set AdminDown -> AdminDown
	f.session.setAdminDown()
	outPkt = waitEgressPacketWithState(t, f.session, nil, layers.BFDStateAdminDown)
	assertStateTransition(t, f.statusCh, types.BFDStateAdminDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticAdministrativelyDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))

	// L: AdminDown (R: Down) -> AdminDown
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateAdminDown)
	require.EqualValues(t, outPkt.Diagnostic, types.BFDDiagnosticAdministrativelyDown)
	require.EqualValues(t, f.localDiscriminator, outPkt.MyDiscriminator)
	require.EqualValues(t, slowDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.Contains(t, []uint32{f.remoteDiscriminator, 0}, uint32(outPkt.YourDiscriminator))
}

func Test_BFDSessionUpdate(t *testing.T) {
	f := newTestFixture(t)
	f.session.start()
	defer f.session.stop()

	assertStateTransition(t, f.statusCh, types.BFDStateDown)

	// L: Down (R: Init) -> Up
	inPkt := createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateInit)
	f.session.inPacketsCh <- inPkt
	waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	assertStateTransition(t, f.statusCh, types.BFDStateUp)
	f.session.Lock()
	require.EqualValues(t, inPkt.DesiredMinTxInterval, f.session.remote.desiredMinTxInterval)
	require.EqualValues(t, inPkt.RequiredMinRxInterval, f.session.remote.requiredMinRxInterval)
	require.EqualValues(t, inPkt.MyDiscriminator, f.session.remote.discriminator)
	f.session.Unlock()

	// L: Up (R: Up) -> Up
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	inPkt.Final = true // end Poll sequence after moving to Up
	f.session.inPacketsCh <- inPkt
	waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	f.session.Lock()
	require.EqualValues(t, inPkt.DesiredMinTxInterval, f.session.remote.desiredMinTxInterval)
	require.EqualValues(t, inPkt.RequiredMinRxInterval, f.session.remote.requiredMinRxInterval)
	require.EqualValues(t, inPkt.MyDiscriminator, f.session.remote.discriminator)
	f.session.Unlock()

	// Remote initiates Poll sequence -> send Final
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	inPkt.DesiredMinTxInterval = 20000
	inPkt.RequiredMinRxInterval = 25000
	inPkt.DetectMultiplier = 5
	inPkt.Poll = true
	f.session.inPacketsCh <- inPkt
	outPkt := waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	require.False(t, outPkt.Poll)
	require.True(t, outPkt.Final)
	f.session.Lock()
	require.EqualValues(t, inPkt.DesiredMinTxInterval, f.session.remote.desiredMinTxInterval)
	require.EqualValues(t, inPkt.RequiredMinRxInterval, f.session.remote.requiredMinRxInterval)
	require.EqualValues(t, inPkt.DetectMultiplier, f.session.remote.detectMultiplier)
	f.session.Unlock()

	// Remote continues in Poll sequence -> send Final
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	inPkt.DesiredMinTxInterval = 20000
	inPkt.RequiredMinRxInterval = 25000
	inPkt.DetectMultiplier = 5
	inPkt.Poll = true
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	require.False(t, outPkt.Poll)
	require.True(t, outPkt.Final)
	f.session.Lock()
	require.EqualValues(t, inPkt.DesiredMinTxInterval, f.session.remote.desiredMinTxInterval)
	require.EqualValues(t, inPkt.RequiredMinRxInterval, f.session.remote.requiredMinRxInterval)
	require.EqualValues(t, inPkt.DetectMultiplier, f.session.remote.detectMultiplier)
	f.session.Unlock()

	// Remote terminates Poll sequence -> send Poll & Final cleared
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	require.False(t, outPkt.Poll)
	require.False(t, outPkt.Final)
	f.session.Lock()
	require.EqualValues(t, inPkt.DesiredMinTxInterval, f.session.remote.desiredMinTxInterval)
	require.EqualValues(t, inPkt.RequiredMinRxInterval, f.session.remote.requiredMinRxInterval)
	require.EqualValues(t, inPkt.DetectMultiplier, f.session.remote.detectMultiplier)
	f.session.Unlock()

	// Session update from our side -> send Poll
	cfg := f.sessionCfg
	cfg.ReceiveInterval = 30 * time.Millisecond
	cfg.TransmitInterval = 35 * time.Millisecond
	cfg.DetectMultiplier = 4
	err := f.session.update(cfg)
	require.NoError(t, err)
	outPkt = waitEgressPacketWithState(t, f.session, nil, layers.BFDStateUp)
	require.True(t, outPkt.Poll)
	require.False(t, outPkt.Final)
	f.session.Lock()
	require.EqualValues(t, f.session.local.desiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, f.session.local.requiredMinRxInterval, outPkt.RequiredMinRxInterval)
	require.EqualValues(t, cfg.DetectMultiplier, outPkt.DetectMultiplier)
	require.NotEqualValues(t, cfg.ReceiveInterval/time.Microsecond, outPkt.RequiredMinRxInterval)
	require.NotEqualValues(t, cfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.NotEqualValues(t, f.session.local.configuredDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.NotEqualValues(t, f.session.local.configuredRequiredMinRxInterval, outPkt.RequiredMinRxInterval)
	f.session.Unlock()

	// Remote replies without Final -> resend Poll
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	require.True(t, outPkt.Poll)
	require.False(t, outPkt.Final)
	f.session.Lock()
	require.EqualValues(t, f.session.local.desiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, f.session.local.requiredMinRxInterval, outPkt.RequiredMinRxInterval)
	require.EqualValues(t, cfg.DetectMultiplier, outPkt.DetectMultiplier)
	require.NotEqualValues(t, cfg.ReceiveInterval/time.Microsecond, outPkt.RequiredMinRxInterval)
	require.NotEqualValues(t, cfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.NotEqualValues(t, f.session.local.configuredDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.NotEqualValues(t, f.session.local.configuredRequiredMinRxInterval, outPkt.RequiredMinRxInterval)
	f.session.Unlock()

	// Remote replies with Final -> send Poll & Final cleared (Poll sequence terminated, new values applied)
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	inPkt.Final = true
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	require.False(t, outPkt.Poll)
	require.False(t, outPkt.Final)
	f.session.Lock()
	require.EqualValues(t, f.session.local.desiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, f.session.local.requiredMinRxInterval, outPkt.RequiredMinRxInterval)
	require.EqualValues(t, cfg.DetectMultiplier, outPkt.DetectMultiplier)
	require.EqualValues(t, cfg.ReceiveInterval/time.Microsecond, outPkt.RequiredMinRxInterval)
	require.EqualValues(t, cfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, f.session.local.configuredDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, f.session.local.configuredRequiredMinRxInterval, outPkt.RequiredMinRxInterval)
	f.session.Unlock()
}

func Test_BFDStatePreservation(t *testing.T) {
	f := newTestFixture(t)
	f.session.start()
	defer f.session.stop()

	assertStateTransition(t, f.statusCh, types.BFDStateDown)

	// L: Down (R: Init) -> Up
	inPkt := createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateInit)
	f.session.inPacketsCh <- inPkt
	waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	assertStateTransition(t, f.statusCh, types.BFDStateUp)

	// at this moment, the state should be preserved if the peer flaps to Down immediately

	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	f.session.inPacketsCh <- inPkt
	outPkt := waitFirstEgressPacket(t, f.session)
	f.session.Lock()
	if f.session.statePreserveTime.After(time.Now()) {
		// we can assert this only if we were quick enough - within the state preservation timeframe
		require.EqualValues(t, outPkt.State, types.BFDStateUp)
	}
	f.session.Unlock()

	// eventually session should go to the Down state

	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateDown)
	require.EqualValues(t, outPkt.State, types.BFDStateDown)
}

func createTestControlPacket(myDiscriminator, yourDiscriminator uint32, state layers.BFDState) *ControlPacket {
	pkt := &ControlPacket{
		&layers.BFD{
			Version:               1,
			MyDiscriminator:       layers.BFDDiscriminator(myDiscriminator),
			YourDiscriminator:     layers.BFDDiscriminator(yourDiscriminator),
			RequiredMinRxInterval: 10000, // 10ms
			DesiredMinTxInterval:  10000, // 10ms
			DetectMultiplier:      3,
			State:                 state,
		},
	}
	if pkt.State != layers.BFDStateUp {
		pkt.DesiredMinTxInterval = layers.BFDTimeInterval(slowDesiredMinTxInterval)
	}
	return pkt
}

// waitFirstEgressPacket waits for and returns the first egress packet generated by the session.
func waitFirstEgressPacket(t *testing.T, session *bfdSession) *ControlPacket {
	// fail if the expected state is not reached within this timeframe
	failTimer := time.NewTimer(5 * time.Duration(slowDesiredMinTxInterval) * time.Microsecond)

	conn := session.outConn.(*fakeControlConn)
	for {
		select {
		case pkt := <-conn.outPkt:
			return pkt
		case <-failTimer.C:
			require.Fail(t, "missed egress packet")
		}
	}
}

// waitEgressPacketWithState waits for and returns the first egress packet with the provided state
// generated by the session. Until the packet with the expected state is received, mocks the remote peer
// by periodically "sending" the passed incoming packet into the incoming packets channel.
func waitEgressPacketWithState(t *testing.T, session *bfdSession, inPkt *ControlPacket, expState layers.BFDState) *ControlPacket {
	// fail if the expected state is not reached within this timeframe
	failTimer := time.NewTimer(5 * time.Duration(slowDesiredMinTxInterval) * time.Microsecond)

	// ensure the "remote" periodically transmits the inPkt to us (if provided)
	remoteTxTime := time.Duration(slowDesiredMinTxInterval) * time.Microsecond
	if inPkt != nil {
		remoteTxTime = time.Duration(inPkt.DesiredMinTxInterval) * time.Microsecond
	}
	remoteTxTimer := time.NewTimer(remoteTxTime)

	conn := session.outConn.(*fakeControlConn)
	for {
		select {
		case pkt := <-conn.outPkt:
			if expState == pkt.State {
				return pkt
			}
		case <-remoteTxTimer.C:
			if inPkt != nil {
				session.inPacketsCh <- inPkt
				remoteTxTimer.Reset(remoteTxTime)
			}
		case <-failTimer.C:
			require.Failf(t, "missed state change", "%s expected", expState)
		}
	}
}
