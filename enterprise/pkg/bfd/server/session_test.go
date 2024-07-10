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

type fakeClientConn struct {
	localAddrPort  netip.AddrPort
	remoteAddrPort netip.AddrPort
	outPkt         chan *ControlPacket
}

func (conn *fakeClientConn) Write(pkt *ControlPacket) error {
	conn.outPkt <- pkt
	return nil
}

func (conn *fakeClientConn) LocalAddrPort() netip.AddrPort {
	return conn.localAddrPort
}

func (conn *fakeClientConn) RemoteAddrPort() netip.AddrPort {
	return conn.remoteAddrPort
}

func (conn *fakeClientConn) Close() error {
	return nil
}

func (conn *fakeClientConn) Reset() {
}

type testFixture struct {
	controlConn, echoConn *fakeClientConn
	statusCh              chan types.BFDPeerStatus

	sessionCfg          *types.BFDPeerConfig
	session             *bfdSession
	localDiscriminator  uint32
	remoteDiscriminator uint32
}

func newTestFixture(t *testing.T, echoEnabled bool) *testFixture {
	slowDesiredMinTxInterval = uint32(50 * time.Millisecond / time.Microsecond)  // 50ms to speed up the tests
	slowRequiredMinRxInterval = uint32(30 * time.Millisecond / time.Microsecond) // 30ms to speed up the tests

	logger := log.StandardLogger()
	logger.SetLevel(log.DebugLevel)

	f := &testFixture{
		localDiscriminator:  12345,
		remoteDiscriminator: 56789,
	}

	f.controlConn = &fakeClientConn{
		outPkt: make(chan *ControlPacket, 10),
	}
	f.echoConn = &fakeClientConn{
		outPkt: make(chan *ControlPacket, 10),
	}
	f.sessionCfg = &types.BFDPeerConfig{
		ReceiveInterval:  10 * time.Millisecond,
		TransmitInterval: 11 * time.Millisecond,
		DetectMultiplier: 3,
	}
	if echoEnabled {
		f.sessionCfg.EchoReceiveInterval = 15 * time.Millisecond
		f.sessionCfg.EchoTransmitInterval = 16 * time.Millisecond
	}
	f.statusCh = make(chan types.BFDPeerStatus, 10)

	s, err := newBFDSession(logger, f.sessionCfg, f.controlConn, f.echoConn, f.localDiscriminator, f.statusCh)
	require.NoError(t, err)
	f.session = s

	return f
}

func Test_BFDSessionStateMachine(t *testing.T) {
	f := newTestFixture(t, false)
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
	assertEventualState(t, f.statusCh, types.BFDStateUp, types.BFDDiagnosticNoDiagnostic)
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
	assertEventualState(t, f.statusCh, types.BFDStateUp, types.BFDDiagnosticNoDiagnostic)
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
	f := newTestFixture(t, false)
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
	require.EqualValues(t, cfg.DetectMultiplier, outPkt.DetectMultiplier)
	// DesiredMinTxInterval was increased and session state is Up,
	// the actual transmission interval used MUST NOT change until the Poll Sequence has terminated.
	require.NotEqualValues(t, f.session.local.desiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, cfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, f.session.local.configuredDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	// RequiredMinRxInterval was increased, should apply immediately
	require.EqualValues(t, f.session.local.requiredMinRxInterval, outPkt.RequiredMinRxInterval)
	require.EqualValues(t, cfg.ReceiveInterval/time.Microsecond, outPkt.RequiredMinRxInterval)
	require.EqualValues(t, f.session.local.configuredRequiredMinRxInterval, outPkt.RequiredMinRxInterval)
	f.session.Unlock()

	// Remote replies without Final -> resend Poll
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	require.True(t, outPkt.Poll)
	require.False(t, outPkt.Final)
	f.session.Lock()
	require.EqualValues(t, cfg.DetectMultiplier, outPkt.DetectMultiplier)
	// DesiredMinTxInterval was increased and session state is Up,
	// the actual transmission interval used MUST NOT change until the Poll Sequence has terminated.
	require.NotEqualValues(t, f.session.local.desiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, cfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, f.session.local.configuredDesiredMinTxInterval, outPkt.DesiredMinTxInterval)
	// RequiredMinRxInterval was increased, should apply immediately
	require.EqualValues(t, f.session.local.requiredMinRxInterval, outPkt.RequiredMinRxInterval)
	require.EqualValues(t, cfg.ReceiveInterval/time.Microsecond, outPkt.RequiredMinRxInterval)
	require.EqualValues(t, f.session.local.configuredRequiredMinRxInterval, outPkt.RequiredMinRxInterval)
	f.session.Unlock()

	// Remote replies with Final -> send Poll & Final cleared (Poll sequence terminated, new values applied)
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	inPkt.Final = true
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	require.False(t, outPkt.Poll)
	require.False(t, outPkt.Final)
	f.session.Lock()
	require.EqualValues(t, cfg.DetectMultiplier, outPkt.DetectMultiplier)

	require.EqualValues(t, f.session.local.desiredMinTxInterval, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, cfg.TransmitInterval/time.Microsecond, outPkt.DesiredMinTxInterval)
	require.EqualValues(t, f.session.local.configuredDesiredMinTxInterval, outPkt.DesiredMinTxInterval)

	require.EqualValues(t, f.session.local.requiredMinRxInterval, outPkt.RequiredMinRxInterval)
	require.EqualValues(t, cfg.ReceiveInterval/time.Microsecond, outPkt.RequiredMinRxInterval)
	require.EqualValues(t, f.session.local.configuredRequiredMinRxInterval, outPkt.RequiredMinRxInterval)
	f.session.Unlock()
}

func Test_BFDStatePreservation(t *testing.T) {
	f := newTestFixture(t, false)
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

func Test_BFDSessionEchoFunction(t *testing.T) {
	f := newTestFixture(t, true)
	f.session.start()
	defer f.session.stop()

	assertStateTransition(t, f.statusCh, types.BFDStateDown)

	// L: Down (R: Down) -> Init
	inPkt := createTestControlPacket(f.remoteDiscriminator, 0, layers.BFDStateDown)
	inPkt.RequiredMinEchoRxInterval = 10000
	f.session.inPacketsCh <- inPkt
	outPkt := waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateInit)
	require.EqualValues(t, f.sessionCfg.EchoReceiveInterval/time.Microsecond, outPkt.RequiredMinEchoRxInterval)

	assertNoEgressEchoPacket(t, f.session) // not yet Up

	// L: Init (R: Down) -> Init
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateDown)
	inPkt.RequiredMinEchoRxInterval = 10000
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateInit)
	require.EqualValues(t, f.sessionCfg.EchoReceiveInterval/time.Microsecond, outPkt.RequiredMinEchoRxInterval)
	require.EqualValues(t, f.sessionCfg.ReceiveInterval/time.Microsecond, outPkt.RequiredMinRxInterval)

	assertNoEgressEchoPacket(t, f.session) // not yet Up

	// L: Init (R: Init) -> Up
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateInit)
	inPkt.RequiredMinEchoRxInterval = 10000
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	require.EqualValues(t, slowRequiredMinRxInterval, outPkt.RequiredMinRxInterval)

	echoPkt := waitFirstEgressEchoPacket(t, f.session)
	require.EqualValues(t, f.localDiscriminator, echoPkt.MyDiscriminator)

	// L: Up (R: Up) -> Up
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	inPkt.RequiredMinEchoRxInterval = 10000
	inPkt.Final = true // end Poll sequence after moving to Up to proceed with shorter detection time
	f.session.inPacketsCh <- inPkt
	waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)

	// only Echo packets back-and-forth, let control detection time expire
	attempts := 0
	for {
		// generate incoming echo packet
		inEchoPkt := createTestControlPacket(f.localDiscriminator, f.remoteDiscriminator, layers.BFDStateUp)
		f.session.inEchoPacketsCh <- inEchoPkt

		outPkt = waitFirstEgressPacket(t, f.session)
		if outPkt.State == layers.BFDStateDown {
			// session went down due to control detection time expiration
			require.EqualValues(t, types.BFDDiagnosticControlDetectionTimeExpired, outPkt.Diagnostic)
			break
		}

		// make sure we do not loop indefinitely
		attempts++
		if attempts > 10 {
			require.Fail(t, "failed waiting for control detection time expiration")
		}
	}

	// drain echo packets channel
	drainEgressEchoPackets(f.session)

	// L: Down (R: Init) -> Up - zero remote RequiredMinEchoRxInterval
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateInit)
	f.session.inPacketsCh <- inPkt
	waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)

	assertNoEgressEchoPacket(t, f.session) // zero remote RequiredMinEchoRxInterval

	// L: Up (R: Up) -> Up - zero remote RequiredMinEchoRxInterval
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	inPkt.Final = true // end Poll sequence after moving to Up to proceed with shorter detection time
	f.session.inPacketsCh <- inPkt
	waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)

	assertNoEgressEchoPacket(t, f.session) // zero remote RequiredMinEchoRxInterval

	// L: Up (R: Up) -> Up
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	inPkt.RequiredMinEchoRxInterval = 10000
	f.session.inPacketsCh <- inPkt
	waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)

	inEchoPkt := createTestControlPacket(f.localDiscriminator, f.remoteDiscriminator, layers.BFDStateUp)
	f.session.inEchoPacketsCh <- inEchoPkt
	waitFirstEgressEchoPacket(t, f.session)

	// only control packets back-and-forth, let echo detection time expire

	// L: Up (R: Up) -> Down (Echo function failed)
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateUp)
	inPkt.RequiredMinEchoRxInterval = 10000
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateDown)
	require.EqualValues(t, types.BFDDiagnosticEchoFunctionFailed, outPkt.Diagnostic)
	require.EqualValues(t, f.sessionCfg.ReceiveInterval/time.Microsecond, outPkt.RequiredMinRxInterval)

	// L: Down (R: Init) -> Up
	inPkt = createTestControlPacket(f.remoteDiscriminator, f.localDiscriminator, layers.BFDStateInit)
	inPkt.RequiredMinEchoRxInterval = 10000
	f.session.inPacketsCh <- inPkt
	outPkt = waitEgressPacketWithState(t, f.session, inPkt, layers.BFDStateUp)
	require.EqualValues(t, slowRequiredMinRxInterval, outPkt.RequiredMinRxInterval)

	echoPkt = waitFirstEgressEchoPacket(t, f.session)
	require.EqualValues(t, f.localDiscriminator, echoPkt.MyDiscriminator)

	// Session update from our side -> ReceiveInterval smaller than slowRequiredMinRxInterval, keep using slowRequiredMinRxInterval
	cfg := f.sessionCfg
	cfg.ReceiveInterval = time.Duration(slowRequiredMinRxInterval)*time.Microsecond - time.Millisecond
	err := f.session.update(cfg)
	require.NoError(t, err)
	outPkt = waitEgressPacketWithState(t, f.session, nil, layers.BFDStateUp)
	require.EqualValues(t, slowRequiredMinRxInterval, outPkt.RequiredMinRxInterval)

	echoPkt = waitFirstEgressEchoPacket(t, f.session)
	require.EqualValues(t, f.localDiscriminator, echoPkt.MyDiscriminator)

	// Session update from our side -> ReceiveInterval greater than slowRequiredMinRxInterval, use the new value
	cfg.ReceiveInterval = time.Duration(slowRequiredMinRxInterval)*time.Microsecond + time.Millisecond
	err = f.session.update(cfg)
	require.NoError(t, err)
	outPkt = waitEgressPacketWithState(t, f.session, nil, layers.BFDStateUp)
	require.EqualValues(t, f.sessionCfg.ReceiveInterval/time.Microsecond, outPkt.RequiredMinRxInterval)
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
	// fail if no packet is received within this timeframe
	failTimer := time.NewTimer(5 * time.Duration(slowDesiredMinTxInterval) * time.Microsecond)

	conn := session.outConn.(*fakeClientConn)
	select {
	case pkt := <-conn.outPkt:
		return pkt
	case <-failTimer.C:
		require.Fail(t, "missed egress packet")
	}
	return nil
}

// waitFirstEgressPacket waits for and returns the first egress packet generated by the session.
func waitFirstEgressEchoPacket(t *testing.T, session *bfdSession) *ControlPacket {
	// fail if no packet is received within this timeframe
	failTimer := time.NewTimer(5 * time.Duration(slowDesiredMinTxInterval) * time.Microsecond)

	conn := session.outEchoConn.(*fakeClientConn)
	select {
	case pkt := <-conn.outPkt:
		return pkt
	case <-failTimer.C:
		require.Fail(t, "missed egress Echo packet")
	}
	return nil
}

// assertNoEgressEchoPacket asserts that there was no egress echo packet generated by the session
// since session creation / echo packets drain.
func assertNoEgressEchoPacket(t *testing.T, session *bfdSession) {
	conn := session.outEchoConn.(*fakeClientConn)
	select {
	case <-conn.outPkt:
		require.Fail(t, "unexpected Echo packet was sent")
	default:
		return
	}
}

// drainEchoPackets drains egress echo packets channel of the session.
func drainEgressEchoPackets(session *bfdSession) {
	conn := session.outEchoConn.(*fakeClientConn)
	for len(conn.outPkt) > 0 {
		<-conn.outPkt
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

	conn := session.outConn.(*fakeClientConn)
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
