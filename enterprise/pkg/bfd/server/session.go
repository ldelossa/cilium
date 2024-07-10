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
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"

	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"

	"github.com/cilium/cilium/enterprise/pkg/bfd/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// inPacketChannelSize is the buffer size of the incoming packet channel for each session.
	// Normally it should never get filled, as in most cases, the processing of the incoming
	// packet involves only updating session state variables.
	// If the channel is full, it may be that the remote system is sending packets too fast.
	// In such case, the server may drop the packet instead of delivering it.
	inPacketChannelSize = 100

	// minNotUpDesiredMinTxInterval is the minimal value for the DesiredMinTxInterval when the session is not Up.
	// (When bfd.SessionState is not Up, the system MUST set bfd.DesiredMinTxInterval
	// to a value of not less than one second (1,000,000 microseconds)
	minNotUpDesiredMinTxInterval = uint32(time.Second / time.Microsecond)

	// minEchoActiveRequiredMinRxInterval is the minimal value for the RequiredMinRxInterval when Echo Function is active
	// (When the Echo function is active, a system SHOULD set bfd.RequiredMinRxInterval to a value
	// of not less than one second (1,000,000 microseconds))
	minEchoActiveRequiredMinRxInterval = uint32(time.Second / time.Microsecond)
)

var (
	// slowDesiredMinTxInterval is the value of the bfd.DesiredMinTxInterval used if the session is not Up.
	// This is hold in a variable (instead of const) just to allow overriding it in tests to speed them up.
	slowDesiredMinTxInterval = minNotUpDesiredMinTxInterval

	// slowRequiredMinRxInterval is the value of the bfd.RequiredMinRxInterval used when Echo Function is active.
	// This is hold in a variable (instead of const) just to allow overriding it in tests to speed them up.
	slowRequiredMinRxInterval = minEchoActiveRequiredMinRxInterval
)

// bfdSession represents a single BFD session between the local system and a remote peer.
// It processes received BFD packets de-multiplexed to the session and generates BFD packets to transmit,
// while holding the internal state in the state variables as defined in RFC 5880, section 6.8.1.
type bfdSession struct {
	lock.Mutex
	logger log.FieldLogger

	// stopChan is used to stop the main session processing goroutine
	stopChan chan struct{}

	// statusCh is used to deliver session status updates upon each status change
	statusCh chan types.BFDPeerStatus

	// inPacketsCh is used to deliver incoming BFD Control packets de-multiplexed to this session
	inPacketsCh chan *ControlPacket

	// inEchoPacketsCh is used to deliver incoming BFD Echo packets de-multiplexed to this session
	inEchoPacketsCh chan *ControlPacket

	// outConn is the packet connection associated with this session used for sending outgoing BFD Control packets
	outConn bfdClientConnection

	// outEchoConn is the packet connection associated with this session used for sending outgoing BFD Echo packets
	outEchoConn bfdClientConnection

	// peerAddress is the remote peer's IP address
	peerAddress netip.Addr

	// networkInterface this session is bound to (can be empty in case it is not bound to any interface)
	networkInterface string

	// current calculated transmission interval & transmit timer
	curTransmitInterval time.Duration
	transmitTimer       *time.Timer

	// current calculated Echo transmission interval & Echo transmit timer
	curEchoTransmitInterval time.Duration
	echoTransmitTimer       *time.Timer

	// current calculated detection time & detection timer
	curDetectionTime  time.Duration
	curDetectionTimer *time.Timer

	// current calculated Echo detection time & Echo detection timer
	curEchoDetectionTime  time.Duration
	curEchoDetectionTimer *time.Timer

	// lastPacketReceived is the time of receipt of last BFD Control packet
	lastPacketReceived time.Time

	// lastStateChange is the time of the last session state transition
	lastStateChange time.Time

	// statePreserveTime is the time until the state of the session has to be preserved
	statePreserveTime time.Time

	// local holds session state variables as perceived by the local system
	local bfdLocalState

	// remote holds session state variables as perceived by the remote system
	remote bfdRemoteState
}

// bfdLocalState holds session state variables as perceived by the local system.
type bfdLocalState struct {
	// passiveMode is true if this system is in taking a passive role in session initialization
	// (it will not begin sending BFD packets for a particular session until it has received
	// a BFD packet for that session (RFC 5880, section 6.1.))
	passiveMode bool

	// demandMode represents the bfd.DemandMode state variable:
	//   Set to 1 if the local system wishes to use Demand mode, or 0 if not.
	//
	// NOTE: local demand mode is not supported at the moment.
	//demandMode bool

	// inPollSequence is true if we have initiated the Poll Sequence (RFC 5880, section 6.5)
	inPollSequence bool

	// sessionState represents the bfd.SessionState state variable:
	//   Perceived state of the session (Init, Up, Down, or AdminDown).
	sessionState types.BFDState

	// discriminator represents the bfd.LocalDiscr state variable:
	//   The local discriminator for this BFD session, used to uniquely
	//   identify it. It MUST be unique across all BFD sessions on this
	//   system, and nonzero. It SHOULD be set to a random (but still
	//   unique) value to improve security.
	discriminator uint32

	// diagnostic represents the bfd.LocalDiag state variable:
	//   The diagnostic code specifying the reason for the most recent
	//   change in the local session state.
	diagnostic types.BFDDiagnostic

	// desiredMinTxInterval represents the bfd.DesiredMinTxInterval state variable:
	//   The minimum interval, in microseconds, between transmitted BFD
	//   Control packets that this system would like to use at the current
	//   time, less any jitter applied (see section 6.8.2).  The actual
	//   interval is negotiated between the two systems.
	//
	//   When bfd.SessionState is not Up, the system MUST set
	//   bfd.DesiredMinTxInterval to a value of not less than one second
	//   (1,000,000 microseconds).  This is intended to ensure that the
	//   bandwidth consumed by BFD sessions that are not Up is negligible,
	//   particularly in the case where a neighbor may not be running BFD.
	desiredMinTxInterval uint32

	// configuredDesiredMinTxInterval holds configured (desired) value for the bfd.DesiredMinTxInterval,
	// as the actual value may be changed if the session is not Up, or if the Poll sequence needs to finish
	// before applying new value.
	configuredDesiredMinTxInterval uint32

	// desiredMinTxIntervalApplied is true if the configuredDesiredMinTxInterval has been applied to desiredMinTxInterval,
	// false if this has not happened yet - if the Poll sequence was needed before applying and has not finished yet.
	desiredMinTxIntervalApplied bool

	// requiredMinRxInterval represents the bfd.RequiredMinRxInterval state variable:
	//   The minimum interval, in microseconds, between received BFD
	//   Control packets that this system requires, less any jitter applied
	//   by the sender (see section 6.8.2).
	requiredMinRxInterval uint32

	// configuredRequiredMinRxInterval holds configured value for the RequiredMinRxInterval,
	// as the currently used value may be different from the configured one during the Poll Sequence.
	configuredRequiredMinRxInterval uint32

	// requiredMinRxIntervalApplied is true if the configuredRequiredMinRxInterval has been applied to requiredMinRxInterval,
	// false if this has not happened yet - if the Poll sequence was needed before applying and has not finished yet.
	requiredMinRxIntervalApplied bool

	// detectMultiplier represents the bfd.DetectMult state variable:
	//   The desired Detection Time multiplier for BFD Control packets on
	//   the local system.  The negotiated Control packet transmission
	//   interval, multiplied by this variable, will be the Detection Time
	//   for this session (as seen by the remote system).
	detectMultiplier uint8

	// requiredMinEchoRxInterval the minimum interval, in microseconds, between received
	// BFD Echo packets that this system is capable of supporting, less
	// any jitter applied by the sender.
	// Zero value disables the Echo function in the direction towards the local system.
	requiredMinEchoRxInterval uint32

	// desiredMinEchoTxInterval defines the minimum interval that the local system would like to use when
	// transmitting BFD Echo packets, less any jitter applied.
	// Non-zero value enables the Echo Function in the direction towards the remote system.
	// Zero value disables the Echo function in the direction towards the remote system.
	desiredMinEchoTxInterval uint32
}

// bfdRemoteState holds session state variables as perceived by the remote system.
type bfdRemoteState struct {
	// demandMode represents the bfd.RemoteDemandMode state variable:
	//   Set to 1 if the remote system wishes to use Demand mode, or 0 if
	//   not.  This is the value of the Demand (D) bit in the last received
	//   BFD Control packet.
	demandMode bool

	// sessionState represents the bfd.RemoteSessionState state variable:
	//   The session state last reported by the remote system in the State
	//   (Sta) field of the BFD Control packet.
	sessionState types.BFDState

	// discriminator represents the bfd.RemoteDiscr state variable:
	//   The remote discriminator for this BFD session.  This is the
	//   discriminator chosen by the remote system, and is totally opaque
	//   to the local system.  This MUST be initialized to zero.  If a
	//   period of a Detection Time passes without the receipt of a valid,
	//   authenticated BFD packet from the remote system, this variable
	//   MUST be set to zero.
	discriminator uint32

	// diagnostic is the diagnostic code last reported by the remote system
	// in the Diag field of the BFD Control packet.
	diagnostic types.BFDDiagnostic

	// 	desiredMinTxInterval uint32 is the last value of Desired Min Tx interval
	// received from the remote system in a BFD Control packet.
	desiredMinTxInterval uint32

	// requiredMinRxInterval represents the bfd.RemoteMinRxInterval state variable:
	//  The last value of Required Min RX Interval received from the
	//   remote system in a BFD Control packet.
	requiredMinRxInterval uint32

	// detectMultiplier is the last value of the desired Detection Time multiplier
	// received from the remote system in a BFD Control packet.
	detectMultiplier uint8

	// requiredMinEchoRxInterval is the last value of the Required Min Echo RX Interval
	// received from the remote system in a BFD Control packet.
	requiredMinEchoRxInterval uint32
}

// newBFDSession creates a new BFD session with provided configuration.
func newBFDSession(logger log.FieldLogger, cfg *types.BFDPeerConfig, conn, echoConn bfdClientConnection, localDiscr uint32, statusUpdateCh chan types.BFDPeerStatus) (*bfdSession, error) {
	if cfg.PeerAddress.IsUnspecified() {
		return nil, fmt.Errorf("PeerAddress not specified")
	}
	if cfg.ReceiveInterval == 0 {
		return nil, fmt.Errorf("ReceiveInterval is zero")
	}
	if cfg.TransmitInterval == 0 {
		return nil, fmt.Errorf("TransmitInterval is zero")
	}
	if cfg.DetectMultiplier == 0 {
		return nil, fmt.Errorf("DetectMultiplier is zero")
	}

	s := &bfdSession{
		logger: logger.WithFields(log.Fields{
			types.PeerAddressField:   cfg.PeerAddress,
			types.DiscriminatorField: localDiscr,
		}),
		peerAddress:      cfg.PeerAddress,
		networkInterface: cfg.Interface,
		outConn:          conn,
		outEchoConn:      echoConn,
		inPacketsCh:      make(chan *ControlPacket, inPacketChannelSize),
		inEchoPacketsCh:  make(chan *ControlPacket, inPacketChannelSize),
		stopChan:         make(chan struct{}),
		statusCh:         statusUpdateCh,
		local: bfdLocalState{
			discriminator:                   localDiscr,
			passiveMode:                     cfg.PassiveMode,
			detectMultiplier:                cfg.DetectMultiplier,
			requiredMinRxInterval:           uint32(cfg.ReceiveInterval / time.Microsecond),
			configuredRequiredMinRxInterval: uint32(cfg.ReceiveInterval / time.Microsecond),
			requiredMinRxIntervalApplied:    true,
			desiredMinTxInterval:            uint32(cfg.TransmitInterval / time.Microsecond),
			configuredDesiredMinTxInterval:  uint32(cfg.TransmitInterval / time.Microsecond),
			desiredMinTxIntervalApplied:     true,
			requiredMinEchoRxInterval:       uint32(cfg.EchoReceiveInterval / time.Microsecond),
			desiredMinEchoTxInterval:        uint32(cfg.EchoTransmitInterval / time.Microsecond),
			sessionState:                    types.BFDStateDown, // RFC 5880 6.8.1. State Variables: This variable MUST be initialized to Down.
		},
		remote: bfdRemoteState{
			requiredMinRxInterval: 1, // RFC 5880 6.8.1. State Variables: This variable MUST be initialized to 1.
		},
	}

	// When bfd.SessionState is not Up, the system MUST set bfd.DesiredMinTxInterval
	// to a value of not less than one second (1,000,000 microseconds).
	if cfg.TransmitInterval < time.Second {
		s.local.desiredMinTxInterval = slowDesiredMinTxInterval
	}

	return s, nil
}

// start starts the session processing.
func (s *bfdSession) start() {
	go s.worker()
}

// stop stops the session. No further BFD packets will be processed / sent for this session.
func (s *bfdSession) stop() {
	close(s.stopChan)
}

// update updates the session with the new configuration.
// Only changes in timer parameters are accepted, all other changes are ignored.
func (s *bfdSession) update(cfg *types.BFDPeerConfig) error {
	s.Lock()
	defer s.Unlock()

	if cfg.ReceiveInterval == 0 {
		return fmt.Errorf("ReceiveInterval is zero")
	}
	if cfg.TransmitInterval == 0 {
		return fmt.Errorf("TransmitInterval is zero")
	}
	if cfg.DetectMultiplier == 0 {
		return fmt.Errorf("DetectMultiplier is zero")
	}

	echoDetectTimeAffected := false // tracks whether Echo detection time has been affected and needs an update

	cfgTransmitInterval := uint32(cfg.TransmitInterval / time.Microsecond)
	cfgReceiveInterval := uint32(cfg.ReceiveInterval / time.Microsecond)

	// 6.8.3.  Timer Manipulation
	// If either bfd.DesiredMinTxInterval is changed or bfd.RequiredMinRxInterval is changed,
	// a Poll Sequence MUST be initiated (see section 6.5).

	//   If bfd.DesiredMinTxInterval is increased and bfd.SessionState is Up,
	//   the actual transmission interval used MUST NOT change until the Poll
	//   Sequence described above has terminated.  This is to ensure that the
	//   remote system updates its Detection Time before the transmission
	//   interval increases.
	if s.local.configuredDesiredMinTxInterval != cfgTransmitInterval {
		if s.local.configuredDesiredMinTxInterval < cfgTransmitInterval && s.local.sessionState == types.BFDStateUp {
			s.local.desiredMinTxIntervalApplied = false
		} else {
			s.local.desiredMinTxInterval = cfgTransmitInterval
		}
		s.local.configuredDesiredMinTxInterval = cfgTransmitInterval
		s.local.inPollSequence = true
	}

	//   If bfd.RequiredMinRxInterval is reduced and bfd.SessionState is Up,
	//   the previous value of bfd.RequiredMinRxInterval MUST be used when
	//   calculating the Detection Time for the remote system until the Poll
	//   Sequence described above has terminated.  This is to ensure that the
	//   remote system is transmitting packets at the higher rate (and those
	//   packets are being received) prior to the Detection Time being
	//   reduced.
	if s.local.configuredRequiredMinRxInterval != cfgReceiveInterval {
		if s.curEchoTransmitInterval == 0 || cfgReceiveInterval > slowRequiredMinRxInterval {
			// Change the effective value only if the Echo Function is not active,
			// or the configured rx interval is larger than slowRequiredMinRxInterval
			// (When the Echo function is active, a system SHOULD set bfd.RequiredMinRxInterval to a value
			// of not less than one second (1,000,000 microseconds))

			if s.local.configuredRequiredMinRxInterval > cfgReceiveInterval && s.local.sessionState == types.BFDStateUp {
				s.local.requiredMinRxIntervalApplied = false
			} else {
				s.local.requiredMinRxInterval = cfgReceiveInterval
			}
			s.local.inPollSequence = true
		}
		s.local.configuredRequiredMinRxInterval = cfgReceiveInterval
	}

	// 6.8.12.  Detect Multiplier Change
	// The new value will be transmitted with the next BFD Control packet, and the use of
	// a Poll Sequence is not necessary.
	if s.local.detectMultiplier != cfg.DetectMultiplier {
		s.local.detectMultiplier = cfg.DetectMultiplier
		echoDetectTimeAffected = true
	}

	// 6.8.13.  Enabling or Disabling The Echo Function
	// If it is desired to enable or disable the looping back of received
	// BFD Echo packets, this MAY be done at any time by changing the value
	// of Required Min Echo RX Interval to zero or nonzero in outgoing BFD
	// Control packets.
	s.local.requiredMinEchoRxInterval = uint32(cfg.EchoReceiveInterval / time.Microsecond)

	// update echo transmit interval, which is only a local matter
	echoTransmitInterval := uint32(cfg.EchoTransmitInterval / time.Microsecond)
	if s.local.desiredMinEchoTxInterval != echoTransmitInterval {
		s.local.desiredMinEchoTxInterval = echoTransmitInterval
		echoDetectTimeAffected = true
	}

	if echoDetectTimeAffected {
		// if the Echo detection time was affected, update Echo transmit & detection times immediately
		s.updateEchoTransmitInterval()
		s.updateEchoDetectionTime()
	}

	s.notifyStatusChange()

	return nil
}

// setAdminDown configures the session to be administratively down.
// While AdminDown, we will still continue sending the control packets.
func (s *bfdSession) setAdminDown() {
	s.Lock()
	defer s.Unlock()

	// RFC 5880 6.8.16.  Administrative Control
	//     Set bfd.SessionState to AdminDown
	//     Set bfd.LocalDiag to an appropriate value
	//     Cease the transmission of BFD Echo packets
	s.local.sessionState = types.BFDStateAdminDown
	s.local.diagnostic = types.BFDDiagnosticAdministrativelyDown
	s.lastStateChange = time.Now()

	// BFD Control packets SHOULD be transmitted for at least a Detection
	// Time after transitioning to AdminDown state in order to ensure that
	// the remote system is aware of the state change.  BFD Control packets
	// MAY be transmitted indefinitely after transitioning to AdminDown
	// state in order to maintain session state in each system.

	// When bfd.SessionState is not Up, the system MUST set bfd.DesiredMinTxInterval
	// to a value of not less than one second (1,000,000 microseconds).
	if s.local.desiredMinTxInterval < minNotUpDesiredMinTxInterval {
		s.local.desiredMinTxInterval = slowDesiredMinTxInterval // session not up - no need to wait until Poll terminates
		s.local.inPollSequence = true
	}

	s.notifyStatusChange()
}

// setAdminUp sets the session state to administratively up, if it was AdminDown before.
func (s *bfdSession) setAdminUp() {
	s.Lock()
	defer s.Unlock()

	if s.local.sessionState != types.BFDStateAdminDown {
		return
	}

	// RFC 5880 6.8.16.  Administrative Control
	// If enabling session Set bfd.SessionState to Down
	s.local.sessionState = types.BFDStateDown
	s.local.diagnostic = types.BFDDiagnosticNoDiagnostic
	s.lastStateChange = time.Now()

	s.notifyStatusChange()
}

// worker is the main processing routine of the session, handling incoming packets and timer events.
func (s *bfdSession) worker() {
	s.Lock()

	// initialize timers
	s.curDetectionTimer = time.NewTimer(time.Duration(math.MaxInt64))
	s.curEchoDetectionTimer = time.NewTimer(time.Duration(math.MaxInt64))
	s.curEchoDetectionTimer.Stop() // echo is stopped by default
	s.transmitTimer = time.NewTimer(time.Duration(math.MaxInt64))
	s.echoTransmitTimer = time.NewTimer(time.Duration(math.MaxInt64))
	s.echoTransmitTimer.Stop() // echo is stopped by default
	s.updateTransmitInterval()
	s.updateEchoTransmitInterval()

	// send initial session state update
	s.lastStateChange = time.Now()
	s.notifyStatusChange()

	s.Unlock()

loop:
	for {
		select {
		case pkt := <-s.inPacketsCh:
			s.handleIncomingControlPacket(pkt)
		case pkt := <-s.inEchoPacketsCh:
			s.handleIncomingEchoPacket(pkt)
		case <-s.transmitTimer.C:
			err := s.sendPeriodicControlPacket()
			if err != nil {
				s.logger.WithError(err).Error("Error by sending BFD Control packet")
			}
		case <-s.echoTransmitTimer.C:
			err := s.sendPeriodicEchoPacket()
			if err != nil {
				s.logger.WithError(err).Error("Error by sending BFD Echo packet")
			}
		case <-s.curDetectionTimer.C:
			err := s.handleDetectionTimerExpiration()
			if err != nil {
				s.logger.WithError(err).Error("Error by handling BFD detection timer expiration")
			}
		case <-s.curEchoDetectionTimer.C:
			err := s.handleEchoDetectionTimerExpiration()
			if err != nil {
				s.logger.WithError(err).Error("Error by handling BFD Echo detection timer expiration")
			}
		case <-s.stopChan:
			break loop
		}
	}

	// stop timers
	s.Lock()
	s.transmitTimer.Stop()
	s.echoTransmitTimer.Stop()
	s.curDetectionTimer.Stop()
	s.curEchoDetectionTimer.Stop()
	s.Unlock()
}

// handleIncomingControlPacket handles an incoming Control packet for this session.
func (s *bfdSession) handleIncomingControlPacket(pkt *ControlPacket) {
	s.Lock()
	defer s.Unlock()

	s.lastPacketReceived = time.Now()

	// tracks whether the session state has been changed as part of the packet processing
	sessionStateChanged := false
	// tracks whether status change notification should be sent
	notifyStatusChange := false

	// keep remote state for informational purposes
	s.remote.diagnostic = types.BFDDiagnostic(pkt.Diagnostic)
	s.remote.detectMultiplier = uint8(pkt.DetectMultiplier)
	s.remote.requiredMinEchoRxInterval = uint32(pkt.RequiredMinEchoRxInterval)
	s.remote.desiredMinTxInterval = uint32(pkt.DesiredMinTxInterval)

	// RFC 5880 6.8.6.  Reception of BFD Control Packets:

	// Set bfd.RemoteDiscr to the value of My Discriminator.
	s.remote.discriminator = uint32(pkt.MyDiscriminator)

	// Set bfd.RemoteState to the value of the State (Sta) field.
	s.remote.sessionState = types.BFDState(pkt.State)

	// Set bfd.RemoteDemandMode to the value of the Demand (D) bit.
	s.remote.demandMode = pkt.Demand

	// Set bfd.RemoteMinRxInterval to the value of Required Min RX Interval.
	s.remote.requiredMinRxInterval = uint32(pkt.RequiredMinRxInterval)

	// If a Poll Sequence is being transmitted by the local system and
	// the Final (F) bit in the received packet is set, the Poll Sequence
	// MUST be terminated.
	if s.local.inPollSequence && pkt.Final {
		s.local.inPollSequence = false
		notifyStatusChange = true

		// if the desiredMinTxInterval or requiredMinRxInterval were changed, they will become effective now
		if !s.local.desiredMinTxIntervalApplied {
			s.local.desiredMinTxInterval = s.local.configuredDesiredMinTxInterval
			s.local.desiredMinTxIntervalApplied = true
		}
		if !s.local.requiredMinRxIntervalApplied {
			s.local.requiredMinRxInterval = s.local.configuredRequiredMinRxInterval
			s.local.requiredMinRxIntervalApplied = true
		}
	}

	// Update the transmit interval as described in section 6.8.2.
	s.updateTransmitInterval()
	s.updateEchoTransmitInterval()

	// Update the Detection Time as described in section 6.8.4.
	s.updateDetectionTime(pkt)
	s.updateEchoDetectionTime()

	// If bfd.SessionState is AdminDown Discard the packet (section 6.8.6.)
	if s.local.sessionState == types.BFDStateAdminDown {
		return
	}

	// If received state is AdminDown
	if pkt.State == layers.BFDStateAdminDown {
		// If bfd.SessionState is not Down
		if s.local.sessionState != types.BFDStateDown {
			// Set bfd.SessionState to Down
			// Set bfd.LocalDiag to 3 (Neighbor signaled session down)
			sessionStateChanged = s.changeStateIfAllowed(types.BFDStateDown, types.BFDDiagnosticNeighborSignaledSessionDown)
		}
	} else {
		// If bfd.SessionState is Down
		if s.local.sessionState == types.BFDStateDown {
			// If received State is Down
			if pkt.State == layers.BFDStateDown {
				// Set bfd.SessionState to Init
				sessionStateChanged = s.changeStateIfAllowed(types.BFDStateInit, types.BFDDiagnosticNoDiagnostic)

				// Else if received State is Init
			} else if pkt.State == layers.BFDStateInit {
				// Set bfd.SessionState to Up
				sessionStateChanged = s.changeStateIfAllowed(types.BFDStateUp, types.BFDDiagnosticNoDiagnostic)
			}

			// Else if bfd.SessionState is Init
		} else if s.local.sessionState == types.BFDStateInit {
			// If received State is Init or Up
			if pkt.State == layers.BFDStateInit || pkt.State == layers.BFDStateUp {
				// Set bfd.SessionState to Up
				sessionStateChanged = s.changeStateIfAllowed(types.BFDStateUp, types.BFDDiagnosticNoDiagnostic)
			}

			// Else (bfd.SessionState is Up)
		} else {
			// If received State is Down
			if pkt.State == layers.BFDStateDown {
				// Set bfd.SessionState to Down
				// Set bfd.LocalDiag to 3 (Neighbor signaled session down)
				sessionStateChanged = s.changeStateIfAllowed(types.BFDStateDown, types.BFDDiagnosticNeighborSignaledSessionDown)
			}
		}
	}

	// If the Poll (P) bit is set, send a BFD Control packet to the
	// remote system with the Poll (P) bit clear, and the Final (F) bit
	// set (see section 6.8.7).
	if pkt.Poll {
		s.sendFinalPacket()
		notifyStatusChange = true
	}

	// If the packet was not discarded, it has been received for purposes
	// of the Detection Time expiration rules in section 6.8.4.
	s.resetDetectionTimer()

	if sessionStateChanged {
		// notify about the change
		notifyStatusChange = true

		txIntervalChanged := false
		if s.local.sessionState != types.BFDStateUp {
			// When bfd.SessionState is not Up, the system MUST set bfd.DesiredMinTxInterval
			// to a value of not less than one second (1,000,000 microseconds).
			if s.local.desiredMinTxInterval < minNotUpDesiredMinTxInterval {
				// DesiredMinTxInterval is increased, but session not Up - no need to wait until Poll terminates
				s.local.desiredMinTxInterval = slowDesiredMinTxInterval
				txIntervalChanged = true
			}
		} else {
			// if the session went Up, start using configured DesiredMinTxInterval if it differs from the actual one
			if s.local.desiredMinTxInterval != s.local.configuredDesiredMinTxInterval {
				// DesiredMinTxInterval is lowered here from slowDesiredMinTxInterval - no need to wait until Poll terminates
				s.local.desiredMinTxInterval = s.local.configuredDesiredMinTxInterval
				txIntervalChanged = true
			}
		}
		if txIntervalChanged {
			// tx interval changed, we should initiate Poll Sequence and update transmit interval
			if !pkt.Poll {
				// If the timing is such that a system
				// receiving a Poll Sequence wishes to change the parameters described
				// in this paragraph, the new parameter values MAY be carried in packets
				// with the Final (F) bit set, even if the Poll Sequence has not yet
				// been sent
				s.local.inPollSequence = true
			}
			s.updateTransmitInterval()
		}
		s.updateEchoTransmitInterval() // if the session state changed, we may need to update echo transmit interval
	}

	// notify if any session status changes were detected
	if notifyStatusChange {
		s.notifyStatusChange()
	}
}

// handleIncomingEchoPacket handles an incoming Echo packet for this session.
func (s *bfdSession) handleIncomingEchoPacket(pkt *ControlPacket) {
	s.Lock()
	defer s.Unlock()

	s.resetEchoDetectionTimer()
}

// changeStateIfAllowed changes session state to the provided value if it is allowed
// (if the state should not be preserved for some more time).
func (s *bfdSession) changeStateIfAllowed(state types.BFDState, diagnostic types.BFDDiagnostic) bool {
	if s.local.sessionState == state {
		return false
	}

	// RFC 5880 6.8.1.  State Variables
	//  Once session state is created, and at least one BFD Control packet is
	//  received from the remote end, it MUST be preserved for at least one
	//  Detection Time (see section 6.8.4) subsequent to the receipt of the
	//  last BFD Control packet, regardless of the session state.  This
	//  preserves timing parameters in case the session flaps.  A system MAY
	//  preserve session state longer than this.s
	if !s.lastPacketReceived.IsZero() && !s.statePreserveTime.IsZero() && s.statePreserveTime.After(time.Now()) {
		return false // state should be preserved
	}

	// state can be changed
	s.changeState(state, diagnostic)
	return true
}

// changeState changes session state to the provided value.
func (s *bfdSession) changeState(state types.BFDState, diagnostic types.BFDDiagnostic) {
	s.local.sessionState = state
	s.local.diagnostic = diagnostic

	s.lastStateChange = time.Now()
	s.statePreserveTime = s.lastPacketReceived.Add(s.curDetectionTime)
}

// sendPeriodicControlPacket sends a periodic control packet for the session.
func (s *bfdSession) sendPeriodicControlPacket() error {
	s.Lock()
	defer s.Unlock()

	// set a new timer after sending this periodic packet
	defer s.setTransmitTimer()

	// A system MUST NOT transmit BFD Control packets if bfd.RemoteDiscr is
	// zero and the system is taking the Passive role.
	if s.remote.discriminator == 0 && s.local.passiveMode {
		return nil
	}

	// A system MUST NOT periodically transmit BFD Control packets if
	// bfd.RemoteMinRxInterval is zero.
	if s.remote.requiredMinRxInterval == 0 {
		return nil
	}

	// A system MUST NOT periodically transmit BFD Control packets if Demand
	// mode is active on the remote system (bfd.RemoteDemandMode is 1,
	// bfd.SessionState is Up, and bfd.remoteSessionState is Up) and a Poll
	// Sequence is not being transmitted.
	if s.remote.demandMode &&
		s.local.sessionState == types.BFDStateUp &&
		s.remote.sessionState == types.BFDStateUp &&
		!s.local.inPollSequence {
		return nil
	}

	pkt := s.createControlPacket(false)

	err := s.outConn.Write(pkt)
	if err != nil {
		// the peer may be already down, just log this
		s.logger.WithError(err).Debug("Error by writing to BFD connection")
	}

	return nil
}

// sendPeriodicEchoPacket sends a periodic Echo packet for the session.
func (s *bfdSession) sendPeriodicEchoPacket() error {
	s.Lock()
	defer s.Unlock()

	// BFD Echo packets MUST NOT be transmitted when bfd.SessionState is not Up.
	if s.local.sessionState != types.BFDStateUp {
		return nil
	}

	// BFD Echo packets MUST NOT be transmitted unless the last BFD
	// Control packet received from the remote system contains a nonzero
	// value in Required Min Echo RX Interval.
	if s.remote.requiredMinEchoRxInterval == 0 {
		return nil
	}

	pkt := s.createControlPacket(false)

	err := s.outEchoConn.Write(pkt)
	if err != nil {
		// the peer may be already down, just log this
		s.logger.WithError(err).Debug("Error by writing to BFD Echo connection")
	}

	// set a timer for the next packet
	s.setEchoTransmitTimer()

	return nil
}

// handleDetectionTimerExpiration handles expiration of the detection timer.
func (s *bfdSession) handleDetectionTimerExpiration() error {
	s.Lock()
	defer s.Unlock()

	// 6.8.1.  BFDState Variables - bfd.RemoteDiscr
	// If a period of a Detection Time passes without the receipt of a valid,
	// authenticated BFD packet from the remote system, this variable
	// MUST be set to zero.
	s.remote.discriminator = 0

	// 6.8.4.  Calculating the Detection Time

	// If Demand mode is not active, and a period of time equal to the
	// Detection Time passes without receiving a BFD Control packet from the
	// remote system, and bfd.SessionState is Init or Up, the session has
	// gone down -- the local system MUST set bfd.SessionState to Down and
	// bfd.LocalDiag to 1 (Control Detection Time Expired).
	if s.local.sessionState == types.BFDStateUp || s.local.sessionState == types.BFDStateInit {
		s.logger.Debug("Control detection timer expired, session Down")

		// change the state (as the detection timer expired, we don't need to check if it needs to be preserved)
		s.changeState(types.BFDStateDown, types.BFDDiagnosticControlDetectionTimeExpired)

		// When bfd.SessionState is not Up, the system MUST set bfd.DesiredMinTxInterval
		// to a value of not less than one second (1,000,000 microseconds).
		if s.local.desiredMinTxInterval < minNotUpDesiredMinTxInterval {
			s.local.desiredMinTxInterval = slowDesiredMinTxInterval
		}

		s.notifyStatusChange()
		if err := s.sendStateUpdatePacket(); err != nil {
			// peer most likely down, just log this
			s.logger.WithError(err).Debug("Error sending state update to BFD peer")
		}
	}

	return nil
}

// handleEchoDetectionTimerExpiration handles expiration of the Echo detection timer.
func (s *bfdSession) handleEchoDetectionTimerExpiration() error {
	s.Lock()
	defer s.Unlock()

	// 6.8.5.  Detecting Failures with the Echo Function
	//   When the Echo function is active and a sufficient number of Echo
	//   packets have not arrived as they should, the session has gone down --
	//   the local system MUST set bfd.SessionState to Down and bfd.LocalDiag
	//   to 2 (Echo Function Failed).

	if s.curEchoTransmitInterval > 0 && s.local.sessionState == types.BFDStateUp {
		s.logger.Debug("Echo detection timer expired, session Down")

		// change the state (as the detection timer expired, we don't need to check if it needs to be preserved)
		s.changeState(types.BFDStateDown, types.BFDDiagnosticEchoFunctionFailed)

		// When bfd.SessionState is not Up, the system MUST set bfd.DesiredMinTxInterval
		// to a value of not less than one second (1,000,000 microseconds).
		if s.local.desiredMinTxInterval < minNotUpDesiredMinTxInterval {
			s.local.desiredMinTxInterval = slowDesiredMinTxInterval
		}

		s.updateEchoTransmitInterval() // affected by session state change

		s.notifyStatusChange()
		if err := s.sendStateUpdatePacket(); err != nil {
			// peer most likely down, just log this
			s.logger.WithError(err).Debug("Error sending state update to BFD peer")
		}
	}

	return nil
}

func (s *bfdSession) updateTransmitInterval() {
	oldInterval := s.curTransmitInterval

	// RFC 5880 6.8.2. + 6.8.7.
	//  With the exceptions listed in the remainder of this section, a system
	//  MUST NOT transmit BFD Control packets at an interval less than the
	//  larger of bfd.DesiredMinTxInterval and bfd.RemoteMinRxInterval, less
	//  applied jitter (see below).  In other words, the system reporting the
	//  slower rate determines the transmission rate.

	if s.local.desiredMinTxInterval > s.remote.requiredMinRxInterval {
		s.curTransmitInterval = time.Duration(s.local.desiredMinTxInterval) * time.Microsecond
	} else {
		s.curTransmitInterval = time.Duration(s.remote.requiredMinRxInterval) * time.Microsecond
	}

	if s.curTransmitInterval != oldInterval {
		s.setTransmitTimer()
	}
}

func (s *bfdSession) updateEchoTransmitInterval() {
	oldInterval := s.curEchoTransmitInterval

	if s.local.sessionState != types.BFDStateUp || s.local.desiredMinEchoTxInterval == 0 || s.remote.requiredMinEchoRxInterval == 0 {
		// RFC 5880 6.8.9.
		//   BFD Echo packets MUST NOT be transmitted when bfd.SessionState is not
		//   Up.  BFD Echo packets MUST NOT be transmitted unless the last BFD
		//   Control packet received from the remote system contains a nonzero
		//   value in Required Min Echo RX Interval.
		s.curEchoTransmitInterval = 0
	} else {
		// RFC 5880 6.8.9.
		//   The interval between transmitted BFD Echo packets MUST NOT be less than
		//   the value advertised by the remote system in Required Min Echo RX Interval
		if s.local.desiredMinEchoTxInterval > s.remote.requiredMinEchoRxInterval {
			s.curEchoTransmitInterval = time.Duration(s.local.desiredMinEchoTxInterval) * time.Microsecond
		} else {
			s.curEchoTransmitInterval = time.Duration(s.remote.requiredMinEchoRxInterval) * time.Microsecond
		}
	}

	if s.curEchoTransmitInterval != oldInterval {
		if oldInterval == 0 {
			// echo transmit is just being enabled, reset the connection and detection timer
			s.outEchoConn.Reset()
			s.updateEchoDetectionTime()
			s.resetEchoDetectionTimer()

			// When the Echo function is active, a system SHOULD set
			// bfd.RequiredMinRxInterval to a value of not less than one second
			// (1,000,000 microseconds).
			if s.local.requiredMinRxInterval < slowRequiredMinRxInterval {
				// RequiredMinRxInterval is increased - non need to wait for Poll no terminate
				s.local.requiredMinRxInterval = slowRequiredMinRxInterval
				s.local.inPollSequence = true
			}
		}
		if s.curEchoTransmitInterval == 0 {
			// echo transmit is just being disabled
			if s.local.requiredMinRxInterval > s.local.configuredRequiredMinRxInterval {
				// need to lower RequiredMinRxInterval from slowRequiredMinRxInterval

				// If bfd.RequiredMinRxInterval is reduced and bfd.SessionState is Up,
				//   the previous value of bfd.RequiredMinRxInterval MUST be used when
				//   calculating the Detection Time for the remote system until the Poll
				//   Sequence described above has terminated
				if s.local.sessionState == types.BFDStateUp {
					s.local.requiredMinRxIntervalApplied = false // lower after poll sequence terminates
				} else {
					s.local.requiredMinRxInterval = s.local.configuredRequiredMinRxInterval // lower immediately
				}
				s.local.inPollSequence = true
			}
		}
		s.setEchoTransmitTimer()
	}
}

func (s *bfdSession) setTransmitTimer() {
	// RFC 5880  6.8.7.  Transmitting BFD Control Packets
	// The periodic transmission of BFD Control packets MUST be jittered on
	// a per-packet basis by up to 25%, that is, the interval MUST be
	// reduced by a random value of 0 to 25%, in order to avoid self-
	// synchronization with other systems on the same subnetwork.  Thus, the
	// average interval between packets will be roughly 12.5% less than that
	// negotiated.

	quarterInterval := s.curTransmitInterval / 4
	// 75% + 0-25%
	nextInterval := (quarterInterval * 3) + time.Duration(rand.Int64N(int64(quarterInterval)))

	if s.local.detectMultiplier == 1 {
		// If bfd.DetectMult is equal to 1, the interval between transmitted BFD
		// Control packets MUST be no more than 90% of the negotiated
		// transmission interval, and MUST be no less than 75% of the negotiated
		// transmission interval.  This is to ensure that, on the remote system,
		// the calculated Detection Time does not pass prior to the receipt of
		// the next BFD Control packet.

		thenthInterval := s.curTransmitInterval / 10
		// 75% + 0-15%
		nextInterval = (quarterInterval * 3) + time.Duration(rand.Int64N(int64(quarterInterval-thenthInterval)))
	}

	s.transmitTimer = time.NewTimer(nextInterval)
}

func (s *bfdSession) setEchoTransmitTimer() {
	if s.curEchoTransmitInterval == 0 {
		// stop the timer if echo transmit is disabled
		s.echoTransmitTimer.Stop()
		return
	}

	// RFC 5880  6.8.9.  Transmission of BFD Echo Packets
	//   A 25% jitter MAY be applied to the rate of transmission, such that
	//   the actual interval MAY be between 75% and 100% of the advertised value.

	quarterInterval := s.curEchoTransmitInterval / 4
	// 75% + 0-25%
	nextInterval := (quarterInterval * 3) + time.Duration(rand.Int64N(int64(quarterInterval)))

	s.echoTransmitTimer = time.NewTimer(nextInterval)
}

func (s *bfdSession) updateDetectionTime(pkt *ControlPacket) {
	// RFC 5880 6.8.4.
	// In Asynchronous mode, the Detection Time calculated in the local
	// system is equal to the value of Detect Mult received from the remote
	// system, multiplied by the agreed transmit interval of the remote
	// system (the greater of bfd.RequiredMinRxInterval and the last
	// received Desired Min TX Interval).  The Detect Mult value is (roughly
	// speaking, due to jitter) the number of packets that have to be missed
	// in a row to declare the session to be down.
	remoteTransmitInterval := s.local.requiredMinRxInterval
	if uint32(pkt.DesiredMinTxInterval) > remoteTransmitInterval {
		remoteTransmitInterval = uint32(pkt.DesiredMinTxInterval)
	}

	s.curDetectionTime = time.Duration(uint32(pkt.DetectMultiplier)*remoteTransmitInterval) * time.Microsecond
}

func (s *bfdSession) updateEchoDetectionTime() {
	// RFC 5880 6.8.5.
	//   The means by which the Echo function failures are detected is outside
	//   of the scope of this specification.  Any means that will detect a
	//   communication failure are acceptable.

	// We use the actual transmit interval * local detect multiplier as the detection time

	s.curEchoDetectionTime = s.curEchoTransmitInterval * time.Duration(s.local.detectMultiplier)
}

func (s *bfdSession) resetDetectionTimer() {
	if !s.curDetectionTimer.Reset(s.curDetectionTime) {
		s.curDetectionTimer = time.NewTimer(s.curDetectionTime)
	}
}

func (s *bfdSession) resetEchoDetectionTimer() {
	if s.curEchoDetectionTime == 0 {
		return // do not reset if already disabled
	}
	if !s.curEchoDetectionTimer.Reset(s.curEchoDetectionTime) {
		s.curEchoDetectionTimer = time.NewTimer(s.curEchoDetectionTime)
	}
}

func (s *bfdSession) sendFinalPacket() error {
	// If a BFD Control packet is received with the Poll (P) bit set to 1,
	// the receiving system MUST transmit a BFD Control packet with the Poll
	// (P) bit clear and the Final (F) bit set as soon as practicable,
	// without respect to the transmission timer or any other transmission
	// limitations, without respect to the session state, and without
	// respect to whether Demand mode is active on either system.

	newPkt := s.createControlPacket(true)

	err := s.outConn.Write(newPkt)
	if err != nil {
		// the peer may be already down, just log this
		s.logger.WithError(err).Debug("Error by writing to BFD connection")
	}

	return nil
}

func (s *bfdSession) sendStateUpdatePacket() error {
	// A BFD Control packet SHOULD be transmitted during the interval
	// between periodic Control packet transmissions when the contents of
	// that packet would differ from that in the previously transmitted
	// packet (other than the Poll and Final bits) in order to more rapidly
	// communicate a change in state.

	newPkt := s.createControlPacket(false)

	err := s.outConn.Write(newPkt)
	if err != nil {
		// the peer may be already down, just log this
		s.logger.WithError(err).Debug("Error by writing to BFD connection")
	}

	return nil
}

func (s *bfdSession) createControlPacket(final bool) *ControlPacket {
	newPkt := &ControlPacket{BFD: &layers.BFD{}}

	// RFC 5880, section 6.8.7.  Transmitting BFD Control Packets
	// The contents of transmitted BFD Control packets MUST be set as follows:

	// Set Version to the current version number (1).
	newPkt.Version = 1

	// Set Diag to bfd.LocalDiag.
	newPkt.Diagnostic = layers.BFDDiagnostic(s.local.diagnostic)

	// Set State to the value indicated by bfd.SessionState.
	newPkt.State = layers.BFDState(s.local.sessionState)

	// Set Poll to 1 if the local system is sending a Poll Sequence, or 0 if
	// not.
	// BFD Control packet MUST NOT have both the Poll (P) and Final (F) bits set.
	newPkt.Poll = s.local.inPollSequence && !final

	// Set Final to 1 if the local system is responding to a Control packet
	// received with the Poll (P) bit set, or 0 if not.
	newPkt.Final = final

	// Set Control Plane Independent to 1 if the local system's BFD implementation is independent
	// of the control plane (it can continue to function through a
	// 	disruption of the control plane).
	newPkt.ControlPlaneIndependent = false

	// Set Authentication Present to 1 if authentication is in use on this session (bfd.AuthType
	// is nonzero), or 0 if not.
	newPkt.AuthPresent = false

	// Set Demand to bfd.DemandMode if bfd.SessionState is Up and
	// bfd.remoteSessionState is Up.  Otherwise, it is set to 0.
	newPkt.Demand = false

	// Set Multipoint to 0.
	newPkt.Multipoint = false

	// Set Detect Mult to bfd.DetectMult.
	newPkt.DetectMultiplier = layers.BFDDetectMultiplier(s.local.detectMultiplier)

	// Set My Discriminator to bfd.localDiscr.
	newPkt.MyDiscriminator = layers.BFDDiscriminator(s.local.discriminator)

	// Set Your Discriminator to bfd.RemoteDiscr.
	newPkt.YourDiscriminator = layers.BFDDiscriminator(s.remote.discriminator)

	// Set Desired Min TX Interval to bfd.DesiredMinTxInterval.
	newPkt.DesiredMinTxInterval = layers.BFDTimeInterval(s.local.desiredMinTxInterval)
	if newPkt.Poll && !s.local.desiredMinTxIntervalApplied {
		// if the configured value has not been applied yet, we advertise the configured value,
		// it will be applied when the Poll sequence terminates
		newPkt.DesiredMinTxInterval = layers.BFDTimeInterval(s.local.configuredDesiredMinTxInterval)
	}

	// Set Required Min RX Interval to bfd.RequiredMinRxInterval.
	newPkt.RequiredMinRxInterval = layers.BFDTimeInterval(s.local.requiredMinRxInterval)
	if newPkt.Poll && !s.local.requiredMinRxIntervalApplied {
		// if the configured value has not been applied yet, we advertise the configured value,
		// it will be applied when the Poll sequence terminates
		newPkt.RequiredMinRxInterval = layers.BFDTimeInterval(s.local.configuredRequiredMinRxInterval)
	}

	// Set Required Min Echo RX Interval to the minimum required Echo packet receive interval for this
	// session. If this field is set to zero, the local system is
	// unwilling or unable to loop back BFD Echo packets to the remote
	// system, and the remote system will not send Echo packets.
	newPkt.RequiredMinEchoRxInterval = layers.BFDTimeInterval(s.local.requiredMinEchoRxInterval)

	return newPkt
}

func (s *bfdSession) notifyStatusChange() {
	update := types.BFDPeerStatus{
		PeerAddress:     s.peerAddress,
		Interface:       s.networkInterface,
		LastStateChange: s.lastStateChange,
		Local: types.BFDSessionStatus{
			State:                s.local.sessionState,
			Discriminator:        s.local.discriminator,
			Diagnostic:           s.local.diagnostic,
			DetectMultiplier:     s.local.detectMultiplier,
			ReceiveInterval:      time.Duration(s.local.requiredMinRxInterval) * time.Microsecond,
			TransmitInterval:     time.Duration(s.local.desiredMinTxInterval) * time.Microsecond,
			EchoReceiveInterval:  time.Duration(s.local.requiredMinEchoRxInterval) * time.Microsecond,
			EchoTransmitInterval: time.Duration(s.local.desiredMinEchoTxInterval) * time.Microsecond,
		},
		Remote: types.BFDSessionStatus{
			State:               s.remote.sessionState,
			Discriminator:       s.remote.discriminator,
			Diagnostic:          s.remote.diagnostic,
			DetectMultiplier:    s.remote.detectMultiplier,
			ReceiveInterval:     time.Duration(s.remote.requiredMinRxInterval) * time.Microsecond,
			TransmitInterval:    time.Duration(s.remote.desiredMinTxInterval) * time.Microsecond,
			EchoReceiveInterval: time.Duration(s.remote.requiredMinEchoRxInterval) * time.Microsecond,
		},
	}

	s.logger.WithField(types.SessionStateField, update.Local.State).Debug("Generating session status update event")

	// send the status update, but don't ever block if the event readers are too slow.
	// If that happens, warn and drop the oldest event.
	select {
	case s.statusCh <- update:
	default:
		<-s.statusCh // drop the oldest event
		s.statusCh <- update
		s.logger.Warn("BFD event channel full, oldest event dropped")
	}
}
