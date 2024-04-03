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

import "github.com/google/gopacket/layers"

// ControlPacket represent a single BFD control packet.
type ControlPacket struct {
	*layers.BFD
}

func (pkt *ControlPacket) isValid() bool {
	// RFC 5880 6.8.6.  Reception of BFD Control Packets

	//  If the version number is not correct (1), the packet MUST be
	// discarded.
	if pkt.Version != 1 {
		return false
	}

	// If the Detect Mult field is zero, the packet MUST be discarded.
	if pkt.DetectMultiplier == 0 {
		return false
	}

	// If the Multipoint (M) bit is nonzero, the packet MUST be discarded.
	if pkt.Multipoint {
		return false
	}

	// If the My Discriminator field is zero, the packet MUST be
	// discarded.
	if pkt.MyDiscriminator == 0 {
		return false
	}

	if pkt.YourDiscriminator == 0 && pkt.State != layers.BFDStateDown && pkt.State != layers.BFDStateAdminDown {
		// If the Your Discriminator field is zero and the State field is not
		// Down or AdminDown, the packet MUST be discarded.
		return false
	}

	// If the A bit is set and no authentication is in use (bfd.AuthType
	// is zero), the packet MUST be discarded.
	if pkt.AuthPresent && (pkt.AuthHeader == nil || pkt.AuthHeader.AuthType == layers.BFDAuthTypeNone) {
		return false
	}

	// If the A bit is clear and authentication is in use (bfd.AuthType
	// is nonzero), the packet MUST be discarded.
	if !pkt.AuthPresent && pkt.AuthHeader != nil {
		return false
	}

	return true
}
