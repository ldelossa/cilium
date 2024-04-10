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
	"fmt"
	"net/netip"
	"time"

	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

type BFDPeerKey struct {
	PeerAddress      netip.Addr
	NetworkInterface string
}

func NewBFDPeersTable() (statedb.RWTable[*BFDPeerStatus], error) {
	return statedb.NewTable[*BFDPeerStatus](
		"bfd-peers",
		BFDPeerAddressInterfaceIndex,
		BFDPeerAddressIndex,
	)
}

var (
	BFDPeerAddressInterfaceIndex = statedb.Index[*BFDPeerStatus, BFDPeerKey]{
		Name: "PeerAddressInterface",
		FromObject: func(b *BFDPeerStatus) index.KeySet {
			return index.NewKeySet(BFDPeerKey{PeerAddress: b.PeerAddress, NetworkInterface: b.Interface}.Key())
		},
		FromKey: BFDPeerKey.Key,
		Unique:  true,
	}
	BFDPeerAddressIndex = statedb.Index[*BFDPeerStatus, netip.Addr]{
		Name: "PeerAddress",
		FromObject: func(s *BFDPeerStatus) index.KeySet {
			return index.NewKeySet(index.NetIPAddr(s.PeerAddress))
		},
		FromKey: index.NetIPAddr,
		Unique:  false,
	}
)

func (p BFDPeerKey) Key() index.Key {
	key := append(index.NetIPAddr(p.PeerAddress), '+')
	key = append(key, index.String(p.NetworkInterface)...)
	return key
}

func (*BFDPeerStatus) TableHeader() []string {
	return []string{
		"PeerAddress",
		"Interface",
		"Discriminator",
		"RemDiscriminator",
		"State",
		"LastStateChange",
		"Multi",
		"RemMulti",
		"RxInterval",
		"RemRxInterval",
		"TxInterval",
		"RemTxInterval",
		"EchoRxInterval",
		"Diagnostic",
		"RemDiagnostic",
	}
}

func (s *BFDPeerStatus) TableRow() []string {
	return []string{
		s.PeerAddress.String(),
		s.Interface,
		fmt.Sprint(s.Local.Discriminator),
		fmt.Sprint(s.Remote.Discriminator),
		s.Local.State.String(),
		time.Since(s.LastStateChange).Round(time.Second).String(),
		fmt.Sprint(s.Local.DetectMultiplier),
		fmt.Sprint(s.Remote.DetectMultiplier),
		s.Local.ReceiveInterval.String(),
		s.Remote.ReceiveInterval.String(),
		s.Local.TransmitInterval.String(),
		s.Remote.TransmitInterval.String(),
		s.Local.EchoReceiveInterval.String(),
		s.Local.Diagnostic.String(),
		s.Remote.Diagnostic.String(),
	}
}
