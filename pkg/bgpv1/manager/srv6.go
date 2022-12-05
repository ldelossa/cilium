// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"

	"github.com/cilium/cilium/pkg/bgpv1/types"
)

// AddVPNv4Path will advertise the VPNv4 advertisement information to any
// connected peers of this speaker.
func (sc *ServerWithConfig) AddVPNv4Path(ctx context.Context, advert types.VPNv4Advertisement) error {
	resp, err := sc.Server.AdvertiseVPNv4Path(ctx, types.VPNv4PathRequest{Advert: advert})
	if err != nil {
		return err
	}
	sc.SRv6L3VPNAnnouncements[advert.VRF.VRFID] = resp.Advert
	return nil
}

// WithdrawVPNv4Path will remove a previously advertised VPNv4 advertisement.
func (sc *ServerWithConfig) WithdrawVPNv4Path(ctx context.Context, advert types.VPNv4Advertisement) error {
	err := sc.Server.WithdrawVPNv4Path(ctx, types.VPNv4PathRequest{Advert: advert})

	delete(sc.SRv6L3VPNAnnouncements, advert.VRF.VRFID)
	return err
}

// GetSRv6L3VPNAnnouncement will retrieve a VPNv4Advertisement given a VRF ID.
// There is no lock over the list of VPNv4Advertisements thus this method is not
// concurrency safe.
func (sc *ServerWithConfig) GetSRv6L3VPNAnnouncement(vrfID uint32) *types.VPNv4Advertisement {
	advert, ok := sc.SRv6L3VPNAnnouncements[vrfID]
	if !ok {
		return nil
	}
	return &advert
}
