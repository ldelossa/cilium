// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func GetPeerAddressFromConfig(conf *v1alpha1.IsovalentBGPNodeInstance, peerName string) (netip.Addr, error) {
	if conf == nil {
		return netip.Addr{}, fmt.Errorf("passed instance is nil")
	}

	for _, peer := range conf.Peers {
		if peer.Name == peerName {
			if peer.PeerAddress != nil {
				return netip.ParseAddr(*peer.PeerAddress)
			} else {
				return netip.Addr{}, fmt.Errorf("peer %s does not have a PeerAddress", peerName)
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("peer %s not found in instance %s", peerName, conf.Name)
}
