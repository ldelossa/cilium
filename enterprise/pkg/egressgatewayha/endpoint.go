// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgatewayha

import (
	"fmt"
	"net/netip"

	"k8s.io/apimachinery/pkg/types"

	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
)

// endpointMetadata stores relevant metadata associated with a endpoint that's updated during endpoint
// add/update events
type endpointMetadata struct {
	// Endpoint labels
	labels map[string]string
	// Endpoint ID
	id endpointID
	// ips are endpoint's unique IPs
	ips []netip.Addr
	// nodeIP is the internal IP of the node where the endpoint's pod is running
	nodeIP netip.Addr
}

// endpointID is based on endpoint's UID
type endpointID = types.UID

func getEndpointMetadata(endpoint *k8sTypes.CiliumEndpoint, identityLabels labels.Labels) (*endpointMetadata, error) {
	var addrs []netip.Addr

	if endpoint.UID == "" {
		// this can happen when CiliumEndpointSlices are in use - which is not supported in the EGW yet
		return nil, fmt.Errorf("endpoint has empty UID")
	}

	if endpoint.Networking == nil {
		return nil, fmt.Errorf("endpoint has no networking metadata")
	}

	if len(endpoint.Networking.Addressing) == 0 {
		return nil, fmt.Errorf("failed to get valid endpoint IPs")
	}

	for _, pair := range endpoint.Networking.Addressing {
		if pair.IPV4 != "" {
			addr, err := netip.ParseAddr(pair.IPV4)
			if err != nil || !addr.Is4() {
				continue
			}
			addrs = append(addrs, addr)
		}
	}

	nodeIP, err := netip.ParseAddr(endpoint.Networking.NodeIP)
	if err != nil {
		return nil, fmt.Errorf("cannot parse endpoint's node IP")
	}

	data := &endpointMetadata{
		labels: identityLabels.K8sStringMap(),
		id:     endpoint.UID,
		ips:    addrs,
		nodeIP: nodeIP,
	}

	return data, nil
}
