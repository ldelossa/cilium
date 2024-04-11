//nolint:goheader
//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package dnsproxy

import (
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/u8proto"
)

func (p *DNSProxy) GetAllRules() (map[uint64]restore.DNSRules, error) {
	result := make(map[uint64]restore.DNSRules, len(p.allowed))

	for epID := range p.allowed {
		rules, err := p.GetRules(uint16(epID))
		if err != nil {
			return nil, err
		}
		// Insert the V1 Rules for older versions of DNSProxy.
		// TODO: This can be removed when 1.15 is deprecated.
		for portProto, ipRules := range rules {
			if portProto.IsPortV2() {
				proto := portProto.Protocol()
				// Only add protocols that support DNS.
				if proto == uint8(u8proto.TCP) || proto == uint8(u8proto.UDP) {
					rules[portProto.ToV1()] = ipRules
				}
			}
		}
		result[epID] = rules
	}

	return result, nil
}
