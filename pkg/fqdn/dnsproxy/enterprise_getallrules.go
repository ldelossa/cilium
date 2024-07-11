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

	fqdnpb "github.com/cilium/cilium/enterprise/fqdn-proxy/api/v1/dnsproxy"
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

// DumpRules gets all rules currently known by the proxy.
// Returns all rules indexed by subject endpoint ID and port+proto
func (p *DNSProxy) DumpRules() []*fqdnpb.FQDNRules {
	p.RLock()
	defer p.RUnlock()

	result := make([]*fqdnpb.FQDNRules, 0, len(p.allowed))

	for endpointID, portRules := range p.allowed {
		for portProto, allowed := range portRules {
			// Allowed is a map of selector to regex

			// Filter out protocols that cannot apply to DNS.
			if proto := portProto.Protocol(); proto != uint8(u8proto.UDP) && proto != uint8(u8proto.TCP) {
				continue
			}

			// Re-construct the desired proxy state from the compiled allow list.
			//
			// This logic should match enterprise/fqdnha/remoteproxy/proxy.go, where the L7DataMap
			// is convernted to a fqdnpb.FQDNRules.
			l := len(allowed)
			r := &fqdnpb.FQDNRules{
				EndpointID: endpointID,
				DestPort:   uint32(portProto.Port()),
				DestProto:  uint32(portProto.Protocol()),
				Rules: &fqdnpb.L7Rules{
					SelectorRegexMapping:      make(map[string]string, l),
					SelectorIdentitiesMapping: make(map[string]*fqdnpb.IdentityList, l),
				},
			}

			// Convert cachedSelector -> regex map to the realized value suitable for
			// map[selector] -> regex
			// map[selector] -> []ids (but it's a []u32 for some reason)
			for selector, dnsRE := range allowed {
				r.Rules.SelectorRegexMapping[selector.String()] = dnsRE.String()

				// []u64 -> []u32 :-)
				selections := selector.GetSelections()
				idList := make([]uint32, 0, len(selections))
				for _, nid := range selections {
					idList = append(idList, uint32(nid))
				}
				r.Rules.SelectorIdentitiesMapping[selector.String()] = &fqdnpb.IdentityList{List: idList}
			}

			result = append(result, r)
		}
	}

	return result
}
