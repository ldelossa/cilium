package gobgp

import (
	"context"
	"fmt"
	"net"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	gobgpb "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/srv6"
)

// MapSRv6EgressPolicy will map any discovered VPNv4 routes which match passed in
// VRF's route reflectors into srv6.EgressPolicy(s) and return these to the caller.
func (g *GoBGPServer) MapSRv6EgressPolicy(ctx context.Context, vrfs []*srv6.VRF) ([]*srv6.EgressPolicy, error) {
	l := g.logger.WithFields(
		logrus.Fields{
			"component": "gobgp.MapSRv6EgressPolicy",
		},
	)
	l.Info("Mapping SRv6 VRFs to SRv6 egress policies.")

	var (
		VPNv4Paths []*gobgp.Path
		policies   []*srv6.EgressPolicy
	)

	lpr := &gobgp.ListPathRequest{
		TableType: gobgp.TableType_GLOBAL,
		Family:    GoBGPVPNv4Family,
	}

	err := g.server.ListPath(ctx, lpr, func(d *gobgp.Destination) {
		for _, p := range d.Paths {
			if p.Best {
				VPNv4Paths = append(VPNv4Paths, d.Paths...)
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list VPNv4 paths for virtual router with local ASN %d: %w", g.asn, err)
	}

	l.WithField("count", len(VPNv4Paths)).Info("Discovered advertised VPNv4 routes.")

	for _, p := range VPNv4Paths {
		out, err := g.mapVPNv4ToEgressPolicy(ctx, p, vrfs)
		if err != nil {
			return nil, fmt.Errorf("failed to map VPNv4 paths to egress policies: %w", err)
		}
		policies = append(policies, out...)
	}

	l.WithField("count", len(policies)).Info("Mapped VPNv4 paths to egress policies")
	return policies, nil
}

func (g *GoBGPServer) mapVPNv4ToEgressPolicy(ctx context.Context, vpnv4 *gobgp.Path, vrfs []*srv6.VRF) ([]*srv6.EgressPolicy, error) {
	l := g.logger.WithFields(
		logrus.Fields{
			"component": "gobgp.RouterManager.MapVPNv4ToEgressPolicy",
		},
	)

	var (
		// require extended communities for route target.
		extCommunities *gobgpb.PathAttributeExtendedCommunities
		// require MP BGP Reach NLRIs to mape prefixes to destination CIDRs
		mpReach *gobgpb.PathAttributeMpReachNLRI
		// require BGP prefix-sid attribute to extract destination CIDR
		prefixSID *gobgpb.PathAttributePrefixSID
		// extracted prefixes from MP BGP VPNv4 NLRI
		prefixes []*net.IPNet
		// extracted route target from BGP extended community.
		RT string
		// extracted SRv6 SID from BGP Prefix SID attribute.
		destinationSID [16]byte
	)

	attrs, err := apiutil.UnmarshalPathAttributes(vpnv4.Pattrs)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal path attributes: %w", err)
	}

	for _, attr := range attrs {
		switch v := attr.(type) {
		case *gobgpb.PathAttributeExtendedCommunities:
			extCommunities = v
		case *gobgpb.PathAttributeMpReachNLRI:
			mpReach = v
		case *gobgpb.PathAttributePrefixSID:
			prefixSID = v
		}
	}

	// if we do not have our required path attributes we cannot map this route.
	// this is not an error.
	if extCommunities == nil {
		l.Debug("Did not find extended communities")
		return nil, nil
	}
	if mpReach == nil {
		l.Debug("Did not find MB NLRIs")
		return nil, nil
	}
	if prefixSID == nil {
		l.Debug("Did not find BGP Prefix SID attribute")
		return nil, nil
	}

	l.Debug("Looking for route target extended community")
	for _, val := range extCommunities.Value {
		switch v := val.(type) {
		case *gobgpb.FourOctetAsSpecificExtended:
			if v.SubType == gobgpb.EC_SUBTYPE_ROUTE_TARGET {
				l.WithField("routeTarget", RT).Debug("Discovered route target in Two-Octect AS Specific Ext Community")
				RT = fmt.Sprintf("%d:%d", v.AS, v.LocalAdmin)
			}
		case *gobgpb.TwoOctetAsSpecificExtended:
			if v.SubType == gobgpb.EC_SUBTYPE_ROUTE_TARGET {
				RT = fmt.Sprintf("%d:%d", v.AS, v.LocalAdmin)
				l.WithField("routeTarget", RT).Debug("Discovered route target in Two-Octect AS Specific Ext Community")
			}
		}
	}
	// we did not find a route target.
	if RT == "" {
		l.Debug("Did not find a route target")
		return nil, nil
	}

	// extract our destination CIDRs from MP BGP NLRIs.
	// these will be VPNv4 encoded IPv4 prefixes.
	if (mpReach.SAFI != gobgpb.SAFI_MPLS_VPN) || (mpReach.AFI != gobgpb.AFI_IP) {
		// this really shouldn't happen since we do a list for paths of this
		// S/AFI type, but may as well be defensive.
		l.Debug("MB BGP NLRI was not correct S/AFI")
		return nil, nil
	}

	var labels []uint32
	for _, prefix := range mpReach.Value {
		switch v := prefix.(type) {
		case *gobgpb.LabeledVPNIPAddrPrefix:
			labels = v.Labels.Labels
			mask := net.CIDRMask(int(v.IPPrefixLen()), 32)
			prefixes = append(prefixes, &net.IPNet{
				IP:   v.Prefix,
				Mask: mask,
			})
		}
	}
	if len(prefixes) == 0 {
		l.Debug("No prefixes provided in VPNv4 path")
		return nil, nil
	}

	// first extract SRv6 SID Information Sub-TLV
	// (RFC draft-ietf-bess-srv6-services 3.1) to obtain destination SID.
	//
	// per RFC:
	// When multiple SRv6 SID Information Sub-TLVs are present, the ingress
	// PE SHOULD use the SRv6 SID from the first instance of the Sub-TLV.
	// An implementation MAY provide a local policy to override this
	// selection.
	//
	// we will only utilize the first SID Info Sub-TLV
	unpackL3Serv := func(l3serv *gobgpb.SRv6L3ServiceAttribute) *gobgpb.SRv6InformationSubTLV {
		for _, subtlv := range l3serv.SubTLVs {
			switch v := subtlv.(type) {
			case *gobgpb.SRv6InformationSubTLV:
				return v
			}
		}
		return nil
	}

	// pull out the first occurrence as well, there doesn't seem to be good reason
	// to parse out multiple.
	unpackInfoSubTLV := func(subtlv *gobgpb.SRv6InformationSubTLV) *gobgpb.SRv6SIDStructureSubSubTLV {
		var subStructTLV *gobgpb.SRv6SIDStructureSubSubTLV
		for _, subsubtlv := range subtlv.SubSubTLVs {
			switch v := subsubtlv.(type) {
			case *gobgpb.SRv6SIDStructureSubSubTLV:
				subStructTLV = v
			}
		}
		return subStructTLV
	}

	for _, tlv := range prefixSID.TLVs {
		switch v := tlv.(type) {
		case *gobgpb.SRv6L3ServiceAttribute:
			infoSubTLV := unpackL3Serv(v)
			if infoSubTLV == nil {
				continue
			}
			subStructTLV := unpackInfoSubTLV(infoSubTLV)
			if subStructTLV == nil {
				continue
			}
			// per RFC (draft-ietf-bess-srv6-services) if Transposition length
			// is not zero the SID was transposed with an MPLS label.
			if subStructTLV.TranspositionLength != 0 {
				l.Debug("Must transpose MPLS label to obtain SID.")

				if len(labels) == 0 {
					return nil, fmt.Errorf("VPNv4 path expects transposition of SID but no MPLS labels discovered")
				}

				transposed, err := g.TransposeSID(labels[0], infoSubTLV, subStructTLV)
				if err != nil {
					return nil, fmt.Errorf("failed to transpose SID: %w", err)
				}
				for i, b := range transposed {
					destinationSID[i] = b
				}
			} else {
				for i, b := range infoSubTLV.SID {
					destinationSID[i] = b
				}
			}
		}
	}

	// map into EgressPolicies
	policies := []*srv6.EgressPolicy{}
	for _, vrf := range vrfs {
		if vrf == nil {
			continue
		}
		if vrf.ImportRouteTarget == RT {
			l.Debugf("Matched vrf's route target %v with discovered route target %v", vrf.ImportRouteTarget, RT)
			policy := &srv6.EgressPolicy{
				VRFID:    vrf.VRFID,
				DstCIDRs: prefixes,
				SID:      destinationSID,
			}
			policies = append(policies, policy)
			l.WithField("policy", policy).Debug("Mapped VPNv4 route to policy.")
		}
	}

	return policies, nil
}

// TransposeSID will return a 128 bit array repsenting an SRv6 SID after transposing
// a defined number of bits from the provided MPLS label.
//
// Per RFC: https://datatracker.ietf.org/doc/html/draft-ietf-bess-srv6-services-15#section-4
// When the TranspositionLengh field in the SRv6SIDSubStructureSubSubTLV is greater then 0
// the SRv6 SID must be obtained by transposing a variable bit range from the MPLS label
// within the VPNv4 NLRI. The bit ranges are provided by fields within the SRv6SIDSubStructureSubSubTLV.
func (g *GoBGPServer) TransposeSID(label uint32, infoTLV *gobgpb.SRv6InformationSubTLV, structTLV *gobgpb.SRv6SIDStructureSubSubTLV) ([]byte, error) {
	l := g.logger.WithFields(
		logrus.Fields{
			"component": "gobgp.TransposeSID",
		},
	)

	// must shift label by twelve, not sure if this is something with frr or not.
	label = label << 12

	off := structTLV.TranspositionOffset // number of bits into the SID where transposition starts
	le := structTLV.TranspositionLength  // length in bits of transposition
	sid := infoTLV.SID

	l.WithFields(logrus.Fields{
		"label":       fmt.Sprintf("%x", label),
		"offset":      off,
		"length":      le,
		"originalSid": fmt.Sprintf("%x", sid),
		"startByte":   off / 8,
	}).Debug("Starting SID transposition")
	for le > 0 {
		var (
			// current byte index to tranpose
			byteI = off / 8
			// current bit index where bit transposition will occur
			bitI = off % 8
			// number of bits that will be copied from label into sid.
			n = (8 - bitI)
		)
		// get to a byte boundary, then eat full bytes until we can't.
		if le >= 8 {
			mask := ^byte(0) << n
			sid[byteI] = ((sid[byteI] & mask) | byte(label>>(32-n)))
			label <<= n
			off = off + n
			le = le - n
			l.WithFields(logrus.Fields{
				"label":          fmt.Sprintf("%x", label),
				"nextOffset":     off,
				"length":         le,
				"copiedN":        n,
				"byteI":          fmt.Sprintf("%x", byteI),
				"bitI":           fmt.Sprintf("%x", bitI),
				"mask":           fmt.Sprintf("%x", mask),
				"transposedByte": fmt.Sprintf("%x", sid[byteI]),
			}).Debug("Transposed bits")
			continue
		}
		// deal with a final bit difference.
		mask := ^byte(0) >> le
		sid[byteI] = ((sid[byteI] & mask) | byte(label>>(32-le))) << (8 - le)
		l.WithFields(logrus.Fields{
			"label":          fmt.Sprintf("%x", label),
			"nextOffset":     off,
			"length":         le,
			"copiedN":        n,
			"byteI":          fmt.Sprintf("%x", byteI),
			"bitI":           fmt.Sprintf("%x", bitI),
			"mask":           fmt.Sprintf("%x", mask),
			"transposedByte": fmt.Sprintf("%x", sid[byteI]),
		}).Debug("Transposed bits")
	}
	l.Debugf("Transposed SID %x", sid)
	return sid, nil
}
