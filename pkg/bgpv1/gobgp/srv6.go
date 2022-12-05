package gobgp

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/srv6"
	gobgp "github.com/osrg/gobgp/v3/api"
	gobgputil "github.com/osrg/gobgp/v3/pkg/apiutil"
	gobgpb "github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/sirupsen/logrus"
)

// TransposeSID will return a 128 bit array repsenting an SRv6 SID after transposing
// a defined number of bits from the provided MPLS label.
//
// Per RFC: https://datatracker.ietf.org/doc/html/draft-ietf-bess-srv6-services-15#section-4
// When the TranspositionLengh field in the SRv6SIDSubStructureSubSubTLV is greater then 0
// the SRv6 SID must be obtained by transposing a variable bit range from the MPLS label
// within the VPNv4 NLRI. The bit ranges are provided by fields within the SRv6SIDSubStructureSubSubTLV.
func TransposeSID(label uint32, infoTLV *gobgpb.SRv6InformationSubTLV, structTLV *gobgpb.SRv6SIDStructureSubSubTLV) ([]byte, error) {
	l := log.WithFields(
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

func MapVRFToVPNv4Route(podCIDRs []*net.IPNet, vrf *srv6.VRF) (*gobgp.Path, error) {
	if vrf.ExportRouteTarget == "" {
		return nil, fmt.Errorf("cannot map VRF without an ExportRouteTarget")
	}

	var (
		AS         uint16
		LocalAdmin uint32
	)

	// format ExportRouteTarget for binary marshalling.
	RT := strings.Split(vrf.ExportRouteTarget, ":")
	tmp, err := strconv.ParseUint(RT[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("could not parse ExportRouteTarget AS field: %w", err)
	}
	AS = uint16(tmp)

	tmp, err = strconv.ParseUint(RT[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("could not parse ExportRouteTarget LocalAdmin field: %w", err)
	}
	LocalAdmin = uint32(tmp)

	// Pack ExportRouteTarget into extCommunities attribute
	extCommsAttr := &gobgpb.PathAttributeExtendedCommunities{
		Value: []gobgpb.ExtendedCommunityInterface{
			&gobgpb.TwoOctetAsSpecificExtended{
				SubType:      gobgpb.EC_SUBTYPE_ROUTE_TARGET,
				AS:           AS,
				LocalAdmin:   LocalAdmin,
				IsTransitive: true,
			},
		},
	}

	medAttr := gobgpb.NewPathAttributeMultiExitDisc(0)

	// The SRv6 SID and endpoint behavior is encoded as a set of nested
	// TLVs.
	//
	// The SRv6 TLVs are encoded as a Prefix SID BGP Attribute of type
	// See: https://www.rfc-editor.org/rfc/rfc9252.html#section-4

	// Pack SRv6SIDStructureSubSubTLV details into a SRv6InformationSubTLV
	SIDInfoTLV := &gobgpb.SRv6InformationSubTLV{
		SID:              vrf.AllocatedSID.To16(),
		EndpointBehavior: uint16(gobgpb.END_DT4),
		SubSubTLVs: []gobgpb.PrefixSIDTLVInterface{
			&gobgpb.SRv6SIDStructureSubSubTLV{
				LocalBlockLength: 128,
			},
		},
	}

	// Pack SRv6InformationSubTLV into a SRv6L3ServiceAttribute
	L3ServTLV := &gobgpb.SRv6L3ServiceAttribute{
		SubTLVs: []gobgpb.PrefixSIDTLVInterface{
			SIDInfoTLV,
		},
	}

	// Encode SRv6L3ServiceAttribute as a PathAttributePrefixSID
	prefixSIDAttr := &gobgpb.PathAttributePrefixSID{
		TLVs: []gobgpb.PrefixSIDTLVInterface{
			L3ServTLV,
		},
	}

	// Pack podCIDRs into VPNv4 MP-NLRI
	labeledPrefixes := []gobgpb.AddrPrefixInterface{}
	for _, podCIDR := range podCIDRs {
		maskLen, _ := podCIDR.Mask.Size()
		rd := &gobgpb.RouteDistinguisherTwoOctetAS{
			Admin:    AS,
			Assigned: LocalAdmin,
		}
		vpnv4 := gobgpb.NewLabeledVPNIPAddrPrefix(uint8(maskLen), podCIDR.IP.String(), *gobgpb.NewMPLSLabelStack(4096), rd)
		labeledPrefixes = append(labeledPrefixes, vpnv4)
	}
	MpReachAttr := &gobgpb.PathAttributeMpReachNLRI{
		AFI:     gobgpb.AFI_IP,
		SAFI:    gobgpb.SAFI_MPLS_VPN,
		Nexthop: net.ParseIP("0.0.0.0"),
		Value:   labeledPrefixes,
	}

	// Mandatory Attributes, ASPATH will be set by GoBGP directly.
	origin := gobgpb.NewPathAttributeOrigin(gobgpb.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE)
	nextHop := gobgpb.NewPathAttributeNextHop("0.0.0.0")

	attrs, err := gobgputil.MarshalPathAttributes([]gobgpb.PathAttributeInterface{
		origin,
		medAttr,
		nextHop,
		extCommsAttr,
		prefixSIDAttr,
		MpReachAttr,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal BGP path attributes: %w", err)
	}

	// Even tho the resuling UPDATE message does not include a top level NLRI
	// structure, GoBGP wants to check that the NLRI and Path's Route Family
	// match, presumably for internal bookkeeping.
	nlri, err := gobgputil.MarshalNLRI(labeledPrefixes[0])
	if err != nil {
		return nil, fmt.Errorf("failed to marshal empty NLRI: %w", err)
	}

	p := &gobgp.Path{
		Pattrs: attrs,
		Family: GoBGPVPNv4Family,
		Nlri:   nlri,
	}

	return p, nil
}
