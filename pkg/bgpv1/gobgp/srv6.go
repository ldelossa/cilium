package gobgp

import (
	"fmt"

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
