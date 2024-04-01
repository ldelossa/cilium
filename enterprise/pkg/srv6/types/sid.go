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
)

// Locator represents a single Locator. It embeds the netip.Prefix, so it can
// be treated as an IP prefix.
type Locator struct {
	netip.Prefix
}

// NewLocator constructs Locator from IPv6 netip.prefix
func NewLocator(prefix netip.Prefix) (Locator, error) {
	if !prefix.Addr().Is6() {
		return Locator{}, fmt.Errorf("locator prefix must be IPv6")
	}
	if prefix.Bits()%8 != 0 {
		return Locator{}, fmt.Errorf("locator prefix length must be byte-aligned")
	}
	return Locator{
		Prefix: prefix,
	}, nil
}

// MustNewLocator is NewLocator but panics on error. Should be used only in tests.
func MustNewLocator(prefix netip.Prefix) Locator {
	l, err := NewLocator(prefix)
	if err != nil {
		panic(err)
	}
	return l
}

// SID represents a single SID. It embeds the netip.Addr, so it can be treated
// as an IP address.
type SID struct {
	netip.Addr
}

// NewSID constructs SID from IPv6 netip.Addr and SIDStructure
func NewSID(addr netip.Addr) (SID, error) {
	if !addr.Is6() {
		return SID{}, fmt.Errorf("SID must be IPv6")
	}
	return SID{
		Addr: addr,
	}, nil
}

// MustNewSID is NewSID but panics on error. Should be used only in tests.
func MustNewSID(addr netip.Addr) SID {
	sid, err := NewSID(addr)
	if err != nil {
		panic(err)
	}
	return sid
}

// NewSIDFromLFA constructs SID from locator, function and argument parts
func NewSIDFromLFA(l Locator, f []byte, a []byte) (SID, error) {
	// We don't have to check for byte alignment here as we already validate it on construction
	locLenBytes := l.Bits() / 8
	funcLenBytes := len(f)
	argLenBytes := len(a)

	if locLenBytes+funcLenBytes+argLenBytes > 16 {
		return SID{}, fmt.Errorf("total length exceeds IPv6 address length")
	}

	arr := l.Addr().As16()
	copy(arr[locLenBytes:locLenBytes+funcLenBytes], f)
	copy(arr[locLenBytes+funcLenBytes:locLenBytes+funcLenBytes+argLenBytes], a)

	return NewSID(netip.AddrFrom16(arr))
}

// MustNewSIDFromLFA is NewSIDFromLFA but panics on error. Should be used only in tests.
func MustNewSIDFromLFA(l Locator, f []byte, a []byte) SID {
	sid, err := NewSIDFromLFA(l, f, a)
	if err != nil {
		panic(err)
	}
	return sid
}

// LocatorBytes extracts locator part from SID and return it as a slice
func (s *SID) LocatorBytes(structure SIDStructure) []byte {
	arr := s.As16()
	return arr[:structure.LocatorLenBytes()]
}

// LocatorBlockBytes extracts locator block part from SID and return it as a slice
func (s *SID) LocatorBlockBytes(structure SIDStructure) []byte {
	arr := s.As16()
	return arr[:structure.LocatorBlockLenBytes()]
}

// LocatorNodeBytes extracts locator node part from SID and return it as a slice
func (s *SID) LocatorNodeBytes(structure SIDStructure) []byte {
	arr := s.As16()
	locBLenBytes := structure.LocatorBlockLenBytes()
	locNLenBytes := structure.LocatorNodeLenBytes()
	return arr[locBLenBytes : locBLenBytes+locNLenBytes]
}

// FunctionBytes extracts function part from SID and return it as a slice
func (s *SID) FunctionBytes(structure SIDStructure) []byte {
	arr := s.As16()
	locLenBytes := structure.LocatorLenBytes()
	funcLenBytes := structure.FunctionLenBytes()
	return arr[locLenBytes : locLenBytes+funcLenBytes]
}

// ArgumentBytes extracts argument part from SID and return it as a slice
func (s *SID) ArgumentBytes(structure SIDStructure) []byte {
	arr := s.As16()
	locLenBytes := structure.LocatorLenBytes()
	funcLenBytes := structure.FunctionLenBytes()
	argLenBytes := structure.ArgumentLenBytes()
	return arr[locLenBytes+funcLenBytes : locLenBytes+funcLenBytes+argLenBytes]
}

// RestBytes extracts non-SID part and return it as a slice
func (s *SID) RestBytes(structure SIDStructure) []byte {
	arr := s.As16()
	locLenBytes := structure.LocatorLenBytes()
	funcLenBytes := structure.FunctionLenBytes()
	argLenBytes := structure.ArgumentLenBytes()
	return arr[locLenBytes+funcLenBytes+argLenBytes:]
}

// Transpose transposes the given SID as defined in the RFC9252 Section 4 and
// returns MPLS label value and the SID that transposed bits are filled with
// zero.
func (s *SID) Transpose(offsetBits, lengthBits uint8) (uint32, []byte, error) {
	transposedSID := s.AsSlice()

	if offsetBits > 128 {
		return 0, nil, fmt.Errorf("offset (%d) is larger than 128", offsetBits)
	}

	if lengthBits > 20 {
		return 0, nil, fmt.Errorf("length (%d) is exceeding MPLS label length", lengthBits)
	}

	if int(offsetBits+lengthBits) > len(transposedSID)*8 {
		return 0, nil, fmt.Errorf("offset + length is exceeding SID length")
	}

	// MPLS label is 20bit, but we'll encode it to uint32 here.
	// Lower 20bits will be filled with label value.
	var label uint32

	//
	// This is a diagram that visually helps understanding the algorithm.
	//       startI                                             endI
	// |      [7]        |      [8]        |        [9]      |  [10]
	// | 0 1 0 1 0 1 0 1 | 1 1 1 1 1 1 1 1 | 1 0 1 0 1 0 1 0 | 1 1 1 1
	// --------------> |---------------------------------------|
	//  Offset(63)                Length (18)
	//
	startI := offsetBits / 8
	endI := (offsetBits + lengthBits) / 8
	for i := startI; i <= endI; i++ {
		mask := byte(0)
		if i == startI {
			// An initial byte may contain non-byte-aligned bits
			bitI := offsetBits % 8
			mask = ^byte(0) >> bitI
			label |= uint32(transposedSID[i] & mask)
		} else if i == endI {
			// An end byte may contain non-byte-aligned bits
			bitI := (offsetBits + lengthBits) % 8
			mask = ^(^byte(0) >> bitI)
			label <<= bitI
			label |= uint32(transposedSID[i]&mask) >> (8 - bitI)
		} else {
			// For middle bytes, we can simply copy bytes
			mask = ^byte(0)
			label <<= 8
			label |= uint32(transposedSID[i] & mask)
		}
		// Put zeros to transposed bits
		transposedSID[i] &= ^mask
	}

	// Zero pad lower bits
	label <<= (20 - lengthBits)

	return label, transposedSID, nil
}

// This is private and must be accessed through SIDStructure interface
type SIDStructure struct {
	// Locator Block length as described in RFC8986.
	locatorBlockLenBits uint8

	// Locator Node length as described in RFC8986.
	locatorNodeLenBits uint8

	// Function length as described in RFC8986.
	functionLenBits uint8

	// Argument length as described in RFC8986.
	argumentLenBits uint8
}

// Creates new SIDStructure with validation. The validations will be performed
// from RFC and Cilium's perspective. The returned SIDStructure is guaranteed
// to be valid and immutable. Thus, no further validation required for using
// it.
func NewSIDStructure(lb uint8, ln uint8, f uint8, a uint8) (SIDStructure, error) {
	// Implementation-specific
	//
	// In RFC standard, it is valid to have non-byte-aligned SID structure.
	// However, here we intentionally make such SID structure invalid. This makes
	// SID allocation and datapath processing simpler. This is a practical limitation
	// used in IOS-XR as well.
	//
	// > The length of block [prefix] is defined in bits. From a hardware-friendliness
	// > perspective, it is expected to use sizes on byte boundaries (16, 24, 32, and so on).
	//
	// Ref: https://www.cisco.com/c/en/us/td/docs/iosxr/ncs5500/segment-routing/73x/b-segment-routing-cg-ncs5500-73x/m-configure-srv6-usid.html
	if lb%8 != 0 || ln%8 != 0 || f%8 != 0 || a%8 != 0 {
		return SIDStructure{}, fmt.Errorf("SID structure bits must be byte-aligned")
	}

	// RFC8986
	if lb+ln+f+a > 128 {
		return SIDStructure{}, fmt.Errorf("total number of bits exceeds 128")
	}

	return SIDStructure{
		locatorBlockLenBits: lb,
		locatorNodeLenBits:  ln,
		functionLenBits:     f,
		argumentLenBits:     a,
	}, nil
}

// MustNewSIDStructure is NewSIDStructure but panics on error. Should be used only in tests.
func MustNewSIDStructure(lb uint8, ln uint8, f uint8, a uint8) SIDStructure {
	ss, err := NewSIDStructure(lb, ln, f, a)
	if err != nil {
		panic(err)
	}
	return ss
}

// String return human-readable string representation of this SIDStructure
func (ss SIDStructure) String() string {
	return fmt.Sprintf("[%d, %d, %d, %d]",
		ss.locatorBlockLenBits, ss.locatorNodeLenBits,
		ss.functionLenBits, ss.argumentLenBits,
	)
}

func (ss SIDStructure) LocatorLenBits() uint8 {
	return ss.locatorBlockLenBits + ss.locatorNodeLenBits
}

func (ss SIDStructure) LocatorLenBytes() uint8 {
	return (ss.locatorBlockLenBits + ss.locatorNodeLenBits) / 8
}

func (ss SIDStructure) LocatorBlockLenBits() uint8 {
	return ss.locatorBlockLenBits
}

func (ss SIDStructure) LocatorBlockLenBytes() uint8 {
	return ss.locatorBlockLenBits / 8
}

func (ss SIDStructure) LocatorNodeLenBits() uint8 {
	return ss.locatorNodeLenBits
}

func (ss SIDStructure) LocatorNodeLenBytes() uint8 {
	return ss.locatorNodeLenBits / 8
}

func (ss SIDStructure) FunctionLenBits() uint8 {
	return ss.functionLenBits
}

func (ss SIDStructure) FunctionLenBytes() uint8 {
	return ss.functionLenBits / 8
}

func (ss SIDStructure) ArgumentLenBits() uint8 {
	return ss.argumentLenBits
}

func (ss SIDStructure) ArgumentLenBytes() uint8 {
	return ss.argumentLenBits / 8
}

type Behavior uint16

const (
	BehaviorUnknown Behavior = 0
	BehaviorEndDT6  Behavior = 0x0012
	BehaviorEndDT4  Behavior = 0x0013
	BehaviorEndDT46 Behavior = 0x0014
	BehaviorUDT6    Behavior = 0x003E
	BehaviorUDT4    Behavior = 0x003F
	BehaviorUDT46   Behavior = 0x0040
)

// BehaviorFromString RFC8986-compliant string of SRv6 behavior to Behavior constant
func BehaviorFromString(s string) Behavior {
	switch s {
	case "End.DT6":
		return BehaviorEndDT6
	case "End.DT4":
		return BehaviorEndDT4
	case "End.DT46":
		return BehaviorEndDT46
	case "uDT6":
		return BehaviorUDT6
	case "uDT4":
		return BehaviorUDT4
	case "uDT46":
		return BehaviorUDT46
	default:
		return BehaviorUnknown
	}
}

// String converts the behavior to RFC8986-compliant string
func (b Behavior) String() string {
	switch b {
	case BehaviorEndDT6:
		return "End.DT6"
	case BehaviorEndDT4:
		return "End.DT4"
	case BehaviorEndDT46:
		return "End.DT46"
	case BehaviorUDT6:
		return "uDT6"
	case BehaviorUDT4:
		return "uDT4"
	case BehaviorUDT46:
		return "uDT46"
	default:
		return "Unknown"
	}
}

type BehaviorType uint16

const (
	BehaviorTypeUnknown BehaviorType = iota
	BehaviorTypeBase
	BehaviorTypeUSID
)

func BehaviorTypeFromString(s string) BehaviorType {
	switch s {
	case "Base":
		return BehaviorTypeBase
	case "uSID":
		return BehaviorTypeUSID
	default:
		return BehaviorTypeUnknown
	}
}

func BehaviorTypeFromBehavior(b Behavior) BehaviorType {
	switch b {
	case BehaviorEndDT6, BehaviorEndDT4, BehaviorEndDT46:
		return BehaviorTypeBase
	case BehaviorUDT6, BehaviorUDT4, BehaviorUDT46:
		return BehaviorTypeUSID
	default:
		return BehaviorTypeUnknown
	}
}

func (k BehaviorType) String() string {
	switch k {
	case BehaviorTypeBase:
		return "Base"
	case BehaviorTypeUSID:
		return "uSID"
	default:
		return "Unknown"
	}
}
