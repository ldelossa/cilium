//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package srv6map

import (
	"unsafe"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/types"

	"golang.org/x/exp/slices"
	netutils "k8s.io/utils/net"
)

func (a *PolicyKey) Equal(b *PolicyKey) bool {
	if (a != nil) != (b != nil) {
		return false
	}
	return a.VRFID == b.VRFID &&
		a.DestCIDR.IP.Equal(b.DestCIDR.IP) &&
		slices.Equal(a.DestCIDR.Mask, b.DestCIDR.Mask)
}

// IsIPv6 returns true if the key is for an IPv6 destination CIDR.
func (k *PolicyKey) IsIPv6() bool {
	return netutils.IsIPv6CIDR(k.DestCIDR)
}

func (a *PolicyValue) Equal(b *PolicyValue) bool {
	if (a != nil) != (b != nil) {
		return false
	}
	return a.SID.IP().Equal(b.SID.IP())
}

// toIPv4 converts the generic PolicyKey into an IPv4 policy key, to be used
// with BPF maps.
func (k *PolicyKey) toIPv4() PolicyKey4 {
	result := PolicyKey4{}
	ones, _ := k.DestCIDR.Mask.Size()

	result.VRFID = k.VRFID
	copy(result.DestCIDR[:], k.DestCIDR.IP.To4())
	result.PrefixLen = policyStaticPrefixBits + uint32(ones)

	return result
}

// toIPv6 converts the generic PolicyKey into an IPv6 policy key, to be used
// with BPF maps.
func (k *PolicyKey) toIPv6() PolicyKey6 {
	result := PolicyKey6{}
	ones, _ := k.DestCIDR.Mask.Size()

	result.VRFID = k.VRFID
	copy(result.DestCIDR[:], k.DestCIDR.IP.To16())
	result.PrefixLen = policyStaticPrefixBits + uint32(ones)

	return result
}

func (m *srv6PolicyMap) Lookup(key PolicyKey, val *PolicyValue) error {
	if key.IsIPv6() {
		return m.Map.Lookup(key.toIPv6(), val)
	}
	return m.Map.Lookup(key.toIPv4(), val)
}

func (m *srv6PolicyMap) Update(key PolicyKey, sid types.IPv6) error {
	val := PolicyValue{SID: sid}
	if key.IsIPv6() {
		return m.Map.Update(key.toIPv6(), val, 0)
	}
	return m.Map.Update(key.toIPv4(), val, 0)
}

func (m *srv6PolicyMap) Delete(key PolicyKey) error {
	if key.IsIPv6() {
		return m.Map.Delete(key.toIPv6())
	}
	return m.Map.Delete(key.toIPv4())
}

// GetPolicyMap returns the appropriate egress policy map (IPv4 or IPv6)
// for the given key.
func GetPolicyMap(key PolicyKey) *srv6PolicyMap {
	if key.IsIPv6() {
		return SRv6PolicyMap6
	}
	return SRv6PolicyMap4
}

func (a *SIDKey) Equal(b *SIDKey) bool {
	if (a != nil) != (b != nil) {
		return false
	}
	return a.SID.IP().Equal(b.SID.IP())
}

func (a *SIDValue) Equal(b *SIDValue) bool {
	if (a != nil) != (b != nil) {
		return false
	}
	return a.VRFID == b.VRFID
}

func (m *srv6SIDMap) Lookup(key SIDKey, val *SIDValue) error {
	return m.Map.Lookup(key, val)
}

func DeleteMaps() {
	SRv6PolicyMap4.Close()
	SRv6PolicyMap4.Unpin()
	SRv6PolicyMap6.Close()
	SRv6PolicyMap6.Unpin()
	SRv6SIDMap.Close()
	SRv6SIDMap.Unpin()
	SRv6VRFMap4.Close()
	SRv6VRFMap4.Unpin()
	SRv6VRFMap6.Close()
	SRv6VRFMap6.Unpin()
}

// IsIPv6 returns true if the key is for an IPv6 endpoint.
func (k *StateKey) IsIPv6() bool {
	return ip.IsIPv6(*k.InnerSrc) && ip.IsIPv6(*k.InnerDst)
}

func (a *VRFKey) Equal(b *VRFKey) bool {
	if (a != nil) != (b != nil) {
		return false
	}
	return a.SourceIP.Equal(*b.SourceIP) &&
		a.DestCIDR.IP.Equal(b.DestCIDR.IP) &&
		slices.Equal(a.DestCIDR.Mask, b.DestCIDR.Mask)
}

// IsIPv6 returns true if the key is for an IPv6 endpoint.
func (k *VRFKey) IsIPv6() bool {
	return ip.IsIPv6(*k.SourceIP)
}

func (a *VRFValue) Equal(b *VRFValue) bool {
	if (a != nil) != (b != nil) {
		return false
	}
	return a.ID == b.ID
}

func VRFMapsInitialized() bool {
	return SRv6VRFMap4 != nil && SRv6VRFMap6 != nil
}

// toIPv4 converts the generic VRFKey into an IPv4 VRF mapping key,
// to be used with BPF maps.
func (k *VRFKey) toIPv4() VRFKey4 {
	result := VRFKey4{}
	ones, _ := k.DestCIDR.Mask.Size()

	copy(result.SourceIP[:], k.SourceIP.To4())
	copy(result.DestCIDR[:], k.DestCIDR.IP.To4())
	result.PrefixLen = uint32(unsafe.Sizeof(result.SourceIP)*8) + uint32(ones)

	return result
}

// toIPv6 converts the generic VRFKey into an IPv6 VRF mapping key,
// to be used with BPF maps.
func (k *VRFKey) toIPv6() VRFKey6 {
	result := VRFKey6{}
	ones, _ := k.DestCIDR.Mask.Size()

	copy(result.SourceIP[:], k.SourceIP.To16())
	copy(result.DestCIDR[:], k.DestCIDR.IP.To16())
	result.PrefixLen = uint32(unsafe.Sizeof(result.SourceIP)*8) + uint32(ones)

	return result
}

func (m *srv6VRFMap) Lookup(key VRFKey, val *VRFValue) error {
	if key.IsIPv6() {
		return m.Map.Lookup(key.toIPv6(), val)
	}
	return m.Map.Lookup(key.toIPv4(), val)
}

func (m *srv6VRFMap) Update(key VRFKey, vrfID uint32) error {
	val := VRFValue{ID: vrfID}
	if key.IsIPv6() {
		return m.Map.Update(key.toIPv6(), val, 0)
	}
	return m.Map.Update(key.toIPv4(), val, 0)
}

func (m *srv6VRFMap) Delete(key VRFKey) error {
	if key.IsIPv6() {
		return m.Map.Delete(key.toIPv6())
	}
	return m.Map.Delete(key.toIPv4())
}

// GetVRFMap returns the appropriate VRF mapping map (IPv4 or IPv6)
// for the given key.
func GetVRFMap(key VRFKey) *srv6VRFMap {
	if key.IsIPv6() {
		return SRv6VRFMap6
	}
	return SRv6VRFMap4
}
