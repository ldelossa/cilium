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
	"github.com/cilium/cilium/pkg/types"
)

// Equal compares two PolicyKey objects
func (a *PolicyKey) Equal(b *PolicyKey) bool {
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// Equal compares two PolicyValue objects
func (a *PolicyValue) Equal(b *PolicyValue) bool {
	if a == nil || b == nil {
		return false
	}
	return a.SID.IP().Equal(b.SID.IP())
}

// toIPv4 converts the generic PolicyKey into an IPv4 policy key, to be used
// with BPF maps.
func (k *PolicyKey) toIPv4() *PolicyKey4 {
	return &PolicyKey4{
		PrefixLen: policyStaticPrefixBits + uint32(k.DestCIDR.Bits()),
		VRFID:     k.VRFID,
		DestCIDR:  k.DestCIDR.Addr().As4(),
	}
}

// toIPv6 converts the generic PolicyKey into an IPv6 policy key, to be used
// with BPF maps.
func (k *PolicyKey) toIPv6() *PolicyKey6 {
	return &PolicyKey6{
		PrefixLen: policyStaticPrefixBits + uint32(k.DestCIDR.Bits()),
		VRFID:     k.VRFID,
		DestCIDR:  k.DestCIDR.Addr().As16(),
	}
}

func (m *PolicyMap4) Lookup(key *PolicyKey, val *PolicyValue) error {
	v, err := m.Map.Lookup(key.toIPv4())
	if err != nil {
		return err
	}
	*val = *v.(*PolicyValue)
	return nil
}

func (m *PolicyMap4) Update(key *PolicyKey, sid types.IPv6) error {
	return m.Map.Update(key.toIPv4(), &PolicyValue{SID: sid})
}

func (m *PolicyMap4) Delete(key *PolicyKey) error {
	return m.Map.Delete(key.toIPv4())
}

func (m *PolicyMap6) Lookup(key *PolicyKey, val *PolicyValue) error {
	v, err := m.Map.Lookup(key.toIPv6())
	if err != nil {
		return err
	}
	*val = *v.(*PolicyValue)
	return nil
}

func (m *PolicyMap6) Update(key *PolicyKey, sid types.IPv6) error {
	return m.Map.Update(key.toIPv6(), &PolicyValue{SID: sid})
}

func (m *PolicyMap6) Delete(key *PolicyKey) error {
	return m.Map.Delete(key.toIPv6())
}

// Equal compares two SIDKey objects
func (a *SIDKey) Equal(b *SIDKey) bool {
	if a == nil || b == nil {
		return false
	}
	return a.SID.IP().Equal(b.SID.IP())
}

// Equal compares two SIDValue objects
func (a *SIDValue) Equal(b *SIDValue) bool {
	if a == nil || b == nil {
		return false
	}
	return a.VRFID == b.VRFID
}

func (m *SIDMap) Lookup(key *SIDKey, val *SIDValue) error {
	v, err := m.Map.Lookup(key)
	if err != nil {
		return err
	}
	*val = *v.(*SIDValue)
	return nil
}

func (m *SIDMap) Update(key *SIDKey, vrfID uint32) error {
	return m.Map.Update(key, &SIDValue{VRFID: vrfID})
}

func (m *SIDMap) Delete(key *SIDKey) error {
	return m.Map.Delete(key)
}

// Equal compares two VRFKey objects
func (a *VRFKey) Equal(b *VRFKey) bool {
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// Equal compares two VRFValue objects
func (a *VRFValue) Equal(b *VRFValue) bool {
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// toIPv4 converts the generic VRFKey into an IPv4 VRF mapping key,
// to be used with BPF maps.
func (k *VRFKey) toIPv4() *VRFKey4 {
	return &VRFKey4{
		PrefixLen: vrf4StaticPrefixBits + uint32(k.DestCIDR.Bits()),
		SourceIP:  k.SourceIP.As4(),
		DestCIDR:  k.DestCIDR.Addr().As4(),
	}
}

// toIPv6 converts the generic VRFKey into an IPv6 VRF mapping key,
// to be used with BPF maps.
func (k *VRFKey) toIPv6() *VRFKey6 {
	return &VRFKey6{
		PrefixLen: vrf6StaticPrefixBits + uint32(k.DestCIDR.Bits()),
		SourceIP:  k.SourceIP.As16(),
		DestCIDR:  k.DestCIDR.Addr().As16(),
	}
}

func (m *VRFMap4) Lookup(key *VRFKey, val *VRFValue) error {
	v, err := m.Map.Lookup(key.toIPv4())
	if err != nil {
		return err
	}
	*val = *v.(*VRFValue)
	return nil
}

func (m *VRFMap4) Update(key *VRFKey, vrfID uint32) error {
	return m.Map.Update(key.toIPv4(), &VRFValue{ID: vrfID})
}

func (m *VRFMap4) Delete(key *VRFKey) error {
	return m.Map.Delete(key.toIPv4())
}

func (m *VRFMap6) Lookup(key *VRFKey, val *VRFValue) error {
	v, err := m.Map.Lookup(key.toIPv6())
	if err != nil {
		return err
	}
	*val = *v.(*VRFValue)
	return nil
}

func (m *VRFMap6) Update(key *VRFKey, vrfID uint32) error {
	return m.Map.Update(key.toIPv6(), &VRFValue{ID: vrfID})
}

func (m *VRFMap6) Delete(key *VRFKey) error {
	return m.Map.Delete(key.toIPv6())
}
