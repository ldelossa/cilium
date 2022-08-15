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
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/types"

	"github.com/stretchr/testify/require"
)

func TestPolicyKeyEqual(t *testing.T) {
	tests := []struct {
		name string
		a    *PolicyKey
		b    *PolicyKey
		want bool
	}{
		{
			name: "Equal",
			a: &PolicyKey{
				VRFID:    1,
				DestCIDR: &net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.IPv4Mask(255, 255, 255, 0)},
			},
			b: &PolicyKey{
				VRFID:    1,
				DestCIDR: &net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.IPv4Mask(255, 255, 255, 0)},
			},
			want: true,
		},
		{
			name: "Different VRFID",
			a: &PolicyKey{
				VRFID:    1,
				DestCIDR: &net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.IPv4Mask(255, 255, 255, 0)},
			},
			b: &PolicyKey{
				VRFID:    2,
				DestCIDR: &net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.IPv4Mask(255, 255, 255, 0)},
			},
			want: false,
		},
		{
			name: "Different IPNet",
			a: &PolicyKey{
				VRFID:    1,
				DestCIDR: &net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.IPv4Mask(255, 255, 255, 0)},
			},
			b: &PolicyKey{
				VRFID:    1,
				DestCIDR: &net.IPNet{IP: net.IPv4(10, 0, 0, 2), Mask: net.IPv4Mask(255, 255, 255, 0)},
			},
			want: false,
		},
		{
			name: "Nil receiver",
			a:    nil,
			b: &PolicyKey{
				VRFID:    1,
				DestCIDR: &net.IPNet{IP: net.IPv4(10, 0, 0, 2), Mask: net.IPv4Mask(255, 255, 255, 0)},
			},
			want: false,
		},
		{
			name: "Nil argument",
			a: &PolicyKey{
				VRFID:    1,
				DestCIDR: &net.IPNet{IP: net.IPv4(10, 0, 0, 1), Mask: net.IPv4Mask(255, 255, 255, 0)},
			},
			b:    nil,
			want: false,
		},
		{
			name: "Nil receiver and argument",
			a:    nil,
			b:    nil,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.a.Equal(tt.b), tt.want)
		})
	}
}

func TestPolicyValueEqual(t *testing.T) {
	tests := []struct {
		name string
		a    *PolicyValue
		b    *PolicyValue
		want bool
	}{
		{
			name: "Equal",
			a: &PolicyValue{
				types.IPv6(net.IPv6loopback),
			},
			b: &PolicyValue{
				types.IPv6(net.IPv6loopback),
			},
			want: true,
		},
		{
			name: "Different SID",
			a: &PolicyValue{
				types.IPv6(net.IPv6loopback),
			},
			b: &PolicyValue{
				types.IPv6(net.IPv6unspecified),
			},
			want: false,
		},
		{
			name: "Nil receiver",
			a:    nil,
			b: &PolicyValue{
				types.IPv6(net.IPv6loopback),
			},
			want: false,
		},
		{
			name: "Nil argument",
			a: &PolicyValue{
				types.IPv6(net.IPv6loopback),
			},
			b:    nil,
			want: false,
		},
		{
			name: "Nil receiver and argument",
			a:    nil,
			b:    nil,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.a.Equal(tt.b), tt.want)
		})
	}
}

func TestSIDKeyEqual(t *testing.T) {
	tests := []struct {
		name string
		a    *SIDKey
		b    *SIDKey
		want bool
	}{
		{
			name: "Equal",
			a: &SIDKey{
				types.IPv6(net.IPv6loopback),
			},
			b: &SIDKey{
				types.IPv6(net.IPv6loopback),
			},
			want: true,
		},
		{
			name: "Different VRFID",
			a: &SIDKey{
				types.IPv6(net.IPv6loopback),
			},
			b: &SIDKey{
				types.IPv6(net.IPv6unspecified),
			},
			want: false,
		},
		{
			name: "Nil receiver",
			a:    nil,
			b: &SIDKey{
				types.IPv6(net.IPv6loopback),
			},
			want: false,
		},
		{
			name: "Nil argument",
			a: &SIDKey{
				types.IPv6(net.IPv6loopback),
			},
			b:    nil,
			want: false,
		},
		{
			name: "Nil receiver and argument",
			a:    nil,
			b:    nil,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.a.Equal(tt.b), tt.want)
		})
	}
}

func TestSIDValueEqual(t *testing.T) {
	tests := []struct {
		name string
		a    *SIDValue
		b    *SIDValue
		want bool
	}{
		{
			name: "Equal",
			a: &SIDValue{
				VRFID: 1,
			},
			b: &SIDValue{
				VRFID: 1,
			},
			want: true,
		},
		{
			name: "Different SID",
			a: &SIDValue{
				VRFID: 1,
			},
			b: &SIDValue{
				VRFID: 2,
			},
			want: false,
		},
		{
			name: "Nil receiver",
			a:    nil,
			b: &SIDValue{
				VRFID: 1,
			},
			want: false,
		},
		{
			name: "Nil argument",
			a: &SIDValue{
				VRFID: 1,
			},
			b:    nil,
			want: false,
		},
		{
			name: "Nil receiver and argument",
			a:    nil,
			b:    nil,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.a.Equal(tt.b), tt.want)
		})
	}
}

func TestVRFKeyEqual(t *testing.T) {
	ip1 := net.IPv4(10, 0, 0, 1)
	ip2 := net.IPv4(10, 0, 0, 2)
	tests := []struct {
		name string
		a    *VRFKey
		b    *VRFKey
		want bool
	}{
		{
			name: "Equal",
			a: &VRFKey{
				SourceIP: &ip1,
				DestCIDR: &net.IPNet{IP: ip2, Mask: net.IPv4Mask(255, 255, 255, 0)},
			},
			b: &VRFKey{
				SourceIP: &ip1,
				DestCIDR: &net.IPNet{IP: ip2, Mask: net.IPv4Mask(255, 255, 255, 0)},
			},
			want: true,
		},
		{
			name: "Different SourceIP",
			a: &VRFKey{
				SourceIP: &ip1,
				DestCIDR: &net.IPNet{IP: ip2, Mask: net.IPv4Mask(255, 255, 255, 0)},
			},
			b: &VRFKey{
				SourceIP: &ip2,
				DestCIDR: &net.IPNet{IP: ip2, Mask: net.IPv4Mask(255, 255, 255, 0)},
			},
			want: false,
		},
		{
			name: "Different DestCIDR",
			a: &VRFKey{
				SourceIP: &ip1,
				DestCIDR: &net.IPNet{IP: ip2, Mask: net.IPv4Mask(255, 255, 255, 0)},
			},
			b: &VRFKey{
				SourceIP: &ip1,
				DestCIDR: &net.IPNet{IP: ip2, Mask: net.IPv4Mask(255, 255, 254, 0)},
			},
			want: false,
		},
		{
			name: "Nil receiver",
			a:    nil,
			b: &VRFKey{
				SourceIP: &ip1,
				DestCIDR: &net.IPNet{IP: ip2, Mask: net.IPv4Mask(255, 255, 255, 0)},
			},
			want: false,
		},
		{
			name: "Nil argument",
			a: &VRFKey{
				SourceIP: &ip1,
				DestCIDR: &net.IPNet{IP: ip2, Mask: net.IPv4Mask(255, 255, 255, 0)},
			},
			b:    nil,
			want: false,
		},
		{
			name: "Nil receiver and argument",
			a:    nil,
			b:    nil,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.a.Equal(tt.b), tt.want)
		})
	}
}

func TestVRFValueEqual(t *testing.T) {
	tests := []struct {
		name string
		a    *VRFValue
		b    *VRFValue
		want bool
	}{
		{
			name: "Equal",
			a: &VRFValue{
				ID: 1,
			},
			b: &VRFValue{
				ID: 1,
			},
			want: true,
		},
		{
			name: "Different VRFID",
			a: &VRFValue{
				ID: 1,
			},
			b: &VRFValue{
				ID: 2,
			},
			want: false,
		},
		{
			name: "Nil receiver",
			a:    nil,
			b: &VRFValue{
				ID: 1,
			},
			want: false,
		},
		{
			name: "Nil argument",
			a: &VRFValue{
				ID: 1,
			},
			b:    nil,
			want: false,
		},
		{
			name: "Nil receiver and argument",
			a:    nil,
			b:    nil,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.a.Equal(tt.b), tt.want)
		})
	}
}
