//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package srv6manager

import (
	"fmt"
	"net"
	"net/netip"

	"k8s.io/apimachinery/pkg/types"

	v1alpha1 "github.com/cilium/cilium/pkg/k8s/apis/isovalent.com/v1alpha1"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
)

// EgressPolicy is the internal representation of IsovalentSRv6EgressPolicy.
type EgressPolicy struct {
	// id is the parsed policy name and namespace
	id types.NamespacedName

	VRFID    uint32
	DstCIDRs []netip.Prefix
	SID      ciliumTypes.IPv6
}

// deepcopy-gen cannot generate a DeepCopyInto for net.IPNet. Define by ourselves.
func (in *EgressPolicy) DeepCopy() *EgressPolicy {
	if in == nil {
		return nil
	}
	out := new(EgressPolicy)
	in.deepCopyInto(out)
	return out
}

func (in *EgressPolicy) deepCopyInto(out *EgressPolicy) {
	out.id = in.id
	out.VRFID = in.VRFID
	out.DstCIDRs = make([]netip.Prefix, len(in.DstCIDRs))
	copy(out.DstCIDRs, in.DstCIDRs)
}

// PolicyID includes policy name and namespace
type policyID = types.NamespacedName

func ParsePolicy(csrep *v1alpha1.IsovalentSRv6EgressPolicy) (*EgressPolicy, error) {
	name := csrep.ObjectMeta.Name
	if name == "" {
		return nil, fmt.Errorf("IsovalentSRv6EgressPolicy must have a name")
	}

	var dstCidrList []netip.Prefix
	var sid ciliumTypes.IPv6

	copy(sid[:], net.ParseIP(csrep.Spec.DestinationSID).To16())

	for _, cidrString := range csrep.Spec.DestinationCIDRs {
		cidr, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			return nil, err
		}
		dstCidrList = append(dstCidrList, cidr)
	}

	return &EgressPolicy{
		id: types.NamespacedName{
			Name: name,
		},
		VRFID:    csrep.Spec.VRFID,
		DstCIDRs: dstCidrList,
		SID:      sid,
	}, nil
}

// ParseEgressPolicyID takes a IsovalentSRv6EgressPolicy CR and returns only the policy id
func ParseEgressPolicyID(csrep *v1alpha1.IsovalentSRv6EgressPolicy) types.NamespacedName {
	return policyID{
		Name: csrep.Name,
	}
}
