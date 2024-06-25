//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressgatewayha

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"

	"github.com/cilium/cilium/pkg/ipam/service/allocator"
)

// pool represents a pool of egress CIDRs from which a policy can perform
// IP allocations on behalf of gateway nodes.
// Each CIDR relies on an allocation bitmap from package pkg/ipam/service/allocator
// to keep track of already allocated addresses in the range.
// The strategy used to allocate the next address is the "contiguous" one,
// so the first available IP in the range is selected.
type pool struct {
	ranges []*cidrRange
}

// newPool returns a pool ready to fulfill egress IP allocations.
//
// It returns an error if an invalid CIDR (i.e: a "/0" prefix) is passed as input.
func newPool(prefixes ...netip.Prefix) (*pool, error) {
	ranges := make([]*cidrRange, 0, len(prefixes))
	for _, prefix := range prefixes {
		r, err := newCIDRRange(prefix)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, r)
	}
	return &pool{ranges}, nil
}

// allocate reserves the address passed as input.
//
// It returns an error if the pool's ranges do not contain the address or
// if the address is already reserved.
func (p *pool) allocate(addr netip.Addr) error {
	for _, r := range p.ranges {
		if !r.prefix.Contains(addr) {
			continue
		}
		if err := r.allocate(addr); err != nil {
			return fmt.Errorf("failed to allocate addr %s from pool: %w", addr, err)
		}
		return nil
	}
	return fmt.Errorf("failed to allocate from pool: no range found to reserve addr %s", addr)
}

// allocateNext allocates the next address available in the pool.
// It uses a contiguous allocation strategy: the address is selected from the
// first empty range in the order specified when creating the pool.
// In that range, the first available address is allocated
//
// It returns an error if the pool has no available addresses.
func (p *pool) allocateNext() (netip.Addr, error) {
	for _, r := range p.ranges {
		addr, err := r.allocateNext()
		if err != nil {
			continue
		}
		return addr, nil
	}

	return netip.Addr{}, errors.New("failed to allocate from pool: no address available from ranges")
}

// cidrRange is an adapter to the allocation bitmap from package pkg/ipam/service/allocator
// Differently from other adapters to the same type, it relies on the newer netip.Prefix type
// and does not exclude the network and broadcast addresses from the allocatable range.
// Since this is tailored for egress-gateway IPAM, it supports IPv4 only.
type cidrRange struct {
	prefix netip.Prefix
	// base is a cached version of the start IP in the CIDR range as a *big.Int
	base *big.Int
	// max is the maximum size of the usable addresses in the range
	max int

	alloc allocator.Interface
}

func newCIDRRange(prefix netip.Prefix) (*cidrRange, error) {
	if prefix.Masked().Bits() == 0 {
		return nil, fmt.Errorf("invalid \"/0\" prefix: %s", prefix)
	}

	base := bigForIP(prefix.Masked().Addr())
	max := size(prefix)

	return &cidrRange{
		prefix: prefix,
		base:   base,
		max:    max,
		alloc:  allocator.NewContiguousAllocationMap(max, prefix.String()),
	}, nil
}

func (r *cidrRange) allocate(addr netip.Addr) error {
	allocated, err := r.alloc.Allocate(offset(r.base, addr))
	if err != nil {
		return fmt.Errorf("error while reserving addr %s in cidr %s: %w", addr, r.prefix, err)
	}
	if !allocated {
		return fmt.Errorf("addr %s is already reserved in cidr %s", addr, r.prefix)
	}

	return nil
}

func (r *cidrRange) allocateNext() (netip.Addr, error) {
	os, ok, err := r.alloc.AllocateNext()
	if err != nil {
		return netip.Addr{}, err
	}
	if !ok {
		return netip.Addr{}, fmt.Errorf("cidr %s is full", r.prefix)
	}

	return ipFromOffset(r.base, os), nil
}

func offset(base *big.Int, ip netip.Addr) int {
	return int(big.NewInt(0).Sub(bigForIP(ip), base).Int64())
}

func ipFromOffset(base *big.Int, os int) netip.Addr {
	n := big.NewInt(0).Add(base, big.NewInt(int64(os)))
	return netip.AddrFrom4([4]byte(n.Bytes()))
}

func bigForIP(ip netip.Addr) *big.Int {
	bytes := ip.As4()
	return big.NewInt(0).SetBytes(bytes[:])
}

func size(p netip.Prefix) int {
	return 1 << uint(32-p.Masked().Bits())
}
