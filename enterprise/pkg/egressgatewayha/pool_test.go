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
	"net/netip"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
)

func TestPoolAllocate(t *testing.T) {
	prefix := netip.MustParsePrefix("10.100.255.48/30")

	pool, err := newPool(prefix)
	if err != nil {
		t.Fatalf("unexpected error while creating pool: %s", err)
	}

	// reserve all addresses from prefix
	for addr := prefix.Masked().Addr(); prefix.Contains(addr); addr = addr.Next() {
		if err := pool.allocate(addr); err != nil {
			t.Fatalf("unexpected error while allocating %s: %s", addr, err)
		}
	}

	// allocations for already reserved addresses should fail
	for addr := prefix.Masked().Addr(); prefix.Contains(addr); addr = addr.Next() {
		if err := pool.allocate(addr); err == nil {
			t.Fatalf("expected error while allocating addr %s from depleted pool, got nil", addr)
		}
	}

	// allocations for addresses out of the range should fail
	addr := prefix.Masked().Addr().Prev()
	if err := pool.allocate(addr); err == nil {
		t.Fatalf("expected error while allocating addr %s not contained in pool, got nil", addr)
	}

	prefix2 := netip.MustParsePrefix("10.100.255.52/30")

	pool, err = newPool(prefix, prefix2)
	if err != nil {
		t.Fatalf("unexpected error while creating pool: %s", err)
	}

	// reserve all addresses from first prefix
	for addr := prefix.Masked().Addr(); prefix.Contains(addr); addr = addr.Next() {
		if err := pool.allocate(addr); err != nil {
			t.Fatalf("unexpected error while allocating %s: %s", addr, err)
		}
	}
	// pool should be able to allocate from the next prefix
	for addr := prefix2.Masked().Addr(); prefix2.Contains(addr); addr = addr.Next() {
		if err := pool.allocate(addr); err != nil {
			t.Fatalf("unexpected error while allocating %s: %s", addr, err)
		}
	}
}

func TestPoolAllocateNext(t *testing.T) {
	prefix := netip.MustParsePrefix("10.100.255.48/30")

	pool, err := newPool(prefix)
	if err != nil {
		t.Fatalf("unexpected error while creating pool: %s", err)
	}

	// reserve all addresses from prefix
	for addr := prefix.Masked().Addr(); prefix.Contains(addr); addr = addr.Next() {
		next, err := pool.allocateNext()
		if err != nil {
			t.Fatalf("unexpected error while allocating next address from pool: %s", err)
		}
		if next != addr {
			t.Fatalf("expected allocated address to be %s, got %s", addr, next)
		}
	}

	// further allocations from depleted pool should fail
	if _, err := pool.allocateNext(); err == nil {
		t.Fatal("expected error while allocating next addr from depleted pool, got nil")
	}

	// allocations for addresses out of the range should fail
	addr := prefix.Masked().Addr().Prev()
	if err := pool.allocate(addr); err == nil {
		t.Fatalf("expected error while allocating addr %s not contained in pool", addr)
	}

	prefix2 := netip.MustParsePrefix("10.100.255.52/30")

	pool, err = newPool(prefix, prefix2)
	if err != nil {
		t.Fatalf("unexpected error while creating pool: %s", err)
	}

	// reserve all addresses from prefix
	for addr := prefix.Masked().Addr(); prefix.Contains(addr); addr = addr.Next() {
		next, err := pool.allocateNext()
		if err != nil {
			t.Fatalf("unexpected error while allocating next address from pool: %s", err)
		}
		if next != addr {
			t.Fatalf("expected allocated address to be %s, got %s", addr, next)
		}
	}
	// pool should be able to allocate from the next prefix
	for addr := prefix2.Masked().Addr(); prefix2.Contains(addr); addr = addr.Next() {
		next, err := pool.allocateNext()
		if err != nil {
			t.Fatalf("unexpected error while allocating next address from pool: %s", err)
		}
		if next != addr {
			t.Fatalf("expected allocated address to be %s, got %s", addr, next)
		}
	}
}

func TestPoolAddressIsInRange(t *testing.T) {
	testCases := []struct {
		name     string
		prefix   netip.Prefix
		expected int
	}{
		{
			name:   "/32 CIDR",
			prefix: netip.MustParsePrefix("10.100.255.49/32"),
		},
		{
			name:   "/30 CIDR",
			prefix: netip.MustParsePrefix("10.100.255.48/30"),
		},
		{
			name:   "/24 CIDR",
			prefix: netip.MustParsePrefix("10.100.255.0/24"),
		},
		{
			name:   "non-masked /24 CIDR",
			prefix: netip.MustParsePrefix("10.100.255.49/24"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := newPool(tc.prefix)
			if err != nil {
				t.Fatalf("unexpected error while creating pool: %s", err)
			}

			s := sets.New[netip.Addr]()
			for {
				addr, err := pool.allocateNext()
				if err != nil {
					break
				}
				s.Insert(addr)
			}

			// each allocated IP should be part of the prefix
			for addr := range s {
				if !tc.prefix.Contains(addr) {
					t.Fatalf("allocated address %s is out of pool range %s", addr, tc.prefix)
				}
			}

			// the total number of allocated IPs should equal to the # addresses in the prefix
			nAddrs := 1 << (tc.prefix.Addr().BitLen() - tc.prefix.Bits())
			if s.Len() != nAddrs {
				t.Fatalf("expected %d addresses from prefix %s, got %d", nAddrs, tc.prefix, s.Len())
			}
		})
	}
}
