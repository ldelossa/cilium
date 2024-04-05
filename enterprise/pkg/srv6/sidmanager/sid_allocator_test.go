//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sidmanager

import (
	"net/netip"
	"testing"

	"github.com/cilium/cilium/enterprise/pkg/srv6/types"

	"github.com/stretchr/testify/require"
)

func TestStructuredSIDAllocator(t *testing.T) {
	locator := types.MustNewLocator(
		netip.MustParsePrefix("fd00::/64"),
	)

	structure := types.MustNewSIDStructure(48, 16, 16, 0)

	t.Run("TestAllocate", func(t *testing.T) {
		allocator, err := NewStructuredSIDAllocator(locator, structure, types.BehaviorTypeBase)
		require.NoError(t, err)

		// Valid allocation
		info, err := allocator.Allocate(netip.MustParseAddr("fd00:0:0:0:1::"), "test1", "key1", types.BehaviorEndDT4)
		require.NoError(t, err)
		require.Equal(t, netip.MustParseAddr("fd00:0:0:0:1::"), info.SID.Addr)
		require.Equal(t, types.MustNewSIDStructure(48, 16, 16, 0), info.Structure)

		// Cannot allocate duplicated SID
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:0:1::"), "test1", "key2", types.BehaviorEndDT4)
		require.Error(t, err)

		// Locator mismatch
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:1:1::"), "test1", "key2", types.BehaviorEndDT4)
		require.Error(t, err)

		// Zero function part
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:0::"), "test1", "key2", types.BehaviorEndDT4)
		require.Error(t, err)

		// Non-zero rest part
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:0:2::1"), "test1", "key2", types.BehaviorEndDT4)
		require.Error(t, err)

		// Behavior and BehaviorType mismatched
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:0:2::"), "test1", "key2", types.BehaviorUDT4)
		require.Error(t, err)
	})

	t.Run("TestAllocateNext", func(t *testing.T) {
		allocator, err := NewStructuredSIDAllocator(locator, structure, types.BehaviorTypeBase)
		require.NoError(t, err)

		// Valid allocation
		info, err := allocator.AllocateNext("test1", "key2", types.BehaviorEndDT4)
		require.NoError(t, err)
		require.Len(t, info.SID.FunctionBytes(structure), 2)
		require.NotEqual(t, []byte{0, 0}, info.SID.FunctionBytes(structure))

		// Behavior and BehaviorType mismatched
		_, err = allocator.AllocateNext("test1", "key3", types.BehaviorUDT4)
		require.Error(t, err)
	})

	t.Run("TestRelease", func(t *testing.T) {
		allocator, err := NewStructuredSIDAllocator(locator, structure, types.BehaviorTypeBase)
		require.NoError(t, err)

		// Valid release
		info, err := allocator.AllocateNext("test1", "key2", types.BehaviorEndDT4)
		require.NoError(t, err)

		err = allocator.Release(info.SID.Addr)
		require.NoError(t, err)

		// Released SID should be reallocatable
		info, err = allocator.Allocate(info.SID.Addr, "test1", "key2", types.BehaviorEndDT4)
		require.NoError(t, err)

		err = allocator.Release(info.SID.Addr)
		require.NoError(t, err)
	})

	t.Run("TestAllocatedSIDs", func(t *testing.T) {
		allocator, err := NewStructuredSIDAllocator(locator, structure, types.BehaviorTypeBase)
		require.NoError(t, err)

		// Getting specific owner's SIDs
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:0:1::"), "test1", "key1", types.BehaviorEndDT4)
		require.NoError(t, err)
		sids := allocator.AllocatedSIDs("test1")
		require.Len(t, sids, 1)
		require.Equal(t, "test1", sids[0].Owner)
		require.Equal(t, "key1", sids[0].MetaData)
		require.Equal(t, netip.MustParseAddr("fd00:0:0:0:1::"), sids[0].SID.Addr)
		require.Equal(t, types.BehaviorEndDT4, sids[0].Behavior)

		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:0:2::"), "test2", "key2", types.BehaviorEndDT4)
		require.NoError(t, err)
		sids = allocator.AllocatedSIDs("test2")
		require.Len(t, sids, 1)
		require.Equal(t, "test2", sids[0].Owner)
		require.Equal(t, "key2", sids[0].MetaData)
		require.Equal(t, netip.MustParseAddr("fd00:0:0:0:2::"), sids[0].SID.Addr)
		require.Equal(t, types.BehaviorEndDT4, sids[0].Behavior)

		// Getting all SIDs
		sids = allocator.AllocatedSIDs("")
		require.Len(t, sids, 2)
	})
}

// Do the same test as TestStructuredSIDAllocator, but with the mismatching locator and structure
func TestStructuredSIDAllocatorWithMismatchingLocatorAndStructure(t *testing.T) {
	locator := types.MustNewLocator(
		netip.MustParsePrefix("fd00:0:0:ffff::/64"),
	)

	structure := types.MustNewSIDStructure(32, 16, 32, 0)

	t.Run("TestAllocate", func(t *testing.T) {
		allocator, err := NewStructuredSIDAllocator(locator, structure, types.BehaviorTypeBase)
		require.NoError(t, err)

		// Valid allocation
		info, err := allocator.Allocate(netip.MustParseAddr("fd00:0:0:ffff:1::"), "test1", "key1", types.BehaviorEndDT4)
		require.NoError(t, err)
		require.Equal(t, netip.MustParseAddr("fd00:0:0:ffff:1::"), info.SID.Addr)
		require.Equal(t, types.MustNewSIDStructure(32, 16, 32, 0), info.Structure)

		// Cannot allocate duplicated SID
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:ffff:1::"), "test1", "key2", types.BehaviorEndDT4)
		require.Error(t, err)

		// Cannot allocate from function part overlapping with locator prefix
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:fff1:1::"), "test1", "key2", types.BehaviorEndDT4)
		require.Error(t, err)

		// Zero function part
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:ffff:0::"), "test1", "key2", types.BehaviorEndDT4)
		require.Error(t, err)

		// Non-zero rest part
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:ffff:2::1"), "test1", "key2", types.BehaviorEndDT4)
		require.Error(t, err)

		// Behavior and BehaviorType mismatched
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:ffff:2::"), "test1", "key2", types.BehaviorUDT4)
		require.Error(t, err)
	})

	t.Run("TestAllocateNext", func(t *testing.T) {
		allocator, err := NewStructuredSIDAllocator(locator, structure, types.BehaviorTypeBase)
		require.NoError(t, err)

		// Valid allocation
		info, err := allocator.AllocateNext("test1", "key2", types.BehaviorEndDT4)
		require.NoError(t, err)
		require.Len(t, info.SID.FunctionBytes(structure), 4)
		require.Equal(t, []byte{0xff, 0xff}, info.SID.FunctionBytes(structure)[:2])
		require.NotEqual(t, []byte{0, 0}, info.SID.FunctionBytes(structure)[2:])

		// Behavior and BehaviorType mismatched
		_, err = allocator.AllocateNext("test1", "key3", types.BehaviorUDT4)
		require.Error(t, err)
	})

	t.Run("TestRelease", func(t *testing.T) {
		allocator, err := NewStructuredSIDAllocator(locator, structure, types.BehaviorTypeBase)
		require.NoError(t, err)

		// Valid release
		info, err := allocator.AllocateNext("test1", "key2", types.BehaviorEndDT4)
		require.NoError(t, err)

		err = allocator.Release(info.SID.Addr)
		require.NoError(t, err)

		// Released SID should be reallocatable
		info, err = allocator.Allocate(info.SID.Addr, "test1", "key2", types.BehaviorEndDT4)
		require.NoError(t, err)

		err = allocator.Release(info.SID.Addr)
		require.NoError(t, err)
	})

	t.Run("TestAllocatedSIDs", func(t *testing.T) {
		allocator, err := NewStructuredSIDAllocator(locator, structure, types.BehaviorTypeBase)
		require.NoError(t, err)

		// Getting specific owner's SIDs
		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:ffff:1::"), "test1", "key1", types.BehaviorEndDT4)
		require.NoError(t, err)
		sids := allocator.AllocatedSIDs("test1")
		require.Len(t, sids, 1)
		require.Equal(t, "test1", sids[0].Owner)
		require.Equal(t, "key1", sids[0].MetaData)
		require.Equal(t, netip.MustParseAddr("fd00:0:0:ffff:1::"), sids[0].SID.Addr)
		require.Equal(t, types.BehaviorEndDT4, sids[0].Behavior)

		_, err = allocator.Allocate(netip.MustParseAddr("fd00:0:0:ffff:2::"), "test2", "key2", types.BehaviorEndDT4)
		require.NoError(t, err)
		sids = allocator.AllocatedSIDs("test2")
		require.Len(t, sids, 1)
		require.Equal(t, "test2", sids[0].Owner)
		require.Equal(t, "key2", sids[0].MetaData)
		require.Equal(t, netip.MustParseAddr("fd00:0:0:ffff:2::"), sids[0].SID.Addr)
		require.Equal(t, types.BehaviorEndDT4, sids[0].Behavior)

		// Getting all SIDs
		sids = allocator.AllocatedSIDs("")
		require.Len(t, sids, 2)
	})
}

// Ensures that the allocator can allocate all available SIDs and none of them are corrupted
func TestAllAllocations(t *testing.T) {
	doTest := func(locator types.Locator, structure types.SIDStructure, t *testing.T) {
		// Create allocator
		allocator, err := NewStructuredSIDAllocator(locator, structure, types.BehaviorTypeBase)
		require.NoError(t, err)

		// Allocate all SIDs and ensure none of them are corrupted
		var allocationCount int
		for {
			info, err := allocator.AllocateNext("test", "key", types.BehaviorEndDT4)
			if err != nil {
				require.Equal(t, "no more allocatable SID left", err.Error(), "Got unexpected error")
				break
			}

			allocationCount++

			// Ensure the allocated SID is not corrupted

			// Locator
			loc, err := info.SID.Prefix(locator.Bits())
			require.NoError(t, err)
			require.Equal(t, locator.Prefix, loc)

			// Function
			locLen := locator.Bits() / 8
			function := info.SID.AsSlice()[locLen:int(structure.LocatorLenBytes()+structure.FunctionLenBytes())]
			zeros := []byte{}
			for i := 0; i < len(function); i++ {
				zeros = append(zeros, 0)
			}
			require.NotEqual(t, zeros, function, "Function part should not be zero")

			// Argument and rest of the parts must be zero
			misc := info.SID.AsSlice()[int(structure.LocatorLenBytes()+structure.FunctionLenBytes()):]
			for i := 0; i < len(misc); i++ {
				require.Equal(t, uint8(0), misc[i], "Rest of the part should be zero")
			}
		}
	}

	// IOS-XR compatible locator and structure with locator-function overlap and no overlap
	t.Run("F402416NoOverlap", func(t *testing.T) {
		locator := types.MustNewLocator(netip.MustParsePrefix("fd00:ffff:ffff:ffff::/64"))
		structure := types.MustNewSIDStructure(40, 24, 16, 0)
		doTest(locator, structure, t)
	})

	t.Run("F402416Overlap", func(t *testing.T) {
		locator := types.MustNewLocator(netip.MustParsePrefix("fd00:ffff:ffff:ffff:ff00::/72"))
		structure := types.MustNewSIDStructure(40, 24, 16, 0)
		doTest(locator, structure, t)
	})

	t.Run("F3216NoOverlap", func(t *testing.T) {
		locator := types.MustNewLocator(netip.MustParsePrefix("fd00:ffff:ffff::/48"))
		structure := types.MustNewSIDStructure(32, 16, 16, 0)
		doTest(locator, structure, t)
	})

	t.Run("F3216Overlap", func(t *testing.T) {
		locator := types.MustNewLocator(netip.MustParsePrefix("fd00:ffff:ffff:ff00::/56"))
		structure := types.MustNewSIDStructure(32, 16, 16, 0)
		doTest(locator, structure, t)
	})

	t.Run("F321632NoOverlap", func(t *testing.T) {
		locator := types.MustNewLocator(netip.MustParsePrefix("fd00:ffff:ffff::/48"))
		structure := types.MustNewSIDStructure(32, 16, 32, 0)
		doTest(locator, structure, t)
	})

	t.Run("F321632Overlap", func(t *testing.T) {
		locator := types.MustNewLocator(netip.MustParsePrefix("fd00:ffff:ffff:ffff::/64"))
		structure := types.MustNewSIDStructure(32, 16, 32, 0)
		doTest(locator, structure, t)
	})

	// Non-IOS-XR compatible locator and structure, but useful for excercising the internal logic
	t.Run("F323232NoOverlap", func(t *testing.T) {
		// 32bit allocatable range, but should be capped with 16bit
		locator := types.MustNewLocator(netip.MustParsePrefix("fd00:ffff:ffff:ffff::/64"))
		structure := types.MustNewSIDStructure(32, 32, 32, 0)
		doTest(locator, structure, t)
	})

	t.Run("F323232Overlap", func(t *testing.T) {
		// 24bit allocatable range with overlap, but should be capped with 16bit
		locator := types.MustNewLocator(netip.MustParsePrefix("fd00:ffff:ffff:ffff:ff00::/72"))
		structure := types.MustNewSIDStructure(32, 32, 32, 0)
		doTest(locator, structure, t)
	})

	t.Run("F323224NoOverlap", func(t *testing.T) {
		// 24bit allocatable range, but should be capped with 16bit
		locator := types.MustNewLocator(netip.MustParsePrefix("fd00:ffff:ffff:ffff::/64"))
		structure := types.MustNewSIDStructure(32, 32, 24, 0)
		doTest(locator, structure, t)
	})

	t.Run("F323224Overlap", func(t *testing.T) {
		// 16bit allocatable range with overlap
		locator := types.MustNewLocator(netip.MustParsePrefix("fd00:ffff:ffff:ffff:ff00::/72"))
		structure := types.MustNewSIDStructure(32, 32, 24, 0)
		doTest(locator, structure, t)
	})

	t.Run("F323216NoOverlap", func(t *testing.T) {
		// 16bit allocatable range
		locator := types.MustNewLocator(netip.MustParsePrefix("fd00:ffff:ffff:ffff::/64"))
		structure := types.MustNewSIDStructure(32, 32, 16, 0)
		doTest(locator, structure, t)
	})

	t.Run("F323216Overlap", func(t *testing.T) {
		// 8bit allocatable range with overlap
		locator := types.MustNewLocator(netip.MustParsePrefix("fd00:ffff:ffff:ffff:ff00::/72"))
		structure := types.MustNewSIDStructure(32, 32, 16, 0)
		doTest(locator, structure, t)
	})

	t.Run("F32328NoOverlap", func(t *testing.T) {
		// 8bit allocatable range
		locator := types.MustNewLocator(netip.MustParsePrefix("fd00:ffff:ffff:ffff::/64"))
		structure := types.MustNewSIDStructure(32, 32, 16, 0)
		doTest(locator, structure, t)
	})

	t.Run("F32328Overlap", func(t *testing.T) {
		// No allocatable range, this won't introduce any error, just cannot allocate any SID
		locator := types.MustNewLocator(netip.MustParsePrefix("fd00:ffff:ffff:ffff:ff00::/72"))
		structure := types.MustNewSIDStructure(32, 32, 8, 0)
		doTest(locator, structure, t)
	})
}
