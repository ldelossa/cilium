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
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"

	allocator "github.com/cilium/cilium/pkg/ipam/service/allocator"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/cilium/cilium/enterprise/pkg/srv6/types"
)

type SIDAllocator interface {
	// Locator returns a Locator associated with this allocator
	Locator() types.Locator

	// Structure returns a SID structure associated with this allocator
	Structure() types.SIDStructure

	// BehaviorType returns a type of the behavior for the locator
	BehaviorType() types.BehaviorType

	// Allocate tries to allocate specified SID from this allocator. It returns error if it is already used.
	Allocate(sid netip.Addr, owner string, metadata string, behavior types.Behavior) (*SIDInfo, error)

	// AllocateNext allocates next available SID from this allocator
	AllocateNext(owner string, metadata string, behavior types.Behavior) (*SIDInfo, error)

	// Release releases SID allocated from this allocator
	Release(sid netip.Addr) error

	// AllocatedSIDs returns list of allocated SIDs for specified owner. When empty owner string is specified,
	// it returns all allocated SIDs.
	AllocatedSIDs(owner string) []*SIDInfo
}

type SIDInfo struct {
	Owner        string
	MetaData     string
	SID          types.SID
	Structure    types.SIDStructure
	BehaviorType types.BehaviorType
	Behavior     types.Behavior
}

func (a *SIDInfo) SIDAndBehaviorEqual(b *SIDInfo) bool {
	if (a == nil) || (b == nil) {
		return false
	}
	if a.SID != b.SID {
		return false
	}
	if a.Structure != b.Structure {
		return false
	}
	if a.BehaviorType != b.BehaviorType {
		return false
	}
	if a.Behavior != b.Behavior {
		return false
	}
	return true
}

func (in *SIDInfo) DeepCopy() *SIDInfo {
	if in == nil {
		return nil
	}
	out := new(SIDInfo)
	in.DeepCopyInto(out)
	return out
}

func (in *SIDInfo) DeepCopyInto(out *SIDInfo) {
	out.Owner = in.Owner
	out.MetaData = in.MetaData
	out.SID = in.SID
	out.Structure = in.Structure
	out.BehaviorType = in.BehaviorType
	out.Behavior = in.Behavior
}

// StructuredSIDAllocator is an SRv6 SID allocator that allocates structured SIDs
// using the SID structure information provided.
type StructuredSIDAllocator struct {
	// SID is allocated from this locator prefix
	locator types.Locator

	// SID structure information
	structure types.SIDStructure

	// Type of the behavior which should be bounded to SIDs allocated from this allocator
	behaviorType types.BehaviorType

	// Allocator to manage the allocation of function part.
	allocator *allocator.AllocationBitmap

	// Function part => SID allocation mappings
	allocatedSIDs map[int]*SIDInfo

	// A lock to protect allocatedSIDs
	allocatedSIDsLock lock.Mutex
}

func NewStructuredSIDAllocator(locator types.Locator, structure types.SIDStructure, behaviorType types.BehaviorType) (SIDAllocator, error) {
	if structure.ArgumentLenBits() != 0 {
		return nil, fmt.Errorf("argument length must be zero")
	}

	if behaviorType == types.BehaviorTypeUnknown {
		return nil, fmt.Errorf("unknown behavior type")
	}

	// Cap the maximum number of allocations regardless of the function length.
	// We need this to reduce memory consumption because allocator.AllocationBitmap
	// manages allocation state with a bitmap that each bit represents allocation state.
	// Thus we consume maxAllocations bits for each StructuredSIDAllocator instance.
	// 65536 SIDs should be large enough for our current use case (SRv6 L3VPN with
	// per-VRF SID allocation) because users only allocates very small number of SIDs
	// in practice (number of VRFs on the node).
	maxAllocations := math.Min(
		math.Pow(2, float64(structure.FunctionLenBits())),
		float64(math.MaxUint16),
	)

	allocator := allocator.NewAllocationMap(int(maxAllocations), "")

	// Some implementation doesn't accept zero function part. Pre-allocate it to avoid callers getting it.
	allocator.Allocate(0)

	return &StructuredSIDAllocator{
		locator:       locator,
		structure:     structure,
		behaviorType:  behaviorType,
		allocator:     allocator,
		allocatedSIDs: make(map[int]*SIDInfo),
	}, nil
}

func (a *StructuredSIDAllocator) Locator() types.Locator {
	return a.locator
}

func (a *StructuredSIDAllocator) Structure() types.SIDStructure {
	return a.structure
}

func (a *StructuredSIDAllocator) BehaviorType() types.BehaviorType {
	return a.behaviorType
}

// Create full SID by encoding function part into the locator.
// For example, when the locator fd00:1:2:3::/64 and function
// part is 0x1234, create fd00:1:2:3:1234::.
func (a *StructuredSIDAllocator) encodeSID(f int) (types.SID, error) {
	funcSlice := make([]byte, a.structure.FunctionLenBytes())

	// We only support a function part of
	//
	// 1) Non-zero
	// 2) Byte-aligned
	// 3) 16bit long function in maximum
	//
	// So, these are the all possible cases.
	switch a.structure.FunctionLenBits() {
	case 8:
		funcSlice[0] = uint8(f)
	case 16:
		binary.BigEndian.PutUint16(funcSlice, uint16(f))
	default:
		// This shouldn't happen as we validate SID structure on construction
		return types.SID{}, fmt.Errorf("unsupported function length %d", a.structure.FunctionLenBits())
	}

	// We don't have argument part support so far
	sid, err := types.NewSIDFromLFA(a.locator, funcSlice, []byte{})
	if err != nil {
		return types.SID{}, fmt.Errorf("SID construction failed: %w", err)
	}

	return sid, nil
}

// Do the opposite of encodeSID. Divide SID into locator part and function part
// and returns function part. For example, when the SID is fd00:1:2:3:1234:: and
// loc and func length are 64 and 16, this function returns fd00:1:2:3::/64 and
// 0x1234 (in native endian).
func (a *StructuredSIDAllocator) decodeSID(sid types.SID) (int, error) {
	funcSlice := sid.FunctionBytes(a.structure)

	var f int
	switch a.structure.FunctionLenBits() {
	case 8:
		f = int(funcSlice[0])
	case 16:
		f = int(binary.BigEndian.Uint16(funcSlice))
	default:
		// This shouldn't happen as we validate SID structure on construction
		return 0, fmt.Errorf("unsupported function length %d", a.structure.FunctionLenBits())
	}

	return f, nil
}

func (a *StructuredSIDAllocator) addSIDInfo(f int, si *SIDInfo) {
	a.allocatedSIDsLock.Lock()
	defer a.allocatedSIDsLock.Unlock()
	a.allocatedSIDs[f] = si
}

func (a *StructuredSIDAllocator) delSIDInfo(f int) {
	a.allocatedSIDsLock.Lock()
	defer a.allocatedSIDsLock.Unlock()
	delete(a.allocatedSIDs, f)
}

func (a *StructuredSIDAllocator) Allocate(addr netip.Addr, owner string, metadata string, behavior types.Behavior) (*SIDInfo, error) {
	if owner == "" {
		return nil, fmt.Errorf("empty owner")
	}

	if types.BehaviorTypeFromBehavior(behavior) != a.BehaviorType() {
		return nil, fmt.Errorf("behavior type and behavior are mismatched")
	}

	if !a.locator.Contains(addr) {
		return nil, fmt.Errorf("locator out of range")
	}

	sid, err := types.NewSID(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to create SID: %w", err)
	}

	isZeroBytes := func(bytes []byte) bool {
		for _, b := range bytes {
			if b != 0 {
				return false
			}
		}
		return true
	}

	// Zero function part is invalid
	if isZeroBytes(sid.FunctionBytes(a.structure)) {
		return nil, fmt.Errorf("cannot allocate zero function")
	}

	// Non-zero argument part is invalid
	if !isZeroBytes(sid.ArgumentBytes(a.structure)) {
		return nil, fmt.Errorf("argument part must be all zero")
	}

	// Rest of the SID should be all zero
	if !isZeroBytes(sid.RestBytes(a.structure)) {
		return nil, fmt.Errorf("non-SID part must be all zero")
	}

	f, err := a.decodeSID(sid)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SID: %w", err)
	}

	if allocated, err := a.allocator.Allocate(f); !allocated && err == nil {
		return nil, fmt.Errorf("SID %s is not available", addr.String())
	}

	info := &SIDInfo{
		Owner:        owner,
		MetaData:     metadata,
		SID:          sid,
		Structure:    a.structure,
		BehaviorType: a.BehaviorType(),
		Behavior:     behavior,
	}

	a.addSIDInfo(f, info)

	return info, nil
}

func (a *StructuredSIDAllocator) AllocateNext(owner string, metadata string, behavior types.Behavior) (*SIDInfo, error) {
	if owner == "" {
		return nil, fmt.Errorf("empty owner")
	}

	if types.BehaviorTypeFromBehavior(behavior) != a.BehaviorType() {
		return nil, fmt.Errorf("behavior type and behavior are mismatched")
	}

	f, allocated, err := a.allocator.AllocateNext()
	if f == 0 && !allocated && err == nil {
		return nil, fmt.Errorf("no more allocatable SID left")
	}

	sid, err := a.encodeSID(f)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SID: %w", err)
	}

	info := &SIDInfo{
		Owner:        owner,
		MetaData:     metadata,
		SID:          sid,
		Structure:    a.structure,
		BehaviorType: a.BehaviorType(),
		Behavior:     behavior,
	}

	a.addSIDInfo(f, info)

	return info, nil
}

func (a *StructuredSIDAllocator) Release(addr netip.Addr) error {
	sid, err := types.NewSID(addr)
	if err != nil {
		return fmt.Errorf("failed to create SID: %w", err)
	}

	if !a.locator.Contains(addr) {
		return fmt.Errorf("SID is not allocated from this allocator")
	}

	f, err := a.decodeSID(sid)
	if err != nil {
		return fmt.Errorf("failed to decode SID: %w", err)
	}

	a.allocator.Release(f)
	a.delSIDInfo(f)

	return nil
}

func (a *StructuredSIDAllocator) AllocatedSIDs(owner string) []*SIDInfo {
	ret := []*SIDInfo{}
	for _, alloc := range a.allocatedSIDs {
		if owner == "" || alloc.Owner == owner {
			ret = append(ret, alloc)
		}
	}
	return ret
}
