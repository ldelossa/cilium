//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package locatorpool

import (
	"net/netip"
	"testing"

	"github.com/cilium/cilium/enterprise/pkg/srv6/types"

	"github.com/stretchr/testify/require"
)

func Test_PoolCreation(t *testing.T) {
	tests := []struct {
		description      string
		config           poolConfig
		allocations      int
		nextAllocations  int
		expectedPoolErr  error
		expectedAllocErr error
	}{
		{
			description: "valid pool config",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/48"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(40, 24, 16, 0),
				behaviorType: "Base",
			},
			expectedPoolErr: nil,
		},
		{
			description: "valid pool config, locatorLen and structure mismatch",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/48"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(32, 16, 32, 0),
				behaviorType: "Base",
			},
			expectedPoolErr: nil,
		},
		{
			description: "invalid pool config, invalid behavior type",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/48"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(40, 24, 16, 0),
				behaviorType: "invalid",
			},
			expectedPoolErr: ErrInvalidBehaviorType,
		},
		{
			description: "invalid pool config, prefix length >= LocB + LocN",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/64"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(40, 24, 16, 0),
				behaviorType: "Base",
			},
			expectedPoolErr: ErrInvalidPrefixAndSIDStruct,
		},
		{
			description: "invalid pool config, prefix length < LocB",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00::/32"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(40, 24, 16, 0),
				behaviorType: "Base",
			},
			expectedPoolErr: ErrInvalidPrefixAndSIDStruct,
		},
		{
			description: "invalid pool config, prefix not byte aligned",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/65"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(40, 24, 16, 0),
				behaviorType: "Base",
			},
			expectedPoolErr: ErrPrefixNotByteAligned,
		},
		{
			description: "invalid pool config, not v6 prefix",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("10.10.10.0/24"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(40, 24, 16, 0),
				behaviorType: "Base",
			},
			expectedPoolErr: ErrInvalidPrefix,
		},
		{
			description: "invalid pool config, locatorLen is smaller than LocN",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/32"),
				locatorLen:   40,
				structure:    types.MustNewSIDStructure(32, 16, 32, 0),
				behaviorType: "Base",
			},
			expectedPoolErr: ErrInvalidPrefixAndSIDStruct,
		},
		{
			description: "invalid pool config, locatorLen contains the end of Func",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/32"),
				locatorLen:   80,
				structure:    types.MustNewSIDStructure(32, 16, 32, 0),
				behaviorType: "Base",
			},
			expectedPoolErr: ErrInvalidPrefixAndSIDStruct,
		},
		{
			description: "invalid pool config, locatorLen overlapping with Arg",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/32"),
				locatorLen:   88,
				structure:    types.MustNewSIDStructure(32, 16, 32, 0),
				behaviorType: "Base",
			},
			expectedPoolErr: ErrInvalidPrefixAndSIDStruct,
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := require.New(t)
			_, err := newPool(tt.config)
			if tt.expectedPoolErr != nil {
				req.Contains(err.Error(), tt.expectedPoolErr.Error())
			} else {
				req.NoError(err)
			}
		})
	}
}

func Test_AllocateNext(t *testing.T) {
	tests := []struct {
		description  string
		config       poolConfig
		allocations  int
		expectedFree int
		expectedErr  error
	}{
		{
			description: "valid allocations for pool",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/48"),
				locatorLen:   56,
				structure:    types.MustNewSIDStructure(40, 16, 16, 0),
				behaviorType: "Base",
			},
			allocations:  255,
			expectedFree: 0,
			expectedErr:  nil,
		},
		{
			description: "valid allocations for pool with mismatched locator length and structure",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/48"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(32, 16, 32, 0),
				behaviorType: "Base",
			},
			allocations:  65535,
			expectedFree: 0,
			expectedErr:  nil,
		},
		{
			description: "valid allocations for pool with mismatched locator length and structure, capped",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/40"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(32, 16, 32, 0),
				behaviorType: "Base",
			},
			allocations:  65535,
			expectedFree: 0,
			expectedErr:  nil,
		},
		{
			description: "valid allocations for pool, fill half",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/48"),
				locatorLen:   56,
				structure:    types.MustNewSIDStructure(40, 16, 16, 0),
				behaviorType: "Base",
			},
			allocations:  128,
			expectedFree: 127,
			expectedErr:  nil,
		},
		{
			description: "valid allocations for pool with mismatched locator length and structure, fill half",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/48"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(32, 16, 32, 0),
				behaviorType: "Base",
			},
			allocations:  32768,
			expectedFree: 32767,
			expectedErr:  nil,
		},
		{
			description: "exceed allocations for pool",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/48"),
				locatorLen:   56,
				structure:    types.MustNewSIDStructure(40, 16, 16, 0),
				behaviorType: "Base",
			},
			allocations:  256,
			expectedFree: 0,
			expectedErr:  ErrLocatorPoolExhausted,
		},
		{
			description: "exceed allocations for pool with mismatched locator length and structure",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/48"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(32, 16, 32, 0),
				behaviorType: "Base",
			},
			allocations:  65536,
			expectedFree: 0,
			expectedErr:  ErrLocatorPoolExhausted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := require.New(t)
			pool, err := newPool(tt.config)
			req.NoError(err)

			for i := 1; i <= tt.allocations; i++ {
				_, err = pool.AllocateNext()
				if err != nil {
					break
				}
			}

			if tt.expectedErr != nil {
				req.Error(err)
				req.Contains(err.Error(), tt.expectedErr.Error())
			} else {
				req.NoError(err)
			}

			req.Equal(tt.expectedFree, pool.Free())
		})
	}
}

func Test_AllocateRelease(t *testing.T) {
	tests := []struct {
		description       string
		config            poolConfig
		allocatedLocators []*LocatorInfo
		releasedLocators  []*LocatorInfo
		expectedFree      int
		expectedErr       error
	}{
		{
			description: "allocations",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/48"),
				locatorLen:   56,
				structure:    types.MustNewSIDStructure(40, 16, 16, 0),
				behaviorType: "Base",
			},
			allocatedLocators: []*LocatorInfo{
				{
					Locator:      types.MustNewLocator(netip.MustParsePrefix("fd00:0:1:100::/56")),
					SIDStructure: types.MustNewSIDStructure(40, 16, 16, 0),
					BehaviorType: types.BehaviorTypeBase,
				},
				{
					Locator:      types.MustNewLocator(netip.MustParsePrefix("fd00:0:1:ff00::/56")),
					SIDStructure: types.MustNewSIDStructure(40, 16, 16, 0),
					BehaviorType: types.BehaviorTypeBase,
				},
			},
			releasedLocators: []*LocatorInfo{},
			expectedFree:     253,
			expectedErr:      nil,
		},
		{
			description: "allocations with mismatched locator length and structure",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/48"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(32, 16, 32, 0),
				behaviorType: "Base",
			},
			allocatedLocators: []*LocatorInfo{
				{
					Locator:      types.MustNewLocator(netip.MustParsePrefix("fd00:0:1:100::/64")),
					SIDStructure: types.MustNewSIDStructure(32, 16, 32, 0),
					BehaviorType: types.BehaviorTypeBase,
				},
				{
					Locator:      types.MustNewLocator(netip.MustParsePrefix("fd00:0:1:ff00::/64")),
					SIDStructure: types.MustNewSIDStructure(32, 16, 32, 0),
					BehaviorType: types.BehaviorTypeBase,
				},
			},
			releasedLocators: []*LocatorInfo{},
			expectedFree:     65533,
			expectedErr:      nil,
		},
		{
			description: "single allocations and release",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/48"),
				locatorLen:   56,
				structure:    types.MustNewSIDStructure(40, 16, 16, 0),
				behaviorType: "Base",
			},
			allocatedLocators: []*LocatorInfo{
				{
					Locator:      types.MustNewLocator(netip.MustParsePrefix("fd00:0:1:100::/56")),
					SIDStructure: types.MustNewSIDStructure(40, 16, 16, 0),
					BehaviorType: types.BehaviorTypeBase,
				},
				{
					Locator:      types.MustNewLocator(netip.MustParsePrefix("fd00:0:1:ff00::/56")),
					SIDStructure: types.MustNewSIDStructure(40, 16, 16, 0),
					BehaviorType: types.BehaviorTypeBase,
				},
			},
			releasedLocators: []*LocatorInfo{
				{
					Locator:      types.MustNewLocator(netip.MustParsePrefix("fd00:0:1:100::/56")),
					SIDStructure: types.MustNewSIDStructure(40, 16, 16, 0),
					BehaviorType: types.BehaviorTypeBase,
				},
				{
					Locator:      types.MustNewLocator(netip.MustParsePrefix("fd00:0:1:ff00::/56")),
					SIDStructure: types.MustNewSIDStructure(40, 16, 16, 0),
					BehaviorType: types.BehaviorTypeBase,
				},
			},
			expectedFree: 255,
			expectedErr:  nil,
		},
		{
			description: "single allocations and release with mismatched locator length and structure",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/48"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(32, 16, 32, 0),
				behaviorType: "Base",
			},
			allocatedLocators: []*LocatorInfo{
				{
					Locator:      types.MustNewLocator(netip.MustParsePrefix("fd00:0:1:100::/64")),
					SIDStructure: types.MustNewSIDStructure(32, 16, 32, 0),
					BehaviorType: types.BehaviorTypeBase,
				},
				{
					Locator:      types.MustNewLocator(netip.MustParsePrefix("fd00:0:1:ff00::/64")),
					SIDStructure: types.MustNewSIDStructure(32, 16, 32, 0),
					BehaviorType: types.BehaviorTypeBase,
				},
			},
			releasedLocators: []*LocatorInfo{
				{
					Locator:      types.MustNewLocator(netip.MustParsePrefix("fd00:0:1:100::/64")),
					SIDStructure: types.MustNewSIDStructure(32, 16, 32, 0),
					BehaviorType: types.BehaviorTypeBase,
				},
				{
					Locator:      types.MustNewLocator(netip.MustParsePrefix("fd00:0:1:ff00::/64")),
					SIDStructure: types.MustNewSIDStructure(32, 16, 32, 0),
					BehaviorType: types.BehaviorTypeBase,
				},
			},
			expectedFree: 65535,
			expectedErr:  nil,
		},
		{
			description: "idempotent release",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/48"),
				locatorLen:   56,
				structure:    types.MustNewSIDStructure(40, 16, 16, 0),
				behaviorType: "Base",
			},
			releasedLocators: []*LocatorInfo{
				{
					Locator:      types.MustNewLocator(netip.MustParsePrefix("fd00:0:1:100::/56")),
					SIDStructure: types.MustNewSIDStructure(40, 16, 16, 0),
					BehaviorType: types.BehaviorTypeBase,
				},
				{
					Locator:      types.MustNewLocator(netip.MustParsePrefix("fd00:0:1:ff00::/56")),
					SIDStructure: types.MustNewSIDStructure(40, 16, 16, 0),
					BehaviorType: types.BehaviorTypeBase,
				},
			},
			expectedFree: 255,
			expectedErr:  nil,
		},
		{
			description: "idempotent allocate",
			config: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("fd00:0:1::/48"),
				locatorLen:   56,
				structure:    types.MustNewSIDStructure(40, 16, 16, 0),
				behaviorType: "Base",
			},
			allocatedLocators: []*LocatorInfo{
				{
					Locator:      types.MustNewLocator(netip.MustParsePrefix("fd00:0:1:100::/56")),
					SIDStructure: types.MustNewSIDStructure(40, 16, 16, 0),
					BehaviorType: types.BehaviorTypeBase,
				},
				{
					Locator:      types.MustNewLocator(netip.MustParsePrefix("fd00:0:1:100::/56")),
					SIDStructure: types.MustNewSIDStructure(40, 16, 16, 0),
					BehaviorType: types.BehaviorTypeBase,
				},
			},
			expectedFree: 254,
			expectedErr:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := require.New(t)
			pool, err := newPool(tt.config)
			req.NoError(err)

			// test allocations
			for _, locator := range tt.allocatedLocators {
				err = pool.Allocate(locator)
				if err != nil {
					break
				}
			}
			if tt.expectedErr != nil {
				req.Error(err)
				req.Contains(err.Error(), tt.expectedErr.Error())
			} else {
				req.NoError(err)
			}

			// test release
			for _, locator := range tt.releasedLocators {
				err = pool.Release(locator)
				if err != nil {
					break
				}
			}
			if tt.expectedErr != nil {
				req.Error(err)
				req.Contains(err.Error(), tt.expectedErr.Error())
			} else {
				req.NoError(err)
			}

			req.Equal(tt.expectedFree, pool.Free())
		})
	}
}

func Test_ValidNodeLocator(t *testing.T) {
	tests := []struct {
		description string
		nodeLocator *LocatorInfo
		poolConfig  poolConfig
		expectedErr error
	}{
		{
			description: "valid node locator",
			nodeLocator: &LocatorInfo{
				Locator:      types.MustNewLocator(netip.MustParsePrefix("2001:db8:1:1::/64")),
				SIDStructure: types.MustNewSIDStructure(40, 24, 8, 0),
				BehaviorType: types.BehaviorTypeBase,
			},
			poolConfig: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("2001:db8:1::/48"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(40, 24, 8, 0),
				behaviorType: "Base",
			},
			expectedErr: nil,
		},
		{
			description: "valid node locator with mismatched locator length and structure",
			nodeLocator: &LocatorInfo{
				Locator:      types.MustNewLocator(netip.MustParsePrefix("2001:db8:1:1::/64")),
				SIDStructure: types.MustNewSIDStructure(32, 16, 32, 0),
				BehaviorType: types.BehaviorTypeBase,
			},
			poolConfig: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("2001:db8:1::/48"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(32, 16, 32, 0),
				behaviorType: "Base",
			},
			expectedErr: nil,
		},
		{
			description: "invalid node locator, prefix mismatch",
			nodeLocator: &LocatorInfo{
				Locator:      types.MustNewLocator(netip.MustParsePrefix("2002:db8:1:1::/64")),
				SIDStructure: types.MustNewSIDStructure(40, 24, 8, 0),
				BehaviorType: types.BehaviorTypeBase,
			},
			poolConfig: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("2001:db8:1::/48"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(40, 24, 8, 0),
				behaviorType: "Base",
			},
			expectedErr: ErrInvalidLocator,
		},
		{
			description: "invalid node locator, prefix length mismatch",
			nodeLocator: &LocatorInfo{
				Locator:      types.MustNewLocator(netip.MustParsePrefix("2001:db8:1:1::/72")),
				SIDStructure: types.MustNewSIDStructure(40, 32, 8, 0),
				BehaviorType: types.BehaviorTypeBase,
			},
			poolConfig: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("2001:db8:1::/48"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(40, 24, 8, 0),
				behaviorType: "Base",
			},
			expectedErr: ErrInvalidLocator,
		},
		{
			description: "invalid node locator, sid mismatch",
			nodeLocator: &LocatorInfo{
				Locator:      types.MustNewLocator(netip.MustParsePrefix("2001:db8:1:1::/64")),
				SIDStructure: types.MustNewSIDStructure(40, 24, 16, 0),
				BehaviorType: types.BehaviorTypeBase,
			},
			poolConfig: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("2001:db8:1::/48"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(40, 24, 8, 0),
				behaviorType: "Base",
			},
			expectedErr: ErrInvalidLocator,
		},
		{
			description: "invalid node locator, behavior mismatch",
			nodeLocator: &LocatorInfo{
				Locator:      types.MustNewLocator(netip.MustParsePrefix("2001:db8:1:1::/64")),
				SIDStructure: types.MustNewSIDStructure(40, 24, 16, 0),
				BehaviorType: types.BehaviorTypeUSID,
			},
			poolConfig: poolConfig{
				name:         "pool-1",
				prefix:       netip.MustParsePrefix("2001:db8:1::/48"),
				locatorLen:   64,
				structure:    types.MustNewSIDStructure(40, 24, 8, 0),
				behaviorType: "Base",
			},
			expectedErr: ErrInvalidLocator,
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			req := require.New(t)

			pool, err := newPool(tt.poolConfig)
			req.NoError(err)

			err = pool.Allocate(tt.nodeLocator)
			if tt.expectedErr != nil {
				req.Error(err)
				req.Contains(err.Error(), tt.expectedErr.Error())
			} else {
				req.NoError(err)
			}
		})
	}
}
