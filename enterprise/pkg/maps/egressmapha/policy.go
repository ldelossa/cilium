//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package egressmapha

import (
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	PolicyMapName = "cilium_egress_gw_ha_policy_v4"
	// PolicyStaticPrefixBits represents the size in bits of the static
	// prefix part of an egress policy key (i.e. the source IP).
	PolicyStaticPrefixBits = uint32(unsafe.Sizeof(types.IPv4{}) * 8)
	MaxPolicyEntries       = 1 << 14

	// This define must be kept in sync with EGRESS_GW_HA_MAX_GATEWAY_NODES in the datapath.
	maxGatewayNodes = 64
)

// EgressPolicyKey4 is the key of an egress policy map.
type EgressPolicyKey4 = egressmap.EgressPolicyKey4

// EgressPolicyVal4 is the value of an egress policy map.
type EgressPolicyVal4 struct {
	Size       uint32                      `align:"size"`
	EgressIP   types.IPv4                  `align:"egress_ip"`
	GatewayIPs [maxGatewayNodes]types.IPv4 `align:"gateway_ips"`
}

type PolicyConfig struct {
	// EgressGatewayHAPolicyMapMax is the maximum number of entries
	// allowed in the BPF egress gateway policy map.
	EgressGatewayHAPolicyMapMax int
}

var DefaultPolicyConfig = PolicyConfig{
	EgressGatewayHAPolicyMapMax: 1 << 14,
}

func (def PolicyConfig) Flags(flags *pflag.FlagSet) {
	flags.Int("egress-gateway-ha-policy-map-max", def.EgressGatewayHAPolicyMapMax, "Maximum number of entries in egress gatewa HA policy map")
}

// PolicyMap is used to communicate EGW policies to the datapath.
type PolicyMap interface {
	Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*EgressPolicyVal4, error)
	Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP netip.Addr, gatewayIPs []netip.Addr) error
	Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error
	IterateWithCallback(EgressPolicyIterateCallback) error
}

// policyMap is the internal representation of an egress policy map.
type policyMap struct {
	m *ebpf.Map
}

func createPolicyMapFromDaemonConfig(in struct {
	cell.In

	Lifecycle hive.Lifecycle
	*option.DaemonConfig
	PolicyConfig
}) (out struct {
	cell.Out

	bpf.MapOut[PolicyMap]
	defines.NodeOut
}) {
	out.NodeDefines = map[string]string{
		"EGRESS_GW_HA_POLICY_MAP":      PolicyMapName,
		"EGRESS_GW_HA_POLICY_MAP_SIZE": fmt.Sprint(in.EgressGatewayHAPolicyMapMax),
	}

	if !in.EnableIPv4EgressGatewayHA {
		return
	}

	out.MapOut = bpf.NewMapOut(PolicyMap(createPolicyMap(in.Lifecycle, in.PolicyConfig, ebpf.PinByName)))
	return
}

// CreatePrivatePolicyMap creates an unpinned policy map.
//
// Useful for testing.
func CreatePrivatePolicyMap(lc hive.Lifecycle, cfg PolicyConfig) PolicyMap {
	return createPolicyMap(lc, cfg, ebpf.PinNone)
}

func createPolicyMap(lc hive.Lifecycle, cfg PolicyConfig, pinning ebpf.PinType) *policyMap {
	m := ebpf.NewMap(&ebpf.MapSpec{
		Name:       PolicyMapName,
		Type:       ebpf.LPMTrie,
		KeySize:    uint32(unsafe.Sizeof(EgressPolicyKey4{})),
		ValueSize:  uint32(unsafe.Sizeof(EgressPolicyVal4{})),
		MaxEntries: uint32(cfg.EgressGatewayHAPolicyMapMax),
		Pinning:    pinning,
	})

	lc.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			return m.OpenOrCreate()
		},
		OnStop: func(hive.HookContext) error {
			return m.Close()
		},
	})

	return &policyMap{m}
}

func OpenPinnedPolicyMap() (PolicyMap, error) {
	m, err := ebpf.LoadRegisterMap(PolicyMapName)
	if err != nil {
		return nil, err
	}

	return &policyMap{m}, nil
}

// NewEgressPolicyKey4 returns a new EgressPolicyKey4 object representing the
// (source IP, destination CIDR) tuple.
func NewEgressPolicyKey4(sourceIP netip.Addr, destCIDR netip.Prefix) EgressPolicyKey4 {
	return egressmap.NewEgressPolicyKey4(sourceIP, destCIDR)
}

// NewEgressPolicyVal4 returns a new EgressPolicyVal4 object representing for
// the given egress IP and gateway IPs
func NewEgressPolicyVal4(egressIP netip.Addr, gatewayIPs []netip.Addr) EgressPolicyVal4 {
	val := EgressPolicyVal4{
		Size: uint32(len(gatewayIPs)),
	}

	val.EgressIP.FromAddr(egressIP)
	for i, gw := range gatewayIPs {
		val.GatewayIPs[i].FromAddr(gw)
	}

	return val
}

// Match returns true if the egressIP and gatewayIPs parameters match the egress
// policy value.
func (v *EgressPolicyVal4) Match(egressIP netip.Addr, gatewayIPs []netip.Addr) bool {
	if v.GetEgressIP() != egressIP {
		return false
	}

	if v.Size != uint32(len(gatewayIPs)) {
		return false
	}

	for i, gwIP := range v.GetGatewayIPs() {
		if gwIP != gatewayIPs[i] {
			return false
		}
	}

	return true
}

// GetEgressIP returns the egress policy value's egress IP.
func (v *EgressPolicyVal4) GetEgressIP() netip.Addr {
	return v.EgressIP.Addr()
}

// GetGatewayIPs returns the egress policy value's gateway IP.
func (v *EgressPolicyVal4) GetGatewayIPs() []netip.Addr {
	gatewayIPs := []netip.Addr{}

	for i := uint32(0); i < v.Size; i++ {
		gatewayIPs = append(gatewayIPs, v.GatewayIPs[i].Addr())
	}

	return gatewayIPs
}

// String returns the string representation of an egress policy value.
func (v *EgressPolicyVal4) String() string {
	return fmt.Sprintf("%v %s", v.GetGatewayIPs(), v.GetEgressIP())
}

// Lookup returns the egress policy object associated with the provided (source
// IP, destination CIDR) tuple.
func (m *policyMap) Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*EgressPolicyVal4, error) {
	key := NewEgressPolicyKey4(sourceIP, destCIDR)
	val := EgressPolicyVal4{}

	err := m.m.Lookup(&key, &val)

	return &val, err
}

// Update updates the (sourceIP, destCIDR) egress policy entry with the provided
// egress and gateway IPs.
func (m *policyMap) Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP netip.Addr, gatewayIPs []netip.Addr) error {
	key := NewEgressPolicyKey4(sourceIP, destCIDR)
	val := NewEgressPolicyVal4(egressIP, gatewayIPs)

	return m.m.Update(key, val, 0)
}

// Delete deletes the (sourceIP, destCIDR) egress policy entry.
func (m *policyMap) Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error {
	key := NewEgressPolicyKey4(sourceIP, destCIDR)

	return m.m.Delete(key)
}

// EgressPolicyIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an egress policy map.
type EgressPolicyIterateCallback func(*EgressPolicyKey4, *EgressPolicyVal4)

// IterateWithCallback iterates through all the keys/values of an egress policy
// map, passing each key/value pair to the cb callback.
func (m policyMap) IterateWithCallback(cb EgressPolicyIterateCallback) error {
	return m.m.IterateWithCallback(&EgressPolicyKey4{}, &EgressPolicyVal4{},
		func(k, v interface{}) {
			key := k.(*EgressPolicyKey4)
			value := v.(*EgressPolicyVal4)

			cb(key, value)
		})
}
