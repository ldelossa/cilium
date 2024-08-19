//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package ciliummeshpolicymap

import (
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
)

const (
	ciliumMesh = "enable-cilium-mesh"
)

type Config struct {
	EnableCiliumMesh bool `mapstructure:"enable-cilium-mesh"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool(ciliumMesh, def.EnableCiliumMesh, "Enables Cilium Mesh feature")
}

type ciliumMeshPolicyParams struct {
	cell.In

	Config Config

	Lifecycle cell.Lifecycle
	Logger    logrus.FieldLogger
}

type CiliumMeshPolicyWriter interface {
	WriteEndpoint(ip netip.Addr, pm *policymap.PolicyMap) error

	// A botch to fix a hive dependency cycle: Since the Maps are collected
	// (depended on) by the Loader, but this Map initialisation depends on the
	// loader, we have a cycle. Since the map init is async, we can break the
	// cycle by registering the loader to the policy map init.
	registerLoader(loader types.Loader)
}

type ciliumMeshPolicyMap struct {
	// To avoid a hive dependency cycle, see registerLoader.
	loaderChan chan types.Loader

	m           *ebpf.Map
	initialized chan struct{}
}

func (cmpm *ciliumMeshPolicyMap) writeEndpoint(keys []*lxcmap.EndpointKey, fd int) error {
	if fd < 0 {
		return fmt.Errorf("WriteEndpoint invalid policy fd %d", fd)
	}

	/* Casting file desriptor into uint32 required by BPF syscall */
	epFd := &CiliumMeshPolicyValue{Fd: uint32(fd)}

	for _, v := range keys {
		if err := cmpm.m.Update(v, epFd, 0); err != nil {
			return err
		}
	}
	return nil
}

func (cmpm *ciliumMeshPolicyMap) registerLoader(loader types.Loader) {
	cmpm.loaderChan <- loader
}

// WriteEndpoint writes the policy map file descriptor into the map so that
// the datapath side can do a lookup from EndpointKey->PolicyMap. Locking is
// handled in the usual way via Map lock. If sockops is disabled this will be
// a nop.
func (cmpm *ciliumMeshPolicyMap) WriteEndpoint(ip netip.Addr, pm *policymap.PolicyMap) error {
	<-cmpm.initialized

	var keys []*lxcmap.EndpointKey

	if ip.IsValid() {
		keys = append(keys, lxcmap.NewEndpointKey(ip.AsSlice()))
	}

	return cmpm.writeEndpoint(keys, pm.FD())
}

func newCiliumMeshPolicyParams(p ciliumMeshPolicyParams) (out struct {
	cell.Out

	bpf.MapOut[CiliumMeshPolicyWriter]
}) {

	if !p.Config.EnableCiliumMesh {
		return
	}

	out.MapOut = bpf.NewMapOut(CiliumMeshPolicyWriter(createWithName(p.Lifecycle, MapName)))

	return
}

var (
	MapName      = "cilium_cilium_mesh_ep_to_policy"
	innerMapName = "cilium_mesh_policy_inner_map"
)

const (
	// MaxEntries represents the maximum number of endpoints in the map
	MaxEntries = 65536
)

type EndpointKey struct{ bpf.EndpointKey }

type CiliumMeshPolicyValue struct{ Fd uint32 }

// createWithName creates a new endpoint policy hash of maps for
// looking up an endpoint's policy map by the endpoint key.
//
// The specified name allows non-standard map paths to be used, for instance
// for testing purposes.
func createWithName(lc cell.Lifecycle, name string) *ciliumMeshPolicyMap {
	innerMapSpec := &ebpf.MapSpec{
		Name:       innerMapName,
		Type:       ebpf.LPMTrie,
		KeySize:    uint32(unsafe.Sizeof(policymap.PolicyKey{})),
		ValueSize:  uint32(unsafe.Sizeof(policymap.PolicyEntry{})),
		MaxEntries: MaxEntries,
	}

	cmpm := ebpf.NewMap(&ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.HashOfMaps,
		KeySize:    uint32(unsafe.Sizeof(EndpointKey{})),
		ValueSize:  uint32(unsafe.Sizeof(CiliumMeshPolicyValue{})),
		MaxEntries: uint32(MaxEntries),
		InnerMap:   innerMapSpec,
		Pinning:    ebpf.PinByName,
	})

	initialized := make(chan struct{})

	cmpms := &ciliumMeshPolicyMap{
		// Buffered so that a call to registerLoader does not block.
		loaderChan:  make(chan types.Loader, 1),
		m:           cmpm,
		initialized: initialized,
	}

	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			go func() {
				loader := <-cmpms.loaderChan
				<-loader.HostDatapathInitialized()
				cmpm.OpenOrCreate()
				close(initialized)
			}()

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			return cmpm.Close()
		},
	})

	return cmpms
}

func (v CiliumMeshPolicyValue) String() string { return fmt.Sprintf("fd=%d", v.Fd) }

func (v *CiliumMeshPolicyValue) New() bpf.MapValue { return &CiliumMeshPolicyValue{} }

// GetValuePtr returns the unsafe value pointer to the Endpoint Policy fd
func (v *CiliumMeshPolicyValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

func (k *EndpointKey) New() bpf.MapKey { return &EndpointKey{} }
