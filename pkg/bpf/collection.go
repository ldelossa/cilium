// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/cilium/cilium/pkg/maps/callsmap"
)

const globalDataMap = ".rodata.config"

// LoadCollectionSpec loads the eBPF ELF at the given path and parses it into
// a CollectionSpec. This spec is only a blueprint of the contents of the ELF
// and does not represent any live resources that have been loaded into the
// kernel.
//
// This is a wrapper around ebpf.LoadCollectionSpec that parses legacy iproute2
// bpf_elf_map definitions (only used for prog_arrays at the time of writing)
// and assigns tail calls annotated with `__section_tail` macros to their
// intended maps and slots.
func LoadCollectionSpec(path string) (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, err
	}

	if err := removeUnreachableTailcalls(spec); err != nil {
		return nil, err
	}

	if err := iproute2Compat(spec); err != nil {
		return nil, err
	}

	if err := classifyProgramTypes(spec); err != nil {
		return nil, err
	}

	return spec, nil
}

func removeUnreachableTailcalls(spec *ebpf.CollectionSpec) error {
	type TailCall struct {
		referenced bool
		visited    bool
		spec       *ebpf.ProgramSpec
	}

	entrypoints := make([]*ebpf.ProgramSpec, 0)
	tailcalls := make(map[uint32]*TailCall)

	const (
		// Corresponds to CILIUM_MAP_CALLS.
		cilium_calls_map = 2
	)

	for _, prog := range spec.Programs {
		var id, slot uint32
		// Consider any program that doesn't follow the tailcall naming convention
		// x/y to be an entrypoint.
		// Any program that does follow the x/y naming convention but not part
		// of the cilium_calls map is also considered an entrypoint.
		if _, err := fmt.Sscanf(prog.SectionName, "%d/%v", &id, &slot); err != nil || id != cilium_calls_map {
			entrypoints = append(entrypoints, prog)
			continue
		}

		if tailcalls[slot] != nil {
			return fmt.Errorf("duplicate tail call index %d", slot)
		}

		tailcalls[slot] = &TailCall{
			spec: prog,
		}
	}

	// Discover all tailcalls that are reachable from the given program.
	visit := func(prog *ebpf.ProgramSpec, tailcalls map[uint32]*TailCall) error {
		// We look back from any tailcall, so we expect there to always be 3 instructions ahead of any tail call instr.
		for i := 3; i < len(prog.Instructions); i++ {
			// The `tail_call_static` C function is always used to call tail calls when
			// the map index is known at compile time.
			// Due to inline ASM this generates the following instructions:
			//   Mov R1, Rx
			//   Mov R2, <map>
			//   Mov R3, <index>
			//   call tail_call

			// Find the tail call instruction.
			inst := prog.Instructions[i]
			if !inst.IsBuiltinCall() || inst.Constant != int64(asm.FnTailCall) {
				continue
			}

			// Check that the previous instruction is a mov of the tail call index.
			movIdx := prog.Instructions[i-1]
			if movIdx.OpCode.ALUOp() != asm.Mov || movIdx.Dst != asm.R3 {
				continue
			}

			// Check that the instruction before that is the load of the tail call map.
			movR2 := prog.Instructions[i-2]
			if movR2.OpCode != asm.LoadImmOp(asm.DWord) || movR2.Src != asm.PseudoMapFD {
				continue
			}

			ref := movR2.Reference()

			// Ignore static tail calls made to maps that are not the calls map
			if !strings.Contains(ref, callsmap.MapName) || strings.Contains(ref, callsmap.CustomCallsMapName) {
				log.Debugf("program '%s'/'%s', found tail call at %d, reference '%s', not a calls map, skipping",
					prog.SectionName, prog.Name, i, ref)
				continue
			}

			tc := tailcalls[uint32(movIdx.Constant)]
			if tc == nil {
				return fmt.Errorf(
					"program '%s'/'%s' executes tail call to unknown index '%d' at %d, potential missed tailcall",
					prog.SectionName,
					prog.Name,
					movIdx.Constant,
					i,
				)
			}

			tc.referenced = true
		}

		return nil
	}

	// Discover all tailcalls that are reachable from the entrypoints.
	for _, prog := range entrypoints {
		if err := visit(prog, tailcalls); err != nil {
			return err
		}
	}

	// Keep visiting tailcalls until no more are discovered.
reset:
	for _, tailcall := range tailcalls {
		// If a tailcall is referenced by an entrypoint or another tailcall we should visit it
		if tailcall.referenced && !tailcall.visited {
			if err := visit(tailcall.spec, tailcalls); err != nil {
				return err
			}
			tailcall.visited = true

			// Visiting this tail call might have caused tail calls earlier in the list to become referenced, but this
			// loop already skipped them. So reset the loop. If we already visited a tailcall we will ignore them anyway.
			goto reset
		}
	}

	// Remove all tailcalls that are not referenced.
	for _, tailcall := range tailcalls {
		if !tailcall.referenced {
			log.Debugf("section '%s' / prog '%s', unreferenced, deleting", tailcall.spec.SectionName, tailcall.spec.Name)
			delete(spec.Programs, tailcall.spec.Name)
		}
	}

	return nil
}

// iproute2Compat parses the Extra field of each MapSpec in the CollectionSpec.
// This extra portion is present in legacy bpf_elf_map definitions and must be
// handled before the map can be loaded into the kernel.
//
// It parses the ELF section name of each ProgramSpec to extract any map/slot
// mappings for prog arrays used as tail call maps. The spec's programs are then
// inserted into the appropriate map and slot.
//
// TODO(timo): Remove when bpf_elf_map map definitions are no longer used after
// moving away from iproute2+libbpf.
func iproute2Compat(spec *ebpf.CollectionSpec) error {
	// Parse legacy iproute2 u32 id and pinning fields.
	maps := make(map[uint32]*ebpf.MapSpec)
	for _, m := range spec.Maps {
		if m.Extra != nil && m.Extra.Len() > 0 {
			tail := struct {
				ID      uint32
				Pinning uint32
				_       uint64 // inner_id + inner_idx
			}{}
			if err := binary.Read(m.Extra, spec.ByteOrder, &tail); err != nil {
				return fmt.Errorf("reading iproute2 map definition: %w", err)
			}

			m.Pinning = ebpf.PinType(tail.Pinning)

			// Index maps by their iproute2 .id if any, so X/Y ELF section names can
			// be matched against them.
			if tail.ID != 0 {
				if m2 := maps[tail.ID]; m2 != nil {
					return fmt.Errorf("maps %s and %s have duplicate iproute2 map ID %d", m.Name, m2.Name, tail.ID)
				}
				maps[tail.ID] = m
			}
		}
	}

	for n, p := range spec.Programs {
		// Parse the program's section name to determine which prog array and slot it
		// needs to be inserted into. For example, a section name of '2/14' means to
		// insert into the map with the .id field of 2 at index 14.
		// Uses %v to automatically detect slot's mathematical base, since they can
		// appear either in dec or hex, e.g. 1/0x0515.
		var id, slot uint32
		if _, err := fmt.Sscanf(p.SectionName, "%d/%v", &id, &slot); err == nil {
			// Assign the prog name and slot to the map with the iproute2 .id obtained
			// from the program's section name. The lib will load the ProgramSpecs
			// and insert the corresponding Programs into the prog array at load time.
			m := maps[id]
			if m == nil {
				return fmt.Errorf("no map with iproute2 map .id %d", id)
			}
			m.Contents = append(maps[id].Contents, ebpf.MapKV{Key: slot, Value: n})
		}
	}

	return nil
}

// LoadAndAssign loads spec into the kernel and assigns the requested eBPF
// objects to the given object. It is a wrapper around [LoadCollection]. See its
// documentation for more details on the loading process.
func LoadAndAssign(to any, spec *ebpf.CollectionSpec, opts *CollectionOptions) (func() error, error) {
	log.Debug("Loading Collection into kernel")

	coll, commit, err := LoadCollection(spec, opts)
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		if _, err := fmt.Fprintf(os.Stderr, "Verifier error: %s\nVerifier log: %+v\n", err, ve); err != nil {
			return nil, fmt.Errorf("writing verifier log to stderr: %w", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("loading eBPF collection into the kernel: %w", err)
	}

	if err := coll.Assign(to); err != nil {
		return nil, fmt.Errorf("assigning eBPF objects to %T: %w", to, err)
	}

	return commit, nil
}

type CollectionOptions struct {
	ebpf.CollectionOptions

	// Replacements for constants defined using the DECLARE_CONFIG macros.
	Constants map[string]uint64

	// Maps to be renamed during loading. Key is the key in CollectionSpec.Maps,
	// value is the new name.
	MapRenames map[string]string
}

// LoadCollection loads the given spec into the kernel with the specified opts.
// Returns a function that must be called after the Collection's entrypoints are
// attached to their respective kernel hooks. This function commits pending map
// pins to the bpf file system for maps that were found to be incompatible with
// their pinned counterparts, or for maps with certain flags that modify the
// default pinning behaviour.
//
// When attaching multiple programs from the same ELF in a loop, the returned
// function should only be run after all entrypoints have been attached. For
// example, attach both bpf_host.c:cil_to_netdev and cil_from_netdev before
// invoking the returned function, otherwise missing tail calls will occur.
//
// The value given in ProgramOptions.LogSize is used as the starting point for
// sizing the verifier's log buffer and defaults to 4MiB. On each retry, the log
// buffer quadruples in size, for a total of 5 attempts. If that proves
// insufficient, a truncated ebpf.VerifierError is returned.
//
// Any maps marked as pinned in the spec are automatically loaded from the path
// given in opts.Maps.PinPath and will be used instead of creating new ones.
func LoadCollection(spec *ebpf.CollectionSpec, opts *CollectionOptions) (*ebpf.Collection, func() error, error) {
	if spec == nil {
		return nil, nil, errors.New("can't load nil CollectionSpec")
	}

	if opts == nil {
		opts = &CollectionOptions{}
	}

	// Copy spec so the modifications below don't affect the input parameter,
	// allowing the spec to be safely re-used by the caller.
	spec = spec.Copy()

	if err := renameMaps(spec, opts.MapRenames); err != nil {
		return nil, nil, err
	}

	if err := inlineGlobalData(spec, opts.Constants); err != nil {
		return nil, nil, fmt.Errorf("inlining global data: %w", err)
	}

	// Find and strip all CILIUM_PIN_REPLACE pinning flags before creating the
	// Collection. ebpf-go will reject maps with pins it doesn't recognize.
	toReplace := consumePinReplace(spec)

	// Attempt to load the Collection.
	coll, err := ebpf.NewCollectionWithOptions(spec, opts.CollectionOptions)

	// Collect key names of maps that are not compatible with their pinned
	// counterparts and remove their pinning flags.
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		var incompatible []string
		incompatible, err = incompatibleMaps(spec, opts.CollectionOptions)
		if err != nil {
			return nil, nil, fmt.Errorf("finding incompatible maps: %w", err)
		}
		toReplace = append(toReplace, incompatible...)

		// Retry loading the Collection with necessary pinning flags removed.
		coll, err = ebpf.NewCollectionWithOptions(spec, opts.CollectionOptions)
	}

	if err != nil {
		return nil, nil, err
	}

	// Collect Maps that need their bpffs pins replaced. Pull out Map objects
	// before returning the Collection, since commit() still needs to work when
	// the Map is removed from the Collection, e.g. by [ebpf.Collection.Assign].
	pins, err := mapsToReplace(toReplace, spec, coll, opts.CollectionOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("collecting map pins to replace: %w", err)
	}

	// Load successful, return a function that must be invoked after attaching the
	// Collection's entrypoint programs to their respective hooks.
	commit := func() error {
		return commitMapPins(pins)
	}
	return coll, commit, nil
}

// classifyProgramTypes sets the type of ProgramSpecs which the library cannot
// automatically classify due to them being in unrecognized ELF sections. Only
// programs of type UnspecifiedProgram are modified.
//
// Cilium uses the iproute2 X/Y section name convention for assigning programs
// to prog array slots, which is also not supported.
//
// TODO(timo): When iproute2 is no longer used for any loading, tail call progs
// can receive proper prefixes.
func classifyProgramTypes(spec *ebpf.CollectionSpec) error {
	var t ebpf.ProgramType
	for name, p := range spec.Programs {
		// If the loader was able to classify a program, go with the verdict.
		if p.Type != ebpf.UnspecifiedProgram {
			t = p.Type
			break
		}

		// Assign a program type based on the first recognized function name.
		switch name {
		// bpf_xdp.c
		case "cil_xdp_entry":
			t = ebpf.XDP
		case
			// bpf_lxc.c
			"cil_from_container", "cil_to_container",
			// bpf_host.c
			"cil_from_netdev", "cil_from_host", "cil_to_netdev", "cil_to_host",
			// bpf_network.c
			"cil_from_network",
			// bpf_overlay.c
			"cil_to_overlay", "cil_from_overlay",
			// bpf_wireguard.c
			"cil_to_wireguard":
			t = ebpf.SchedCLS
		default:
			continue
		}

		break
	}

	for _, p := range spec.Programs {
		if p.Type == ebpf.UnspecifiedProgram {
			p.Type = t
		}
	}

	if t == ebpf.UnspecifiedProgram {
		return errors.New("unable to classify program types")
	}

	return nil
}

// renameMaps applies renames to coll.
func renameMaps(coll *ebpf.CollectionSpec, renames map[string]string) error {
	for name, rename := range renames {
		mapSpec := coll.Maps[name]
		if mapSpec == nil {
			return fmt.Errorf("unknown map %q: can't rename to %q", name, rename)
		}

		mapSpec.Name = rename
	}

	return nil
}

// Must match the prefix used by the CONFIG macro in static_data.h.
const constantPrefix = "__config_"

// inlineGlobalData replaces all map loads from a global data section with
// immediate dword loads, effectively performing those map lookups in the
// loader. This is done for compatibility with kernels that don't support
// global data maps yet.
//
// overrides allow changing the value of the inlined global data.
//
// This code interacts with the DECLARE_CONFIG macro in the BPF C code base.
func inlineGlobalData(spec *ebpf.CollectionSpec, overrides map[string]uint64) error {
	offsets, values, err := globalData(spec)
	if err != nil {
		return err
	}
	if offsets == nil {
		// Most likely all references to global data have been compiled
		// out.
		return nil
	}

	for name, value := range overrides {
		constName := constantPrefix + name

		if _, ok := values[constName]; !ok {
			return fmt.Errorf("can't override non-existent constant %q", name)
		}

		values[constName] = value
	}

	for _, prog := range spec.Programs {
		for i, ins := range prog.Instructions {
			if !ins.IsLoadFromMap() || ins.Src != asm.PseudoMapValue {
				continue
			}

			if ins.Reference() != globalDataMap {
				return fmt.Errorf("global constants must be in %s, but found reference to %s", globalDataMap, ins.Reference())
			}

			// Get the offset of the read within the target map,
			// stored in the 32 most-significant bits of Constant.
			// Equivalent to Instruction.mapOffset().
			off := uint32(uint64(ins.Constant) >> 32)

			// Look up the value of the variable stored at the Datasec offset pointed
			// at by the instruction.
			v, ok := offsets[off]
			if !ok {
				return fmt.Errorf("no global constant found in %s at offset %d", globalDataMap, off)
			}

			// Replace the map load with an immediate load. Must be a dword load
			// to match the instruction width of a map load.
			r := asm.LoadImm(ins.Dst, int64(values[v]), asm.DWord)

			// Preserve metadata of the original instruction. Otherwise, a program's
			// first instruction could be stripped of its func_info or Symbol
			// (function start) annotations.
			r.Metadata = ins.Metadata

			prog.Instructions[i] = r
		}
	}

	return nil
}

// globalData gets the contents of the first entry in the global data map
// and removes it from the spec to prevent it from being created in the kernel.
func globalData(spec *ebpf.CollectionSpec) (offsets map[uint32]string, values map[string]uint64, _ error) {
	dm := spec.Maps[globalDataMap]
	if dm == nil {
		return nil, nil, nil
	}

	if dl := len(dm.Contents); dl != 1 {
		return nil, nil, fmt.Errorf("expected one key in %s, found %d", globalDataMap, dl)
	}

	ds, ok := dm.Value.(*btf.Datasec)
	if !ok {
		return nil, nil, fmt.Errorf("no BTF datasec found for %s", globalDataMap)
	}

	data, ok := (dm.Contents[0].Value).([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("expected %s value to be a byte slice, got: %T",
			globalDataMap, dm.Contents[0].Value)
	}

	// Slice up the binary contents of the global data map according to the
	// variables described in its Datasec.
	values = make(map[string]uint64)
	offsets = make(map[uint32]string)
	buf := make([]byte, 8)
	for _, vsi := range ds.Vars {
		v, ok := vsi.Type.(*btf.Var)
		if !ok {
			// VarSecInfo.Type can be a Func.
			continue
		}

		if _, ok := offsets[vsi.Offset]; ok {
			return nil, nil, fmt.Errorf("duplicate VarSecInfo for offset %d", vsi.Offset)
		}

		copy(buf, data[vsi.Offset:vsi.Offset+vsi.Size])

		var value uint64
		switch vsi.Size {
		case 8:
			value = spec.ByteOrder.Uint64(buf)
		case 4:
			value = uint64(spec.ByteOrder.Uint32(buf))
		case 2:
			value = uint64(spec.ByteOrder.Uint16(buf))
		case 1:
			value = uint64(buf[0])
		default:
			return nil, nil, fmt.Errorf("invalid variable size %d", vsi.Size)
		}

		// Emit the variable's value by its offset in the datasec.
		offsets[vsi.Offset] = v.Name
		values[v.Name] = value
	}

	// Remove the map definition to skip loading it into the kernel.
	delete(spec.Maps, globalDataMap)

	return offsets, values, nil
}
