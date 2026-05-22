//go:build linux

package enforce

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/hadamrd/ghostrun/internal/policy"
	"golang.org/x/sys/unix"
)

func connect4DenyProgramSpec() *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{
		Name:       "ghostrun_deny4",
		Type:       ebpf.CGroupSockAddr,
		AttachType: ebpf.AttachCGroupInet4Connect,
		License:    "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Reg(asm.R6, asm.R1),
			asm.LoadMapPtr(asm.R1, 0).WithReference("deny_cidrs"),
			asm.Mov.Reg(asm.R2, asm.R10),
			asm.Add.Imm(asm.R2, -8),
			asm.StoreImm(asm.R2, 0, 32, asm.Word),
			asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),
			asm.StoreMem(asm.R2, 4, asm.R3, asm.Word),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "allow"),
			asm.LoadMapPtr(asm.R1, 0).WithReference("blocked_connects"),
			asm.Mov.Reg(asm.R2, asm.R10),
			asm.Add.Imm(asm.R2, -12),
			asm.StoreImm(asm.R2, 0, 0, asm.Word),
			asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "deny"),
			asm.Mov.Imm(asm.R1, 1),
			asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return().WithSymbol("deny"),
			asm.LoadImm(asm.R0, 1, asm.DWord).WithSymbol("allow"),
			asm.Return(),
		},
	}
}

type connectObjects struct {
	Program         *ebpf.Program `ebpf:"ghostrun_deny4"`
	CIDRs           *ebpf.Map     `ebpf:"deny_cidrs"`
	BlockedConnects *ebpf.Map     `ebpf:"blocked_connects"`
}

func (o connectObjects) Close() {
	if o.Program != nil {
		o.Program.Close()
	}
	if o.CIDRs != nil {
		o.CIDRs.Close()
	}
	if o.BlockedConnects != nil {
		o.BlockedConnects.Close()
	}
}

type lpmTrieKey struct {
	PrefixLen uint32
	Addr      [4]byte
}

func loadConnectObjects(p policy.Policy) (connectObjects, error) {
	contents, err := connectCIDRContents(p)
	if err != nil {
		return connectObjects{}, err
	}
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"deny_cidrs": {
				Type:       ebpf.LPMTrie,
				KeySize:    8,
				ValueSize:  1,
				MaxEntries: uint32(max(1, len(contents))),
				Flags:      unix.BPF_F_NO_PREALLOC,
				Contents:   contents,
			},
			"blocked_connects": {
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  8,
				MaxEntries: 1,
			},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"ghostrun_deny4": connect4DenyProgramSpec(),
		},
	}
	var objects connectObjects
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return connectObjects{}, fmt.Errorf("load connect eBPF objects: %w", err)
	}
	return objects, nil
}

func connectCIDRContents(p policy.Policy) ([]ebpf.MapKV, error) {
	prefixes := p.ConnectPrefixes()
	contents := make([]ebpf.MapKV, 0, len(prefixes))
	for _, prefix := range prefixes {
		addr := prefix.Addr()
		if !addr.Is4() {
			continue
		}
		ones := prefix.Bits()
		if ones < 0 || ones > 32 {
			return nil, fmt.Errorf("invalid IPv4 prefix length %d", ones)
		}
		contents = append(contents, ebpf.MapKV{
			Key: lpmTrieKey{
				PrefixLen: uint32(ones),
				Addr:      addr.As4(),
			},
			Value: uint8(1),
		})
	}
	if len(contents) == 0 {
		return nil, fmt.Errorf("at least one IPv4 deny CIDR is required")
	}
	return contents, nil
}

func (o connectObjects) BlockedConnectCount() (uint64, error) {
	var count uint64
	if o.BlockedConnects == nil {
		return 0, nil
	}
	if err := o.BlockedConnects.Lookup(uint32(0), &count); err != nil {
		return 0, fmt.Errorf("read blocked connect count: %w", err)
	}
	return count, nil
}
