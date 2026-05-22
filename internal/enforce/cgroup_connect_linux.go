//go:build linux

package enforce

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func connect4DenyProgramSpec() *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{
		Name:       "ghostrun_deny4",
		Type:       ebpf.CGroupSockAddr,
		AttachType: ebpf.AttachCGroupInet4Connect,
		License:    "MIT",
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
	}
}
