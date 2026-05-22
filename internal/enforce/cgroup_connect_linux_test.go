//go:build linux

package enforce

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

func TestConnect4DenyProgramSpecLoads(t *testing.T) {
	program, err := ebpf.NewProgram(connect4DenyProgramSpec())
	if errors.Is(err, ebpf.ErrNotSupported) {
		t.Skipf("eBPF program loading unsupported: %v", err)
	}
	if err != nil {
		t.Fatalf("load connect4 deny program: %v", err)
	}
	defer program.Close()
}
