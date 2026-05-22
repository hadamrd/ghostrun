//go:build linux

package enforce

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/hadamrd/ghostrun/internal/policy"
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

func TestConnect4DenyProgramBlocksChildDial(t *testing.T) {
	if os.Getenv("GHOSTRUN_CONNECT_CHILD") == "1" {
		runConnectChild(t)
		return
	}
	if os.Getenv("GHOSTRUN_INTEGRATION") != "1" {
		t.Skip("set GHOSTRUN_INTEGRATION=1 to run cgroup attach integration test")
	}
	if os.Geteuid() != 0 {
		t.Skip("cgroup attach integration test requires root")
	}

	cgroupPath := filepath.Join("/sys/fs/cgroup", "ghostrun-test-"+time.Now().UTC().Format("20060102150405.000000000"))
	if err := os.Mkdir(cgroupPath, 0o755); err != nil {
		t.Fatalf("create test cgroup: %v", err)
	}
	defer os.Remove(cgroupPath)

	program, err := ebpf.NewProgram(connect4DenyProgramSpec())
	if err != nil {
		t.Fatalf("load connect4 deny program: %v", err)
	}
	defer program.Close()

	attached, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: program,
	})
	if err != nil {
		t.Fatalf("attach cgroup program: %v", err)
	}
	defer attached.Close()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	cmd := exec.Command(os.Args[0], "-test.run", "^TestConnect4DenyProgramBlocksChildDial$")
	cmd.Env = append(os.Environ(),
		"GHOSTRUN_CONNECT_CHILD=1",
		"GHOSTRUN_TEST_CGROUP="+cgroupPath,
		"GHOSTRUN_TEST_ADDR="+listener.Addr().String(),
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child did not observe denied connect: %v\n%s", err, output)
	}
}

func runConnectChild(t *testing.T) {
	cgroupPath := os.Getenv("GHOSTRUN_TEST_CGROUP")
	addr := os.Getenv("GHOSTRUN_TEST_ADDR")
	if cgroupPath == "" || addr == "" {
		t.Fatal("missing child test environment")
	}
	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(fmt.Sprint(os.Getpid())), 0o644); err != nil {
		t.Fatalf("join test cgroup: %v", err)
	}
	conn, err := net.DialTimeout("tcp4", addr, time.Second)
	if err == nil {
		conn.Close()
		t.Fatalf("dial to %s succeeded, want denied connect", addr)
	}
}

func TestConnectBackendRunBlocksCommandConnect(t *testing.T) {
	if os.Getenv("GHOSTRUN_BACKEND_CHILD") == "1" {
		runBackendChild(t)
		return
	}
	if os.Getenv("GHOSTRUN_INTEGRATION") != "1" {
		t.Skip("set GHOSTRUN_INTEGRATION=1 to run cgroup backend integration test")
	}
	if os.Geteuid() != 0 {
		t.Skip("cgroup backend integration test requires root")
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	readyFile := filepath.Join(t.TempDir(), "ready")
	p, err := policy.New(policy.Options{DeniedConnectCIDRs: []string{"127.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Run(Request{
		Policy: p,
		Command: []string{
			os.Args[0],
			"-test.run", "^TestConnectBackendRunBlocksCommandConnect$",
		},
		Env: append(os.Environ(),
			"GHOSTRUN_BACKEND_CHILD=1",
			"GHOSTRUN_TEST_ADDR="+listener.Addr().String(),
			"GHOSTRUN_READY_FILE="+readyFile,
		),
		ReadyFile: readyFile,
	})
	if err != nil {
		t.Fatalf("run command with connect backend: %v", err)
	}
	if result.Status != EnforcementBlocked {
		t.Fatalf("status = %q, want %q", result.Status, EnforcementBlocked)
	}
	if result.ExitCode == 0 {
		t.Fatalf("exit code = 0, want failed child command")
	}
	if result.Summary.WouldBlock == 0 {
		t.Fatalf("expected blocked summary, got %#v", result.Summary)
	}
}

func TestConnectBackendRunAllowsNonNetworkCommand(t *testing.T) {
	if os.Getenv("GHOSTRUN_INTEGRATION") != "1" {
		t.Skip("set GHOSTRUN_INTEGRATION=1 to run cgroup backend integration test")
	}
	if os.Geteuid() != 0 {
		t.Skip("cgroup backend integration test requires root")
	}

	p, err := policy.New(policy.Options{DeniedConnectCIDRs: []string{"127.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Run(Request{
		Policy:  p,
		Command: []string{"/bin/sh", "-c", "exit 0"},
	})
	if err != nil {
		t.Fatalf("run non-network command: %v", err)
	}
	if result.Status != EnforcementSucceeded {
		t.Fatalf("status = %q, want %q", result.Status, EnforcementSucceeded)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", result.ExitCode)
	}
	if result.Summary.WouldBlock != 0 {
		t.Fatalf("blocked summary = %#v, want no blocked events", result.Summary)
	}
}

func runBackendChild(t *testing.T) {
	readyFile := os.Getenv("GHOSTRUN_READY_FILE")
	addr := os.Getenv("GHOSTRUN_TEST_ADDR")
	if readyFile == "" || addr == "" {
		t.Fatal("missing backend child test environment")
	}
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(readyFile); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn, err := net.DialTimeout("tcp4", addr, time.Second)
	if err == nil {
		conn.Close()
		t.Fatalf("dial to %s succeeded, want denied connect", addr)
	}
	os.Exit(42)
}
