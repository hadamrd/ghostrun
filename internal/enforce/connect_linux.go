//go:build linux

package enforce

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/hadamrd/ghostrun/internal/report"
)

type connectBackend struct{}

func newConnectBackend() backend {
	return connectBackend{}
}

func expectedConnectBackendName() string {
	return "cgroup-connect"
}

func (connectBackend) Name() string {
	return expectedConnectBackendName()
}

func (connectBackend) Run(request Request) (Result, error) {
	cgroupPath := filepath.Join("/sys/fs/cgroup", "ghostrun-"+time.Now().UTC().Format("20060102150405.000000000"))
	if err := os.Mkdir(cgroupPath, 0o755); err != nil {
		return Result{}, fmt.Errorf("create cgroup: %w", err)
	}
	defer os.Remove(cgroupPath)

	objects, err := loadConnectObjects(request.Policy)
	if err != nil {
		return Result{}, err
	}
	defer objects.Close()

	attached, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objects.Program,
	})
	if err != nil {
		return Result{}, fmt.Errorf("attach connect deny program: %w", err)
	}
	defer attached.Close()

	cmd := exec.Command(request.Command[0], request.Command[1:]...)
	if request.Env != nil {
		cmd.Env = request.Env
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("start command: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(fmt.Sprint(cmd.Process.Pid)), 0o644); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return Result{}, fmt.Errorf("join command cgroup: %w", err)
	}
	if request.ReadyFile != "" {
		if err := os.WriteFile(request.ReadyFile, []byte("ready\n"), 0o644); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return Result{}, fmt.Errorf("signal command ready: %w", err)
		}
	}

	err = cmd.Wait()
	exitCode := cmd.ProcessState.ExitCode()
	recorder := report.New()
	status := EnforcementSucceeded
	if exitCode != 0 {
		status = EnforcementBlocked
		recorder.Record(report.Event{
			Kind:     report.EventConnect,
			Decision: report.DecisionWouldBlock,
			Target:   "ipv4-connect",
		})
	}
	result := Result{
		ExitCode: exitCode,
		Command:  request.Command,
		Status:   status,
		Events:   recorder.Events(),
		Summary:  recorder.Summary(),
	}
	if err != nil {
		return result, nil
	}
	return result, nil
}
