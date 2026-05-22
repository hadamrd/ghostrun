package enforce

import (
	"errors"

	"github.com/hadamrd/ghostrun/internal/policy"
	"github.com/hadamrd/ghostrun/internal/report"
)

var (
	ErrMissingCommand = errors.New("missing command")
	ErrUnsupported    = errors.New("kernel enforcement is unsupported on this host")
)

type Request struct {
	Policy    policy.Policy
	Command   []string
	Env       []string
	ReadyFile string
}

type Result struct {
	ExitCode int              `json:"exit_code"`
	Summary  report.Summary   `json:"summary"`
	Events   []report.Event   `json:"events"`
	Command  []string         `json:"command"`
	Status   EnforcementState `json:"status"`
}

type EnforcementState string

const (
	EnforcementUnsupported EnforcementState = "unsupported"
	EnforcementSucceeded   EnforcementState = "succeeded"
	EnforcementFailed      EnforcementState = "failed"
	EnforcementBlocked     EnforcementState = "blocked"
)

func Run(request Request) (Result, error) {
	if len(request.Command) == 0 {
		return Result{}, ErrMissingCommand
	}
	return selectBackend(request.Policy).Run(request)
}
