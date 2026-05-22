package enforce

import (
	"github.com/hadamrd/ghostrun/internal/policy"
	"github.com/hadamrd/ghostrun/internal/report"
)

type backend interface {
	Name() string
	Run(Request) (Result, error)
}

type unsupportedBackend struct{}

func (unsupportedBackend) Name() string {
	return "unsupported"
}

func (unsupportedBackend) Run(request Request) (Result, error) {
	return unsupportedResult(request), ErrUnsupported
}

func selectBackend(p policy.Policy) backend {
	if len(p.DeniedConnectCIDRs) > 0 {
		return newConnectBackend()
	}
	return unsupportedBackend{}
}

func unsupportedResult(request Request) Result {
	return Result{
		Command: request.Command,
		Status:  EnforcementUnsupported,
		Summary: reportSummary(),
	}
}

func reportSummary() report.Summary {
	return report.New().Summary()
}
