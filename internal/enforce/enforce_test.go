package enforce

import (
	"errors"
	"testing"

	"github.com/hadamrd/ghostrun/internal/policy"
)

func TestRunRejectsUnsupportedBackend(t *testing.T) {
	_, err := Run(Request{
		Policy:  policy.Policy{DeniedWritePrefixes: []string{"/etc"}},
		Command: []string{"echo", "hello"},
	})

	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
}

func TestRunRequiresCommand(t *testing.T) {
	_, err := Run(Request{Policy: policy.Policy{DeniedWritePrefixes: []string{"/etc"}}})

	if !errors.Is(err, ErrMissingCommand) {
		t.Fatalf("error = %v, want ErrMissingCommand", err)
	}
}
