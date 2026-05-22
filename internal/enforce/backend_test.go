package enforce

import (
	"testing"

	"github.com/hadamrd/ghostrun/internal/policy"
)

func TestSelectBackendRequiresConnectPolicy(t *testing.T) {
	backend := selectBackend(policy.Policy{DeniedWritePrefixes: []string{"/etc"}})

	if backend.Name() != "unsupported" {
		t.Fatalf("backend = %q, want unsupported", backend.Name())
	}
}

func TestSelectBackendUsesCgroupConnectWhenConnectPolicyExists(t *testing.T) {
	p, err := policy.New(policy.Options{DeniedConnectCIDRs: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}

	backend := selectBackend(p)

	if backend.Name() != expectedConnectBackendName() {
		t.Fatalf("backend = %q, want %q", backend.Name(), expectedConnectBackendName())
	}
}
