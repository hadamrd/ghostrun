package policy

import "testing"

func TestPolicyMatchesDeniedPathPrefixes(t *testing.T) {
	p := Policy{
		DeniedWritePrefixes: []string{"/etc", "/var/lib/prod"},
	}

	for _, path := range []string{"/etc/passwd", "/etc/ssh/sshd_config", "/var/lib/prod/db"} {
		if !p.DeniesWrite(path) {
			t.Fatalf("expected write to %q to be denied", path)
		}
	}

	for _, path := range []string{"/tmp/file", "/var/lib/product-cache"} {
		if p.DeniesWrite(path) {
			t.Fatalf("expected write to %q to be allowed", path)
		}
	}
}

func TestPolicyMatchesDeniedConnectCIDRs(t *testing.T) {
	p, err := New(Options{
		DeniedConnectCIDRs: []string{"10.0.0.0/8", "192.168.10.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, addr := range []string{"10.1.2.3", "192.168.10.42"} {
		if !p.DeniesConnect(addr) {
			t.Fatalf("expected connect to %q to be denied", addr)
		}
	}

	for _, addr := range []string{"172.16.0.1", "192.168.11.42"} {
		if p.DeniesConnect(addr) {
			t.Fatalf("expected connect to %q to be allowed", addr)
		}
	}
}

func TestPolicyRejectsInvalidCIDR(t *testing.T) {
	_, err := New(Options{DeniedConnectCIDRs: []string{"not-a-cidr"}})
	if err == nil {
		t.Fatal("expected invalid CIDR to be rejected")
	}
}
