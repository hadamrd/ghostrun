package main

import (
	"bytes"
	"testing"
)

func TestParseRequiresCommand(t *testing.T) {
	_, err := parseArgs([]string{"--deny-write", "/etc"})
	if err == nil {
		t.Fatal("expected missing command to fail")
	}
}

func TestParsePolicyFlagsAndCommand(t *testing.T) {
	cfg, err := parseArgs([]string{
		"--deny-write", "/etc",
		"--deny-connect", "10.0.0.0/8",
		"--json",
		"--",
		"echo", "hello",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Policy.DeniedWritePrefixes) != 1 || cfg.Policy.DeniedWritePrefixes[0] != "/etc" {
		t.Fatalf("unexpected denied writes: %#v", cfg.Policy.DeniedWritePrefixes)
	}
	if len(cfg.Policy.DeniedConnectCIDRs) != 1 || cfg.Policy.DeniedConnectCIDRs[0] != "10.0.0.0/8" {
		t.Fatalf("unexpected denied connects: %#v", cfg.Policy.DeniedConnectCIDRs)
	}
	if !cfg.JSON {
		t.Fatal("expected JSON output to be enabled")
	}
	if len(cfg.Command) != 2 || cfg.Command[0] != "echo" || cfg.Command[1] != "hello" {
		t.Fatalf("unexpected command: %#v", cfg.Command)
	}
}

func TestRunRefusesWithoutPolicy(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--", "echo", "hello"}, &stdout, &stderr)

	if code == 0 {
		t.Fatal("expected non-zero exit without policy")
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Fatal("expected safety error on stderr")
	}
}

func TestRunReportsUnsupportedBackendAsNonZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--json", "--deny-write", "/etc", "--", "echo", "hello"}, &stdout, &stderr)

	if code == 0 {
		t.Fatal("expected non-zero exit with unsupported backend")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty for json output", stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"status":"unsupported"`)) {
		t.Fatalf("stdout = %q, want unsupported status", stdout.String())
	}
}
