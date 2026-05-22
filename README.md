# ghostrun

`ghostrun` is an experimental Linux tool for externally dry-running unsafe commands.

The goal is to run unmodified binaries under a policy that blocks selected side effects and reports what the command would have done. The first target is eBPF-backed enforcement for filesystem writes and outbound network connections.

## Status

Early scaffold. The policy model, report model, and CLI safety checks exist. Kernel enforcement is not wired yet, and the CLI refuses to pretend otherwise.

## Target UX

```bash
ghostrun --deny-write /etc --deny-connect 10.0.0.0/8 -- ./deploy.sh
ghostrun --json --deny-write /var/lib/prod -- ./cleanup
```

## v0.1 Scope

- Linux-only enforcement.
- Explicit deny policies for write path prefixes.
- Explicit deny policies for outbound CIDRs.
- Report blocked side effects.
- Refuse to run without a policy.

Transparent write redirection and fake-success shadow mode are intentionally out of scope for v0.1.

## Development

```bash
go test ./...
go run ./cmd/ghostrun --deny-write /etc -- echo hello
```

On non-Linux hosts, development focuses on policy parsing, reporting, CLI behavior, and documentation.

Linux/eBPF checks can run through Colima-backed Docker:

```bash
scripts/test-linux.sh
```
