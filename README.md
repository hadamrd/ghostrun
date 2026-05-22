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

Current Linux status:

- `--deny-connect` selects a cgroup/connect4 eBPF backend.
- The backend creates a temporary cgroup, attaches the program, runs the command inside that cgroup, and removes the cgroup afterward.
- The command is created directly inside the temporary cgroup with `UseCgroupFD`, so user code does not run before cgroup membership is applied.
- Denied IPv4 CIDRs are loaded into an eBPF LPM trie map. The connect hook denies destinations matching that map and allows non-matching destinations.
- Denied connect attempts increment an eBPF counter map; Ghostrun reads it after the command exits and reports blocked attempts even if the command handled the failed connect and exited successfully.
- The backend records the most recent denied IPv4 destination, so blocked connect reports include a concrete target such as `127.0.0.1`.
- Filesystem write blocking is still not active on the current Colima sandbox because BPF LSM is not enabled in the active LSM list.

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
