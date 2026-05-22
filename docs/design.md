# ghostrun Design

## Goal

Provide an external dry-run mode for command-line tools that did not implement dry-run themselves.

## v0.1 Behavior

`ghostrun` runs a command under an explicit deny policy. If the command attempts a denied filesystem or network action, the action should be blocked and reported. The tool should never claim protection when the kernel enforcer is unavailable.

## Architecture

- `cmd/ghostrun`: CLI parsing, safety checks, output mode.
- `internal/policy`: portable policy model and matching semantics.
- `internal/report`: portable event recorder and summary model.
- future `internal/enforce`: Linux-only eBPF enforcement boundary.
- `internal/enforce`: backend selection plus Linux-only cgroup/connect program scaffolding.

## Enforcement Direction

The planned Linux implementation should prefer eBPF LSM hooks where available. Policy should be loaded into BPF maps and scoped to a target process or cgroup. Userspace should own process launch, map population, event collection, and final report generation.

The first working kernel-facing slice is cgroup/connect4: Ghostrun can build and load a minimal program spec in the Colima Linux sandbox, attach it to a temporary cgroup, start a command directly inside that cgroup via `UseCgroupFD`, and block that command from opening an IPv4 TCP connection.

The current Linux backend is command-scoped and CIDR-scoped for IPv4. `--deny-connect` prefixes are loaded into an eBPF LPM trie map, and the cgroup/connect4 program denies only destinations matching that map. Denied attempts increment a BPF counter map, which userspace reads after the command exits to classify the run and build the blocked-connect report.

## Non-Goals

- No transparent write redirection in v0.1.
- No fake success for denied operations in v0.1.
- No global host policy mode.
- No silent operation: the tool must be explicit about unsupported kernels or missing privileges.
