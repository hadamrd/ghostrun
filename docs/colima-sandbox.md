# Colima Linux Sandbox

Colima gives Ghostrun a local Linux kernel for eBPF experiments from macOS.

Verified baseline on 2026-05-22:

| Field | Value |
|---|---|
| OS | Ubuntu 24.04.2 LTS |
| Kernel | 6.8.0-64-generic |
| Arch | aarch64 |
| BTF | `/sys/kernel/btf/vmlinux` exists |
| bpffs | `/sys/fs/bpf` mounted |
| cgroup BPF | `CONFIG_CGROUP_BPF=y` |
| BPF syscall | `CONFIG_BPF_SYSCALL=y` |

Run the sandbox check from macOS:

```bash
colima ssh -- sh /Users/k.majdoub/repos/ghostrun/scripts/check-linux-sandbox.sh
```

Run the Linux test suite from macOS:

```bash
scripts/test-linux.sh
```

That script uses a privileged Docker container so the Linux integration test can create a temporary cgroup, attach the cgroup/connect4 program, run a command inside the cgroup, and prove the command cannot open an IPv4 TCP connection while inside that cgroup.

The connect policy is now CIDR-specific for IPv4: tests deny `127.0.0.0/8` and prove localhost is blocked, then deny `10.0.0.0/8` and prove localhost is allowed. Another test has the child handle the denied connect and exit `0`; Ghostrun still reports `blocked` from the BPF counter map.

The first enforcement target is outbound connect denial with cgroup BPF. Filesystem write blocking likely needs BPF LSM; the current Colima kernel has `CONFIG_BPF_LSM=y`, but `bpf` is not active in `/sys/kernel/security/lsm`.
