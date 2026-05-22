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

The first enforcement target is outbound connect denial with cgroup BPF. Filesystem write blocking likely needs BPF LSM; the current Colima kernel has `CONFIG_BPF_LSM=y`, but `bpf` is not active in `/sys/kernel/security/lsm`.
