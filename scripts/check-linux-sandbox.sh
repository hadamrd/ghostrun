#!/bin/sh
set -eu

failures=0

check_file() {
	name="$1"
	path="$2"
	if [ -e "$path" ]; then
		printf 'ok: %s (%s)\n' "$name" "$path"
	else
		printf 'missing: %s (%s)\n' "$name" "$path"
		failures=$((failures + 1))
	fi
}

check_dir() {
	name="$1"
	path="$2"
	if [ -d "$path" ]; then
		printf 'ok: %s (%s)\n' "$name" "$path"
	else
		printf 'missing: %s (%s)\n' "$name" "$path"
		failures=$((failures + 1))
	fi
}

printf 'kernel: '
uname -a

check_dir "bpffs" /sys/fs/bpf
check_file "kernel BTF" /sys/kernel/btf/vmlinux
check_dir "tracefs" /sys/kernel/tracing

if [ -r /boot/config-"$(uname -r)" ]; then
	if grep -q '^CONFIG_CGROUP_BPF=y' /boot/config-"$(uname -r)"; then
		printf 'ok: CONFIG_CGROUP_BPF=y\n'
	else
		printf 'missing: CONFIG_CGROUP_BPF=y\n'
		failures=$((failures + 1))
	fi
	if grep -q '^CONFIG_BPF_SYSCALL=y' /boot/config-"$(uname -r)"; then
		printf 'ok: CONFIG_BPF_SYSCALL=y\n'
	else
		printf 'missing: CONFIG_BPF_SYSCALL=y\n'
		failures=$((failures + 1))
	fi
else
	printf 'warn: kernel config not readable at /boot/config-%s\n' "$(uname -r)"
fi

if [ -r /sys/kernel/security/lsm ]; then
	printf 'active_lsms: %s\n' "$(cat /sys/kernel/security/lsm)"
else
	printf 'warn: active LSM list not readable\n'
fi

exit "$failures"
