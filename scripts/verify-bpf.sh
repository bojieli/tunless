#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

committed=backend/linux/bpf/tunless_bpf.o
[[ -f "$committed" ]] || {
	echo "embedded BPF object is missing: $committed" >&2
	exit 1
}

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tunless-bpf-repro.XXXXXX")
cleanup() {
	trap - EXIT HUP INT TERM
	rm -f -- "$work_dir/tunless_bpf.o" "$work_dir/committed.normalized.o" \
		"$work_dir/rebuilt.normalized.o"
	rmdir "$work_dir" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

CLANG=${CLANG:-clang-14}
command -v "$CLANG" >/dev/null 2>&1 || {
	echo "$CLANG is required for the reproducible BPF check" >&2
	exit 2
}

BPF_TARGET_ARCH=${BPF_TARGET_ARCH:-x86} CLANG="$CLANG" \
	./scripts/build-bpf.sh "$work_dir/tunless_bpf.o"

if cmp -s "$committed" "$work_dir/tunless_bpf.o"; then
	echo "bpf_full_elf=byte-identical"
else
	objcopy=${LLVM_OBJCOPY:-}
	if [[ -z "$objcopy" ]]; then
		for candidate in llvm-objcopy-14 llvm-objcopy; do
			if command -v "$candidate" >/dev/null 2>&1; then objcopy=$candidate; break; fi
		done
	fi
	[[ -n "$objcopy" ]] || {
		echo "full BPF ELF differs and llvm-objcopy is required to compare program/map content" >&2
		sha256sum "$committed" "$work_dir/tunless_bpf.o" >&2
		exit 1
	}
	cp "$committed" "$work_dir/committed.normalized.o"
	cp "$work_dir/tunless_bpf.o" "$work_dir/rebuilt.normalized.o"
	for object in "$work_dir/committed.normalized.o" "$work_dir/rebuilt.normalized.o"; do
		"$objcopy" --strip-debug --remove-section=.BTF --remove-section=.BTF.ext "$object"
	done
	if ! cmp -s "$work_dir/committed.normalized.o" "$work_dir/rebuilt.normalized.o"; then
		echo "embedded BPF program/map content differs from the clang-14 rebuild" >&2
		sha256sum "$committed" "$work_dir/tunless_bpf.o" \
			"$work_dir/committed.normalized.o" "$work_dir/rebuilt.normalized.o" >&2
		exit 1
	fi
	echo "bpf_full_elf=metadata-differs bpf_program_maps=byte-identical"
fi

sha256sum "$committed"
