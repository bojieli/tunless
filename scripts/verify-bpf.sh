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
	rm -f -- "$work_dir/tunless_bpf.o"
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

if ! cmp -s "$committed" "$work_dir/tunless_bpf.o"; then
	echo "embedded BPF object differs from a clean clang-14 rebuild" >&2
	sha256sum "$committed" "$work_dir/tunless_bpf.o" >&2
	exit 1
fi

sha256sum "$committed"
