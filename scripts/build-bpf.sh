#!/usr/bin/env bash
set -euo pipefail

CLANG=${CLANG:-clang}
OUTPUT=${1:-backend/linux/bpf/tunless_bpf.o}
target_arch=x86
case "$(uname -m)" in
aarch64|arm64) target_arch=arm64 ;;
x86_64|amd64) target_arch=x86 ;;
esac

include_args=()
multiarch=$(gcc -dumpmachine 2>/dev/null || true)
if [[ -n "$multiarch" && -d "/usr/include/$multiarch" ]]; then
	include_args+=("-I/usr/include/$multiarch")
fi

"$CLANG" -O2 -g -target bpf -D"__TARGET_ARCH_$target_arch" \
	"${include_args[@]}" -c backend/linux/bpf/tunless.bpf.c -o "$OUTPUT"

if command -v bpftool >/dev/null && [[ ${BPF_VERIFY:-0} == 1 ]]; then
	verify="/sys/fs/bpf/tunless-verify-$$"
	cleanup() { sudo rm -rf "$verify"; }
	trap cleanup EXIT
	sudo bpftool prog loadall "$OUTPUT" "$verify"
fi
