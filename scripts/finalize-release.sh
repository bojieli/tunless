#!/usr/bin/env bash
set -euo pipefail

output=${1:-dist}
[[ -d "$output" ]] || {
	echo "release directory does not exist: $output" >&2
	exit 2
}
output=$(cd -- "$output" && pwd -P)
manifest=$output/SHA256SUMS
checksum_file=$(mktemp "$output/.tunless-sha256sums.XXXXXX")
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	rm -f -- "$checksum_file"
	exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

(
	cd -- "$output"
	while IFS= read -r -d '' artifact; do
		sha256sum "$artifact"
	done < <(find . -maxdepth 1 -type f ! -name SHA256SUMS ! -name '.tunless-sha256sums.*' -print0 | sort -z)
) | sed 's#  \./#  #' >"$checksum_file"
[[ -s "$checksum_file" ]] || {
	echo "release directory contains no artifacts: $output" >&2
	exit 1
}
if [[ -d "$manifest" && ! -L "$manifest" ]]; then
	echo "release checksum path is a directory: $manifest" >&2
	exit 1
fi
# Never let mv interpret a symlink-to-directory as a destination directory.
if [[ -L "$manifest" ]]; then rm -f -- "$manifest"; fi
mv -f -- "$checksum_file" "$manifest"
(cd -- "$output" && sha256sum --check SHA256SUMS)
