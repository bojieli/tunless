#!/usr/bin/env bash
set -euo pipefail

output=${1:-dist}
[[ -d "$output" ]] || {
	echo "release directory does not exist: $output" >&2
	exit 2
}

find "$output" -maxdepth 1 -type f ! -name SHA256SUMS -print0 |
	sort -z | xargs -0 sha256sum | sed "s#  $output/#  #" >"$output/SHA256SUMS"
(cd "$output" && sha256sum --check SHA256SUMS)
