#!/usr/bin/env bash
set -euo pipefail

binary=${1:-}
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
notices="$repository_root/THIRD_PARTY_NOTICES.md"
temporary_binary=

cleanup() {
	if [[ -n "$temporary_binary" ]]; then rm -f -- "$temporary_binary"; fi
}
trap cleanup EXIT

if [[ -z "$binary" ]]; then
	temporary_binary=$(mktemp "${TMPDIR:-/tmp}/tunless-notices.XXXXXX")
	binary=$temporary_binary
	(
		cd "$repository_root"
		GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$binary" ./cmd/tunless
	)
fi

[[ -f "$binary" ]] || {
	echo "binary does not exist: $binary" >&2
	exit 2
}
[[ -f "$notices" ]] || {
	echo "third-party notice file does not exist: $notices" >&2
	exit 2
}

metadata=$(go version -m "$binary")
go_version=$(awk 'NR == 1 { print $NF }' <<<"$metadata")
grep -Fq -- "Go standard library $go_version" "$notices" || {
	echo "THIRD_PARTY_NOTICES.md does not cover Go standard library $go_version" >&2
	exit 1
}

dependencies=0
while read -r kind module version _; do
	[[ "$kind" == dep ]] || continue
	dependencies=$((dependencies + 1))
	grep -Fq -- "$module $version" "$notices" || {
		echo "THIRD_PARTY_NOTICES.md does not cover $module $version" >&2
		exit 1
	}
done <<<"$metadata"

((dependencies > 0)) || {
	echo "no dependency metadata found in $binary" >&2
	exit 1
}

echo "third_party_notices=pass dependencies=$dependencies go=$go_version"
