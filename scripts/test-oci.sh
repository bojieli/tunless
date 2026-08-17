#!/usr/bin/env bash
set -euo pipefail

version=${1:-}
output=${2:-dist}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || {
	echo "usage: test-oci.sh SEMVER [OUTPUT_DIRECTORY]" >&2
	exit 2
}
output=$(cd "$output" && pwd)
archive=$output/tunless_${version}_oci.tar
[[ -f "$archive" ]] || { echo "missing OCI archive: $archive" >&2; exit 1; }

builder=${TUNLESS_RELEASE_BUILDER:-tunless-release-builder:local}
work_dir=$(mktemp -d "$output/.oci-smoke.XXXXXX")
tags=()
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if ((${#tags[@]})); then docker image rm --force "${tags[@]}" >/dev/null 2>&1 || true; fi
	case "$work_dir" in "$output"/.oci-smoke.*) rm -rf -- "$work_dir" ;; esac
	exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for arch in amd64 arm64; do
	tag=tunless:oci-smoke-$arch-$$
	tags+=("$tag")
	docker run --rm --entrypoint skopeo \
		-v "$output:/release:ro" -v "$work_dir:/converted" "$builder" \
		copy --override-os linux --override-arch "$arch" \
		"oci-archive:/release/$(basename "$archive")" \
		"docker-archive:/converted/$arch.tar:$tag" >/dev/null
	docker load --input "$work_dir/$arch.tar" >/dev/null
	actual=$(docker run --rm --platform "linux/$arch" "$tag" --version)
	[[ "$actual" == "$version" ]] || {
		echo "OCI $arch version is $actual, expected $version" >&2
		exit 1
	}
done

printf 'oci_amd64=pass oci_arm64=pass version=%s\n' "$version"
