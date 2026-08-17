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

tags=()
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if ((${#tags[@]})); then docker image rm --force "${tags[@]}" >/dev/null 2>&1 || true; fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for command in jq tar gzip docker; do
	command -v "$command" >/dev/null 2>&1 || { echo "OCI smoke test requires $command" >&2; exit 2; }
done

blob_path() {
	local digest=$1
	[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "invalid OCI digest: $digest" >&2; exit 1; }
	printf 'blobs/sha256/%s\n' "${digest#sha256:}"
}

root_digest=$(tar -xOf "$archive" index.json | jq -er \
	'.manifests | if length == 1 then .[0].digest else error("expected one tagged index") end')
platform_index=$(tar -xOf "$archive" "$(blob_path "$root_digest")")
for arch in amd64 arm64; do
	tag=tunless:oci-smoke-$arch-$$
	tags+=("$tag")
	manifest_digest=$(jq -er --arg arch "$arch" \
		'.manifests[] | select(.platform.os == "linux" and .platform.architecture == $arch) | .digest' \
		<<<"$platform_index")
	manifest=$(tar -xOf "$archive" "$(blob_path "$manifest_digest")")
	config_digest=$(jq -er '.config.digest' <<<"$manifest")
	layer_digest=$(jq -er \
		'.layers | if length == 1 and .[0].mediaType == "application/vnd.oci.image.layer.v1.tar+gzip" then .[0].digest else error("expected one gzip layer") end' \
		<<<"$manifest")
	tar -xOf "$archive" "$(blob_path "$config_digest")" | jq -e --arg arch "$arch" \
		'.os == "linux" and .architecture == $arch and .config.Entrypoint == ["/usr/local/bin/tunless"]' >/dev/null
	tar -xOf "$archive" "$(blob_path "$layer_digest")" | gzip -dc | \
		docker import --platform "linux/$arch" \
			--change 'ENTRYPOINT ["/usr/local/bin/tunless"]' - "$tag" >/dev/null
	actual=$(docker run --rm --platform "linux/$arch" "$tag" --version)
	[[ "$actual" == "$version" ]] || {
		echo "OCI $arch version is $actual, expected $version" >&2
		exit 1
	}
done

printf 'oci_amd64=pass oci_arm64=pass version=%s\n' "$version"
