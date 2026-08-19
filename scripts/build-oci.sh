#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"
# shellcheck source=scripts/release-common.sh
source "$repository_root/scripts/release-common.sh"
version=${1:-}
output=${2:-dist}
binary_root=${3:-$output}
tunless_validate_version "$version" || {
	echo "usage: build-oci.sh SEMVER [OUTPUT_DIRECTORY]" >&2
	exit 2
}
case "$output" in
/*) ;;
*) output="$repository_root/$output" ;;
esac
case "$binary_root" in
/*) ;;
*) binary_root="$repository_root/$binary_root" ;;
esac
mkdir -p -- "$output"
output=$(cd -- "$output" && pwd -P)
binary_root=$(cd -- "$binary_root" && pwd -P)
[[ -f "$binary_root/tunless_${version}_linux_amd64" && -f "$binary_root/tunless_${version}_linux_arm64" ]] || {
	echo "release binaries are missing from: $binary_root" >&2
	exit 2
}
epoch=${SOURCE_DATE_EPOCH:-$(git -c safe.directory="$repository_root" log -1 --format=%ct)}
[[ $epoch =~ ^[0-9]+$ ]] || {
	echo "SOURCE_DATE_EPOCH must be an integer Unix timestamp" >&2
	exit 2
}
builder=${TUNLESS_BUILDX_BUILDER:-}
created_builder=
cleanup() {
	if [[ -n "$created_builder" ]]; then docker buildx rm "$created_builder" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ -z "$builder" ]]; then
	driver=$(docker buildx inspect 2>/dev/null | awk '/^Driver:/ && !driver { driver=$2 } END { print driver }')
	if [[ "$driver" != docker-container ]]; then
		builder=tunless-release-$$
		created_builder=$builder
		docker buildx create --name "$builder" --driver docker-container --bootstrap >/dev/null
	fi
fi
builder_args=()
if [[ -n "$builder" ]]; then builder_args=(--builder "$builder"); fi
# OCI tag names do not admit SemVer's '+' build-metadata delimiter. Underscore
# cannot occur in a valid SemVer, so this mapping is deterministic and cannot
# collide with another accepted release version.
oci_tag=$(tunless_oci_tag "$version")

docker buildx build \
	"${builder_args[@]}" \
	--progress plain \
	--platform linux/amd64,linux/arm64 \
	--provenance=false \
	--build-arg "VERSION=$version" \
	--build-arg "SOURCE_DATE_EPOCH=$epoch" \
	--build-context "release=$binary_root" \
	--tag "tunless:$oci_tag" \
	--file packaging/oci/Dockerfile \
	--output "type=oci,dest=$output/tunless_${version}_oci.tar,rewrite-timestamp=true" \
	.
