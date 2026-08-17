#!/usr/bin/env bash
set -euo pipefail

version=${1:-}
output=${2:-dist}
binary_root=${3:-$output}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || {
	echo "usage: build-oci.sh SEMVER [OUTPUT_DIRECTORY]" >&2
	exit 2
}
mkdir -p "$output"
[[ -f "$binary_root/tunless_${version}_linux_amd64" && -f "$binary_root/tunless_${version}_linux_arm64" ]] || {
	echo "release binaries are missing from: $binary_root" >&2
	exit 2
}
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
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
		docker buildx create --name "$builder" --driver docker-container --bootstrap >/dev/null
		created_builder=$builder
	fi
fi
builder_args=()
if [[ -n "$builder" ]]; then builder_args=(--builder "$builder"); fi

docker buildx build \
	"${builder_args[@]}" \
	--progress plain \
	--platform linux/amd64,linux/arm64 \
	--provenance=false \
	--build-arg "VERSION=$version" \
	--build-arg "SOURCE_DATE_EPOCH=$epoch" \
	--build-context "release=$binary_root" \
	--tag "tunless:$version" \
	--file packaging/oci/Dockerfile \
	--output "type=oci,dest=$output/tunless_${version}_oci.tar,rewrite-timestamp=true" \
	.
