#!/usr/bin/env bash
set -euo pipefail

version=${1:-0.1.0-rc.1}
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

output=${TUNLESS_RELEASE_OUTPUT:-dist}
builder=${TUNLESS_RELEASE_BUILDER:-tunless-release-builder:local}
export TUNLESS_RELEASE_BUILDER=$builder

if [[ ${TUNLESS_ALLOW_DIRTY_RELEASE:-0} != 1 ]] && [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
	echo "release candidates must be built from a clean working tree (set TUNLESS_ALLOW_DIRTY_RELEASE=1 only for local development)" >&2
	exit 2
fi

created_builder=
cleanup() {
	if [[ -n "$created_builder" ]]; then docker buildx rm "$created_builder" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
driver=$(docker buildx inspect 2>/dev/null | awk '/^Driver:/ { print $2; exit }')
if [[ $driver != docker-container && -z ${TUNLESS_BUILDX_BUILDER:-} ]]; then
	created_builder=tunless-release-check-$$
	docker buildx create --name "$created_builder" --driver docker-container --bootstrap >/dev/null
	export TUNLESS_BUILDX_BUILDER=$created_builder
fi

docker build --progress plain --file packaging/release/Dockerfile --tag "$builder" .
docker run --rm --hostname tunless-release-builder \
	-v "$repository_root:/src" "$builder" "$version" "$output"
./scripts/build-oci.sh "$version" "$output"

repro_output=$output/.reproducibility
docker run --rm --hostname tunless-release-builder \
	-v "$repository_root:/src" "$builder" "$version" "$repro_output"
./scripts/build-oci.sh "$version" "$repro_output" "$repro_output"
./scripts/verify-release-reproducible.sh "$version" "$output" "$repro_output"

oci="$repository_root/$output/tunless_${version}_oci.tar"
docker run --rm --entrypoint syft -v "$repository_root:/src" "$builder" \
	"oci-archive:$oci" -o "spdx-json=/src/$output/tunless_${version}_oci.spdx.json" >/dev/null

./scripts/finalize-release.sh "$output"
./scripts/test-packages.sh "$version" "$output"
./scripts/test-oci.sh "$version" "$output"
