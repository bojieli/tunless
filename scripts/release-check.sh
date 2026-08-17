#!/usr/bin/env bash
set -euo pipefail

version=${1:-0.1.0-rc.1}
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

output=${TUNLESS_RELEASE_OUTPUT:-dist}
builder=${TUNLESS_RELEASE_BUILDER:-tunless-release-builder:local}
export TUNLESS_RELEASE_BUILDER=$builder
container_user="$(id -u):$(id -g)"
source_date_epoch=${SOURCE_DATE_EPOCH:-$(git -c safe.directory="$repository_root" log -1 --format=%ct)}
[[ $source_date_epoch =~ ^[0-9]+$ ]] || {
	echo "SOURCE_DATE_EPOCH must be an integer Unix timestamp" >&2
	exit 2
}
export SOURCE_DATE_EPOCH=$source_date_epoch

if [[ ${TUNLESS_ALLOW_DIRTY_RELEASE:-0} != 1 ]] && [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
	echo "release candidates must be built from a clean working tree (set TUNLESS_ALLOW_DIRTY_RELEASE=1 only for local development)" >&2
	exit 2
fi
case "$output" in
"" | . | .. | /* | ../* | */../* | */..)
	echo "release output must be a non-parent relative directory inside the repository" >&2
	exit 2
	;;
esac
mkdir -p "$output"
output_real=$(cd "$output" && pwd -P)
[[ $output_real == "$repository_root/"* ]] || {
	echo "release output resolves outside the repository: $output" >&2
	exit 2
}
find "$output_real" -xdev -mindepth 1 -depth -delete

created_builder=
cleanup() {
	if [[ -n "$created_builder" ]]; then docker buildx rm "$created_builder" >/dev/null 2>&1 || true; fi
}

build_oci_sboms() {
	local artifact_dir=$1 arch sbom oci
	oci="/src/$artifact_dir/tunless_${version}_oci.tar"
	for arch in amd64 arm64; do
		sbom="tunless_${version}_oci_linux_${arch}.spdx.json"
		docker run --rm --user "$container_user" --env HOME=/tmp --entrypoint syft \
			-v "$repository_root:/src" "$builder" --platform "linux/$arch" \
			--source-name "tunless_${version}_oci_linux_${arch}" "oci-archive:$oci" \
			-o "spdx-json=/src/$artifact_dir/$sbom" >/dev/null
		go run ./cmd/spdx-normalize --epoch "$SOURCE_DATE_EPOCH" \
			--namespace "https://github.com/bojieli/tunless/sbom/$version/$sbom" \
			"$artifact_dir/$sbom"
	done
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
driver=$(docker buildx inspect 2>/dev/null | awk '/^Driver:/ && !driver { driver=$2 } END { print driver }')
if [[ $driver != docker-container && -z ${TUNLESS_BUILDX_BUILDER:-} ]]; then
	created_builder=tunless-release-check-$$
	docker buildx create --name "$created_builder" --driver docker-container --bootstrap >/dev/null
	export TUNLESS_BUILDX_BUILDER=$created_builder
fi

docker build --progress plain --file packaging/release/Dockerfile --tag "$builder" .
docker run --rm --hostname tunless-release-builder \
	--user "$container_user" --env HOME=/tmp --env GOCACHE=/tmp/tunless-go-build \
	--env "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
	-v "$repository_root:/src" "$builder" "$version" "$output"
./scripts/build-oci.sh "$version" "$output"
build_oci_sboms "$output"

repro_output=$output/.reproducibility
docker run --rm --hostname tunless-release-builder \
	--user "$container_user" --env HOME=/tmp --env GOCACHE=/tmp/tunless-go-build \
	--env "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
	-v "$repository_root:/src" "$builder" "$version" "$repro_output"
./scripts/build-oci.sh "$version" "$repro_output" "$repro_output"
build_oci_sboms "$repro_output"
./scripts/verify-release-reproducible.sh "$version" "$output" "$repro_output"

./scripts/finalize-release.sh "$output"
./scripts/test-packages.sh "$version" "$output"
./scripts/test-oci.sh "$version" "$output"
