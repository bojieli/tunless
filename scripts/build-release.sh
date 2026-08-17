#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

version=${1:-}
output=${2:-dist}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || {
	echo "usage: build-release.sh SEMVER [OUTPUT_DIRECTORY]" >&2
	exit 2
}

case "$output" in
/*) ;;
*) output="$repository_root/$output" ;;
esac
mkdir -p "$output"
cp THIRD_PARTY_NOTICES.md "$output/"

epoch=${SOURCE_DATE_EPOCH:-$(git -c safe.directory="$repository_root" log -1 --format=%ct)}
[[ $epoch =~ ^[0-9]+$ ]] || {
	echo "SOURCE_DATE_EPOCH must be an integer Unix timestamp" >&2
	exit 2
}
export SOURCE_DATE_EPOCH=$epoch
export TZ=UTC

for arch in amd64 arm64; do
	base="tunless_${version}_linux_${arch}"
	binary="$output/$base"
	stage="$output/$base.archive"

	GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build \
		-trimpath -buildvcs=false \
		-ldflags "-s -w -buildid= -X main.version=$version" \
		-o "$binary" ./cmd/tunless
	./scripts/verify-third-party-notices.sh "$binary"

	rm -rf -- "$stage"
	mkdir -p "$stage/$base/packaging/systemd" "$stage/$base/scripts"
	cp "$binary" "$stage/$base/tunless"
	cp LICENSE README.md THIRD_PARTY_NOTICES.md "$stage/$base/"
	cp packaging/tunless.env.example "$stage/$base/"
	cp packaging/systemd/tunless-package.service "$stage/$base/packaging/systemd/tunless.service"
	cp packaging/systemd/tunless-container-watch.service "$stage/$base/packaging/systemd/"
	cp scripts/tunless-docker.sh scripts/tunless-docker-watch.sh \
		scripts/tunless-podman.sh scripts/tunless-podman-watch.sh \
		scripts/tunless-cri.sh "$stage/$base/scripts/"
	find "$stage" -exec touch -h -d "@$epoch" {} +
	tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
		-C "$stage" -cf - "$base" | gzip -n >"$output/$base.tar.gz"
	rm -rf -- "$stage"

	sbom="$output/$base.spdx.json"
	syft --source-name "$base" "$binary" -o "spdx-json=$sbom" >/dev/null
	go run ./cmd/spdx-normalize --epoch "$epoch" \
		--namespace "https://github.com/bojieli/tunless/sbom/$version/${sbom##*/}" "$sbom"

	config=$(mktemp "${TMPDIR:-/tmp}/tunless-nfpm.XXXXXX")
	NFPM_ARCH="$arch" VERSION="$version" BINARY="$binary" \
		envsubst <packaging/nfpm.yaml >"$config"
	nfpm package --config "$config" --packager deb \
		--target "$output/$base.deb"
	rpm_arch=x86_64
	if [[ "$arch" == arm64 ]]; then rpm_arch=aarch64; fi
	NFPM_ARCH="$rpm_arch" VERSION="$version" BINARY="$binary" \
		envsubst <packaging/nfpm.yaml >"$config"
	nfpm package --config "$config" --packager rpm \
		--target "$output/tunless_${version}_linux_${rpm_arch}.rpm"
	rm -f -- "$config"
done

find "$output" -maxdepth 1 -type f ! -name SHA256SUMS -print0 |
	sort -z | xargs -0 sha256sum | sed "s#  $output/#  #" >"$output/SHA256SUMS"
