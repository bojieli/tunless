#!/usr/bin/env bash
set -euo pipefail

version=${1:-}
first=${2:-dist}
second=${3:-dist/.reproducibility}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || {
	echo "usage: verify-release-reproducible.sh SEMVER [FIRST_DIRECTORY] [SECOND_DIRECTORY]" >&2
	exit 2
}

for arch in amd64 arm64; do
	for suffix in "" .tar.gz .deb; do
		name=tunless_${version}_linux_${arch}${suffix}
		cmp "$first/$name" "$second/$name"
	done
	cmp "$first/tunless_${version}_linux_${arch}.spdx.json" \
		"$second/tunless_${version}_linux_${arch}.spdx.json"
	cmp "$first/tunless_${version}_oci_linux_${arch}.spdx.json" \
		"$second/tunless_${version}_oci_linux_${arch}.spdx.json"
done
for arch in x86_64 aarch64; do
	name=tunless_${version}_linux_${arch}.rpm
	cmp "$first/$name" "$second/$name"
done
cmp "$first/THIRD_PARTY_NOTICES.md" "$second/THIRD_PARTY_NOTICES.md"

first_oci=$first/tunless_${version}_oci.tar
second_oci=$second/tunless_${version}_oci.tar
cmp "$first_oci" "$second_oci"
first_index=$(tar -xOf "$first_oci" index.json | sha256sum | cut -d' ' -f1)
second_index=$(tar -xOf "$second_oci" index.json | sha256sum | cut -d' ' -f1)
[[ "$first_index" == "$second_index" ]] || {
	echo "OCI manifest indexes are not reproducible" >&2
	exit 1
}

report=$first/REPRODUCIBILITY.txt
{
	printf 'version=%s\n' "$version"
	printf 'source_date_epoch=%s\n' "${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
	printf 'binary_archive_deb_rpm_oci=byte-identical\n'
	printf 'per_platform_spdx_sboms=byte-identical\n'
	printf 'third_party_notices=byte-identical\n'
	printf 'oci_index_sha256=%s\n' "$first_index"
} >"$report"
