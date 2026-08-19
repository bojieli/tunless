#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/release-common.sh
source "$repository_root/scripts/release-common.sh"

valid=(0.1.0 1.2.3-rc.1 1.2.3-alpha-beta+build.7 10.20.30+20260819 1.2.3+build-01.007)
invalid=(1.2 01.2.3 1.02.3 1.2.03 1.2.3- 1.2.3+ 1.2.3-01 v1.2.3 '../1.2.3' "1.2.3+$(printf 'a%.0s' {1..129})")

for version in "${valid[@]}"; do
	tunless_validate_version "$version" || {
		echo "valid semantic version rejected: $version" >&2
		exit 1
	}
done
for version in "${invalid[@]}"; do
	if tunless_validate_version "$version"; then
		echo "invalid semantic version accepted: $version" >&2
		exit 1
	fi
done

[[ $(tunless_oci_tag 1.2.3-rc.1+build.7) == 1.2.3-rc.1_build.7 ]] || {
	echo "SemVer build metadata was not mapped safely to OCI tag syntax" >&2
	exit 1
}

if TUNLESS_ALLOW_DIRTY_RELEASE=1 TUNLESS_RELEASE_OUTPUT=docs \
	bash "$repository_root/scripts/release-check.sh" 1.2.3 >/dev/null 2>&1; then
	echo "release cleanup accepted a tracked output directory" >&2
	exit 1
fi

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/tunless-release-common.XXXXXX")
cleanup() {
	trap - EXIT HUP INT TERM
	rm -f -- "$test_dir/artifacts/payload" "$test_dir/artifacts/SHA256SUMS" "$test_dir/outside"
	rmdir "$test_dir/artifacts" "$test_dir" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$test_dir/artifacts"
printf 'payload\n' >"$test_dir/artifacts/payload"
printf 'sentinel\n' >"$test_dir/outside"
ln -s "$test_dir/outside" "$test_dir/artifacts/SHA256SUMS"
bash "$repository_root/scripts/finalize-release.sh" "$test_dir/artifacts" >/dev/null
[[ ! -L "$test_dir/artifacts/SHA256SUMS" && $(<"$test_dir/outside") == sentinel ]] || {
	echo "release checksum finalization followed an existing symlink" >&2
	exit 1
}
