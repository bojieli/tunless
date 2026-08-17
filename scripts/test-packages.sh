#!/usr/bin/env bash
set -euo pipefail

version=${1:-}
output=${2:-dist}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || {
	echo "usage: test-packages.sh SEMVER [OUTPUT_DIRECTORY]" >&2
	exit 2
}
output=$(cd "$output" && pwd)

archive="$output/tunless_${version}_linux_amd64.tar.gz"
deb="$output/tunless_${version}_linux_amd64.deb"
rpm="$output/tunless_${version}_linux_x86_64.rpm"
archive_arm64="$output/tunless_${version}_linux_arm64.tar.gz"
deb_arm64="$output/tunless_${version}_linux_arm64.deb"
rpm_arm64="$output/tunless_${version}_linux_aarch64.rpm"
debian_amd64_image=debian:bookworm-slim@sha256:362e64223cc0da95422b3b13c045186fc0a81250e765d31c025fbddf257f6143
debian_arm64_image=debian:bookworm-slim@sha256:817e6cf99d6fc127ff4ffe8580049b60deba0adfbbb2bd65ddc3ef8fbb7aade0
rocky_amd64_image=rockylinux:9@sha256:d644d203142cd5b54ad2a83a203e1dee68af2229f8fe32f52a30c6e1d3c3a9e0
rocky_arm64_image=rockylinux:9@sha256:370b6bd1851d5023c5c673535c85cdc5c1d8a59416ad83380a8db7ce3691bd45
for artifact in "$archive" "$deb" "$rpm" "$archive_arm64" "$deb_arm64" "$rpm_arm64"; do
	[[ -f "$artifact" ]] || {
		echo "missing release artifact: $artifact" >&2
		exit 1
	}
done

docker run --rm --platform linux/amd64 -v "$output:/release:ro" "$debian_amd64_image" sh -euxc "
  printf '%s\n' 'path-include /usr/share/doc/tunless/*' > /etc/dpkg/dpkg.cfg.d/tunless-test
  apt-get update >/dev/null
  apt-get install -y /release/$(basename "$deb") >/dev/null
  test \"\$(tunless --version)\" = '$version'
  test -f /usr/lib/systemd/system/tunless.service
  test -f /usr/lib/systemd/system/tunless-container-watch.service
  test -x /usr/libexec/tunless/tunless-docker-watch.sh
  test -f /usr/share/doc/tunless/copyright
  test -f /usr/share/doc/tunless/THIRD_PARTY_NOTICES.md
  apt-get install -y systemd >/dev/null
  systemd-analyze verify /usr/lib/systemd/system/tunless.service /usr/lib/systemd/system/tunless-container-watch.service
  test \"\$(stat -c %a /usr/bin/tunless)\" = 755
  printf '%s\\n' 'TUNLESS_UPSTREAM=127.0.0.1:9999' > /etc/tunless.env
  dpkg -i /release/$(basename "$deb") >/dev/null
  grep -qx 'TUNLESS_UPSTREAM=127.0.0.1:9999' /etc/tunless.env
  dpkg --remove tunless >/dev/null
  test ! -e /usr/bin/tunless
  test -f /etc/tunless.env
"

docker run --rm --platform linux/arm64 -v "$output:/release:ro" "$debian_arm64_image" sh -euxc "
  printf '%s\n' 'path-include /usr/share/doc/tunless/*' > /etc/dpkg/dpkg.cfg.d/tunless-test
  apt-get update >/dev/null
  apt-get install -y /release/$(basename "$deb_arm64") >/dev/null
  test \"\$(tunless --version)\" = '$version'
  test -f /usr/lib/systemd/system/tunless.service
  test -f /usr/lib/systemd/system/tunless-container-watch.service
  test -x /usr/libexec/tunless/tunless-cri.sh
  test -f /usr/share/doc/tunless/copyright
  test -f /usr/share/doc/tunless/THIRD_PARTY_NOTICES.md
  dpkg -V tunless
  dpkg --remove tunless >/dev/null
  test ! -e /usr/bin/tunless
"

docker run --rm --platform linux/amd64 -v "$output:/release:ro" "$rocky_amd64_image" sh -euxc "
  dnf install -y /release/$(basename "$rpm") >/dev/null
  test \"\$(tunless --version)\" = '$version'
  test -f /usr/lib/systemd/system/tunless.service
  test -f /usr/lib/systemd/system/tunless-container-watch.service
  test -x /usr/libexec/tunless/tunless-podman.sh
  test -f /usr/share/licenses/tunless/LICENSE
  test -f /usr/share/licenses/tunless/THIRD_PARTY_NOTICES.md
  test \"\$(stat -c %a /usr/bin/tunless)\" = 755
  printf '%s\\n' 'TUNLESS_UPSTREAM=127.0.0.1:9999' > /etc/tunless.env
  rpm -U --replacepkgs /release/$(basename "$rpm")
  grep -qx 'TUNLESS_UPSTREAM=127.0.0.1:9999' /etc/tunless.env
  rpm -e tunless
  test ! -e /usr/bin/tunless
  test -f /etc/tunless.env -o -f /etc/tunless.env.rpmsave
"

docker run --rm --platform linux/arm64 -v "$output:/release:ro" "$rocky_arm64_image" sh -euxc "
  dnf install -y /release/$(basename "$rpm_arm64") >/dev/null
  test \"\$(tunless --version)\" = '$version'
  test -f /usr/lib/systemd/system/tunless.service
  test -f /usr/lib/systemd/system/tunless-container-watch.service
  test -x /usr/libexec/tunless/tunless-podman.sh
  test -f /usr/share/licenses/tunless/LICENSE
  test -f /usr/share/licenses/tunless/THIRD_PARTY_NOTICES.md
  rpm -V tunless
  rpm -e tunless
  test ! -e /usr/bin/tunless
"

docker run --rm --platform linux/amd64 -v "$output:/release:ro" "$debian_amd64_image" sh -euxc "
  mkdir /unpack
  tar -xzf /release/$(basename "$archive") -C /unpack
  mkdir /unpack-arm64
  tar -xzf /release/$(basename "$archive_arm64") -C /unpack-arm64
  test -f /unpack/tunless_${version}_linux_amd64/THIRD_PARTY_NOTICES.md
  test -f /unpack-arm64/tunless_${version}_linux_arm64/THIRD_PARTY_NOTICES.md
  test \"\$(/unpack-arm64/tunless_${version}_linux_arm64/tunless --version)\" = '$version'
  test \"\$(/unpack/tunless_${version}_linux_amd64/tunless --version)\" = '$version'
"
