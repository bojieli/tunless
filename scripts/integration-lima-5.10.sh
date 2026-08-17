#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

command -v limactl >/dev/null 2>&1 || {
	echo "limactl is required for the disposable kernel 5.10 test" >&2
	exit 2
}
command -v go >/dev/null 2>&1 || {
	echo "Go is required to build the ARM64 test binaries" >&2
	exit 2
}
command -v curl >/dev/null 2>&1 || {
	echo "curl is required to download the pinned ARM64 sing-box test binary" >&2
	exit 2
}

instance=${TUNLESS_LIMA_INSTANCE:-tunless-kernel-510}
if limactl list --json 2>/dev/null | grep -q "\"name\":\"$instance\""; then
	echo "refusing to reuse or delete existing Lima instance: $instance" >&2
	exit 2
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tunless-lima-510.XXXXXX")
created=false
cleanup() {
	trap - EXIT HUP INT TERM
	if [[ "$created" == true ]]; then
		limactl stop "$instance" >/dev/null 2>&1 || true
		limactl delete "$instance" >/dev/null 2>&1 || true
	fi
	case "$work_dir" in
		"${TMPDIR:-/tmp}"/tunless-lima-510.*) rm -rf -- "$work_dir" ;;
	esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

echo "building ARM64 Tunless and sing-box test binaries" >&2
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath \
	-ldflags '-s -w -X main.version=kernel-5.10-integration' \
	-o "$work_dir/tunless" ./cmd/tunless
singbox_archive=sing-box-1.13.18-linux-arm64.tar.gz
curl --fail --location --retry 5 --silent --show-error \
	--output "$work_dir/$singbox_archive" \
	"https://github.com/SagerNet/sing-box/releases/download/v1.13.18/$singbox_archive"
printf '%s  %s\n' a894f6152cade4a2c9d062762d54dea0c1aee673ab4759e0829e19cace932719 \
	"$work_dir/$singbox_archive" | sha256sum --check -
tar -xzf "$work_dir/$singbox_archive" -C "$work_dir"
install -m 0755 "$work_dir/sing-box-1.13.18-linux-arm64/sing-box" "$work_dir/sing-box"

created=true
limactl start --name "$instance" --tty=false testdata/lima-kernel-5.10.yaml

kernel=$(limactl shell "$instance" uname -r | tr -d '\r')
[[ "$kernel" == 5.10.* ]] || {
	echo "unexpected guest kernel: $kernel" >&2
	exit 1
}

limactl shell "$instance" mkdir -p /tmp/tunless-integration/scripts /tmp/tunless-integration/testdata
limactl copy "$work_dir/tunless" "$instance:/tmp/tunless-integration/tunless"
limactl copy "$work_dir/sing-box" "$instance:/tmp/tunless-integration/sing-box"
limactl copy scripts/integration-linux.sh "$instance:/tmp/tunless-integration/scripts/integration-linux.sh"
limactl copy testdata/singbox-direct.json "$instance:/tmp/tunless-integration/testdata/singbox-direct.json"

limactl shell "$instance" -- bash -lc '
  set -euo pipefail
  cd /tmp/tunless-integration
  chmod +x tunless sing-box scripts/integration-linux.sh
  sudo env TUNLESS_BINARY=./tunless SINGBOX_BINARY=./sing-box ./scripts/integration-linux.sh
'

printf 'kernel=%s disposable_instance=%s\n' "$kernel" "$instance"
