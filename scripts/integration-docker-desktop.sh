#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Darwin || $(docker info --format '{{.OSType}}' 2>/dev/null) != linux ]]; then
	echo "run this integration test on macOS with Docker Desktop using Linux containers" >&2
	exit 2
fi

TUNLESS_BINARY=${TUNLESS_BINARY:-./tunless}
SINGBOX_BINARY=${SINGBOX_BINARY:-sing-box}
SINGBOX_CONFIG=${SINGBOX_CONFIG:-testdata/singbox-direct.json}
UPSTREAM=${TUNLESS_UPSTREAM:-127.0.0.1:17898}
image=${TUNLESS_DOCKER_IMAGE:-tunless:desktop-integration}
label=com.bojieli.tunless.desktop-integration
suffix=$$
names=("tunless-desktop-a-$suffix" "tunless-desktop-b-$suffix")
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

[[ -x "$TUNLESS_BINARY" ]] || { echo "tunless binary is not executable: $TUNLESS_BINARY" >&2; exit 2; }
for input in "$SINGBOX_BINARY" "$SINGBOX_CONFIG"; do
	command -v "$input" >/dev/null 2>&1 || [[ -r "$input" ]] || { echo "missing test input: $input" >&2; exit 2; }
done

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tunless-desktop-integration.XXXXXX")
proxy_pid=
watcher_pid=
# shellcheck disable=SC2329 # Invoked by the signal/exit trap below.
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [[ $status -ne 0 && -f "$work_dir/watcher.log" ]]; then tail -100 "$work_dir/watcher.log" >&2; fi
	if [[ -n "$watcher_pid" ]]; then kill "$watcher_pid" 2>/dev/null || true; fi
	for name in "${names[@]}"; do docker rm --force "$name" >/dev/null 2>&1 || true; done
	if [[ -n "$proxy_pid" ]]; then kill "$proxy_pid" 2>/dev/null || true; fi
	if [[ -n "$watcher_pid" ]]; then wait "$watcher_pid" 2>/dev/null || true; fi
	if [[ -n "$proxy_pid" ]]; then wait "$proxy_pid" 2>/dev/null || true; fi
	rm -f -- "$work_dir/proxy.log" "$work_dir/watcher.log"
	rmdir "$work_dir" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$SINGBOX_BINARY" run -c "$SINGBOX_CONFIG" >"$work_dir/proxy.log" 2>&1 &
proxy_pid=$!
for _ in {1..50}; do
	kill -0 "$proxy_pid" 2>/dev/null || { echo "sing-box stopped during startup" >&2; exit 1; }
	if nc -z 127.0.0.1 "${UPSTREAM##*:}"; then break; fi
	sleep 0.1
done

docker build --quiet --tag "$image" --file "$repository_root/packaging/docker/Dockerfile" "$repository_root" >/dev/null
start_container() {
	docker run --detach --name "$1" --label "$label=true" \
		--env HTTP_PROXY= --env HTTPS_PROXY= --env ALL_PROXY= --env NO_PROXY= \
		python:3.11-slim sleep 300 >/dev/null
}
for name in "${names[@]}"; do start_container "$name"; done

TUNLESS_CONTAINER_LABEL=$label \
TUNLESS_DOCKER_MODE=desktop \
TUNLESS_DOCKER_BUILD=never \
TUNLESS_DOCKER_IMAGE=$image \
TUNLESS_BINARY=$TUNLESS_BINARY \
TUNLESS_UPSTREAM=$UPSTREAM \
	"$repository_root/scripts/tunless-docker-watch.sh" --log-level debug >"$work_dir/watcher.log" 2>&1 &
watcher_pid=$!

wait_for_controllers() {
	local expected=$1
	for _ in {1..200}; do
		kill -0 "$watcher_pid" 2>/dev/null || { tail -100 "$work_dir/watcher.log" >&2; return 1; }
		attached=$(grep -c 'attaching Tunless to container' "$work_dir/watcher.log" || true)
		ready=$(grep -c '"msg":"starting tunless"' "$work_dir/watcher.log" || true)
		if [[ $attached -ge $expected && $ready -ge $expected ]]; then return 0; fi
		sleep 0.1
	done
	tail -100 "$work_dir/watcher.log" >&2
	return 1
}

probe='import http.client,ipaddress,socket,ssl,struct
host="icanhazip.com"; ip=socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM)[0][4][0]
raw=socket.create_connection((ip,443),timeout=20); tls=ssl.create_default_context().wrap_socket(raw,server_hostname=host)
tls.sendall(b"GET / HTTP/1.1\r\nHost: icanhazip.com\r\nConnection: close\r\n\r\n")
resp=http.client.HTTPResponse(tls); resp.begin(); assert resp.status==200
wan=resp.read().decode().strip(); assert ipaddress.ip_address(wan).version==4
q=struct.pack("!HHHHHH",0x7441,0x0100,1,0,0,0)+b"\x07example\x03com\x00"+struct.pack("!HH",1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(10); s.sendto(q,("1.1.1.1",53)); r,_=s.recvfrom(4096)
assert r[:2]==b"\x74\x41"; print(wan)'

wait_for_controllers 2
for name in "${names[@]}"; do docker exec "$name" python -c "$probe"; done
docker rm --force "${names[0]}" >/dev/null
start_container "${names[0]}"
wait_for_controllers 3
docker exec "${names[0]}" python -c "$probe"

tcp_flows=$(grep -Ec '"proto":("tcp"|1)' "$work_dir/watcher.log" || true)
udp_flows=$(grep -Ec '"proto":("udp"|2)' "$work_dir/watcher.log" || true)
[[ $tcp_flows -ge 3 && $udp_flows -ge 3 ]] || { tail -100 "$work_dir/watcher.log" >&2; exit 1; }
printf 'platform=macos-docker-desktop attachments=3 tcp_flows=%s udp_flows=%s recreated=yes\n' "$tcp_flows" "$udp_flows"
