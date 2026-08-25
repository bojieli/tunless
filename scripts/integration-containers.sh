#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Linux || $(id -u) -ne 0 ]]; then
	echo "run this integration test as root on native Linux" >&2
	exit 2
fi

engine=${TUNLESS_CONTAINER_ENGINE:-docker}
TUNLESS_BINARY=${TUNLESS_BINARY:-./tunless}
SINGBOX_BINARY=${SINGBOX_BINARY:-sing-box}
SINGBOX_CONFIG=${SINGBOX_CONFIG:-testdata/singbox-direct.json}
UPSTREAM=${TUNLESS_UPSTREAM:-127.0.0.1:17898}
engine_timeout=${TUNLESS_CONTAINER_ENGINE_TIMEOUT:-120}
image=${TUNLESS_CONTAINER_IMAGE:-docker.io/library/python:3.11-slim}
label=com.bojieli.tunless.integration
suffix=$$
names=("tunless-integration-a-$suffix" "tunless-integration-b-$suffix")
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

for command in "$engine" "$TUNLESS_BINARY" "$SINGBOX_BINARY"; do
	command -v "$command" >/dev/null 2>&1 || [[ -x "$command" ]] || {
		echo "required integration-test command is missing: $command" >&2
		exit 2
	}
done
command -v timeout >/dev/null 2>&1 || {
	echo "required integration-test command is missing: timeout" >&2
	exit 2
}
[[ -r "$SINGBOX_CONFIG" ]] || {
	echo "required integration-test config is missing: $SINGBOX_CONFIG" >&2
	exit 2
}
[[ $engine_timeout =~ ^[1-9][0-9]*$ ]] || {
	echo "TUNLESS_CONTAINER_ENGINE_TIMEOUT must be a positive integer number of seconds" >&2
	exit 2
}

engine_command() {
	local status=0
	timeout --signal=TERM --kill-after=10s "${engine_timeout}s" "$engine" "$@" || status=$?
	# A teardown that hangs instead of failing is the shape of a container whose
	# network namespace something still holds open, and exit 124 on its own says
	# only that the clock ran out. Observed once on a hosted runner during
	# `rm --force`, green on the next run, cause unestablished. Print what was
	# holding things when it happens, so the next occurrence is diagnosable
	# rather than another bare timeout. The diagnostics get their own short
	# clock: a wedged engine must not hang the reporting too.
	if [[ $status -eq 124 ]]; then
		{
			echo "engine command timed out after ${engine_timeout}s: $engine $*"
			timeout 15 "$engine" ps --all 2>&1 | head -20 || true
			timeout 15 ps -eo pid,ppid,stat,etime,args 2>&1 | grep -E "[t]unless|[c]onmon" | head -20 || true
			# One attachment is seven links, and this fires when two containers
			# are attached. A twenty-line cap cut the second set out of the
			# first report that needed it.
			timeout 15 bpftool link show 2>&1 | head -60 || true
		} >&2
	fi
	return "$status"
}

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tunless-container-integration.XXXXXX")
proxy_pid=
watcher_pid=
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [[ $status -ne 0 && -f "$work_dir/watcher.log" ]]; then tail -100 "$work_dir/watcher.log" >&2; fi
	if [[ -n "$watcher_pid" ]]; then kill "$watcher_pid" 2>/dev/null || true; fi
	for name in "${names[@]}"; do engine_command rm --force "$name" >/dev/null 2>&1 || true; done
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
	if ss -lnt | grep -q ":${UPSTREAM##*:} "; then break; fi
	sleep 0.1
done

start_container() {
	engine_command run --detach --name "$1" --label "$label=true" --stop-signal SIGKILL \
		--env HTTP_PROXY= --env HTTPS_PROXY= --env ALL_PROXY= --env NO_PROXY= \
		"$image" sleep 300 >/dev/null
}
engine_command pull "$image" >/dev/null
for name in "${names[@]}"; do start_container "$name"; done

TUNLESS_CONTAINER_ENGINE=$engine \
TUNLESS_CONTAINER_LABEL=$label \
TUNLESS_DOCKER_MODE=native \
TUNLESS_BINARY=$TUNLESS_BINARY \
TUNLESS_UPSTREAM=$UPSTREAM \
	"$repository_root/scripts/tunless-docker-watch.sh" --log-level debug >"$work_dir/watcher.log" 2>&1 &
watcher_pid=$!

wait_for_controllers() {
	local expected=$1
	for _ in {1..300}; do
		kill -0 "$watcher_pid" 2>/dev/null || { tail -100 "$work_dir/watcher.log" >&2; return 1; }
		attached=$(grep -c 'attaching Tunless to container' "$work_dir/watcher.log" || true)
		ready=$(grep -c '"msg":"starting tunless"' "$work_dir/watcher.log" || true)
		if [[ $attached -ge $expected && $ready -ge $expected ]]; then return 0; fi
		sleep 0.1
	done
	echo "watcher did not attach $expected container instances" >&2
	tail -100 "$work_dir/watcher.log" >&2
	return 1
}
wait_for_controllers 2

probe='import http.client,ipaddress,socket,ssl,struct
host="icanhazip.com"; ip=socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM)[0][4][0]
raw=socket.create_connection((ip,443),timeout=20); tls=ssl.create_default_context().wrap_socket(raw,server_hostname=host)
tls.sendall(b"GET / HTTP/1.1\r\nHost: icanhazip.com\r\nConnection: close\r\n\r\n")
resp=http.client.HTTPResponse(tls); resp.begin(); assert resp.status==200
wan=resp.read().decode().strip(); assert ipaddress.ip_address(wan).version==4
q=struct.pack("!HHHHHH",0x7341,0x0100,1,0,0,0)+b"\x07example\x03com\x00"+struct.pack("!HH",1,1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(10); s.sendto(q,("9.9.9.9",53)); r,_=s.recvfrom(4096)
assert r[:2]==b"\x73\x41"; print(wan)'
probe_container() {
	local name=$1 exit_address=
	for _ in {1..3}; do
		if exit_address=$(engine_command exec "$name" python -c "$probe"); then printf '%s\n' "$exit_address"; return 0; fi
		sleep 1
	done
	return 1
}
for name in "${names[@]}"; do
	exit_address=$(probe_container "$name")
	[[ "$exit_address" =~ ^[0-9]+(\.[0-9]+){3}$ ]] || { echo "unexpected WAN result from $name: $exit_address" >&2; exit 1; }
done

engine_command rm --force "${names[0]}" >/dev/null
start_container "${names[0]}"
wait_for_controllers 3
exit_address=$(probe_container "${names[0]}")
[[ "$exit_address" =~ ^[0-9]+(\.[0-9]+){3}$ ]] || { echo "unexpected recreated-container WAN result: $exit_address" >&2; exit 1; }

tcp_flows=$(grep -Ec '"proto":("tcp"|1)' "$work_dir/watcher.log" || true)
udp_flows=$(grep -Ec '"proto":("udp"|2)' "$work_dir/watcher.log" || true)
[[ $tcp_flows -ge 3 && $udp_flows -ge 3 ]] || {
	echo "expected captured TCP and UDP from all container instances; tcp=$tcp_flows udp=$udp_flows" >&2
	tail -100 "$work_dir/watcher.log" >&2
	exit 1
}
printf 'engine=%s attachments=3 tcp_flows=%s udp_flows=%s recreated=yes\n' "$engine" "$tcp_flows" "$udp_flows"
