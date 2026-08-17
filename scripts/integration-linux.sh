#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
	echo "run this integration test as root" >&2
	exit 2
fi

TUNLESS_BINARY=${TUNLESS_BINARY:-./tunless}
SINGBOX_BINARY=${SINGBOX_BINARY:-sing-box}
SINGBOX_CONFIG=${SINGBOX_CONFIG:-testdata/singbox-direct.json}
UPSTREAM=${TUNLESS_UPSTREAM:-127.0.0.1:17898}
upstream_port=${UPSTREAM##*:}
[[ "$UPSTREAM" == 127.0.0.1:* && "$upstream_port" =~ ^[1-9][0-9]*$ ]] || {
	echo "the integration harness requires a numeric 127.0.0.1 SOCKS upstream" >&2
	exit 2
}

for path in "$TUNLESS_BINARY" "$SINGBOX_BINARY" "$SINGBOX_CONFIG"; do
	[[ -e "$path" ]] || {
		echo "required integration-test input is missing: $path" >&2
		exit 2
	}
done
[[ $(stat -fc %T /sys/fs/cgroup) == cgroup2fs ]] || {
	echo "the Linux integration test requires cgroup v2" >&2
	exit 2
}

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tunless-integration.XXXXXX")
cgroup=/sys/fs/cgroup/tunless-integration-$$
mkdir "$cgroup"
tunless_pid=
proxy_pid=
client_pid=

cleanup() {
	trap - EXIT HUP INT TERM
	for pid in "$client_pid" "$tunless_pid" "$proxy_pid"; do
		if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
	done
	for pid in "$client_pid" "$tunless_pid" "$proxy_pid"; do
		if [[ -n "$pid" ]]; then wait "$pid" 2>/dev/null || true; fi
	done
	rmdir "$cgroup" 2>/dev/null || true
	rm -f -- "$work_dir/ready" "$work_dir/continue" "$work_dir/udp-result" "$work_dir/tunless.log" "$work_dir/proxy.log"
	rmdir "$work_dir" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

start_proxy() {
	"$SINGBOX_BINARY" run -c "$SINGBOX_CONFIG" >>"$work_dir/proxy.log" 2>&1 &
	proxy_pid=$!
	for _ in {1..50}; do
		kill -0 "$proxy_pid" 2>/dev/null || {
			echo "sing-box stopped during startup" >&2
			return 1
		}
		if ss -lnt | grep -q ":$upstream_port "; then return 0; fi
		sleep 0.1
	done
	echo "sing-box did not listen on $UPSTREAM" >&2
	return 1
}

cgroup_exec() {
	bash -c 'set -euo pipefail; printf "%s\n" "$$" > "$1/cgroup.procs"; shift; exec "$@"' _ "$cgroup" "$@"
}

start_proxy
"$TUNLESS_BINARY" --backend linux --cgroup "$cgroup" --upstream "$UPSTREAM" --listen 127.0.0.1:0 --log-level debug >"$work_dir/tunless.log" 2>&1 &
tunless_pid=$!
for _ in {1..50}; do
	kill -0 "$tunless_pid" 2>/dev/null || {
		echo "Tunless stopped during startup" >&2
		exit 1
	}
	if grep -q 'starting tunless' "$work_dir/tunless.log"; then break; fi
	sleep 0.1
done
grep -q 'starting tunless' "$work_dir/tunless.log" || {
	echo "Tunless did not finish startup" >&2
	exit 1
}

exit_address=$(cgroup_exec env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY curl --noproxy '*' -4 -fsS --max-time 20 https://icanhazip.com)
[[ "$exit_address" =~ ^[0-9]+(\.[0-9]+){3}$ ]] || {
	echo "unexpected WAN response: $exit_address" >&2
	exit 1
}

cgroup_exec python3 - "$work_dir/ready" "$work_dir/continue" >"$work_dir/udp-result" <<'PY' &
import os
import socket
import struct
import sys
import time

ready, proceed = sys.argv[1:]

def query(transaction):
    labels = b"".join(bytes([len(label)]) + label for label in b"example.com".split(b".")) + b"\0"
    return struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect(("1.1.1.1", 53))
sock.settimeout(3)
sock.send(query(0x7100))
reply = sock.recv(4096)
if reply[:2] != struct.pack("!H", 0x7100):
    raise RuntimeError("initial DNS transaction mismatch")
open(ready, "wb").close()
deadline = time.monotonic() + 20
while not os.path.exists(proceed):
    if time.monotonic() > deadline:
        raise TimeoutError("relay restart signal not received")
    time.sleep(0.05)
for attempt in range(1, 31):
    transaction = 0x7100 + attempt
    try:
        sock.send(query(transaction))
        reply = sock.recv(4096)
        if reply[:2] == struct.pack("!H", transaction):
            print(f"recovered_after_attempt={attempt}")
            break
    except OSError:
        pass
    time.sleep(0.25)
else:
    raise TimeoutError("connected UDP did not recover after the SOCKS relay restarted")
PY
client_pid=$!

for _ in {1..200}; do
	kill -0 "$client_pid" 2>/dev/null || {
		wait "$client_pid"
		exit 1
	}
	if [[ -e "$work_dir/ready" ]]; then break; fi
	sleep 0.05
done
[[ -e "$work_dir/ready" ]] || {
	echo "connected UDP client did not complete its initial exchange" >&2
	exit 1
}

kill "$proxy_pid"
wait "$proxy_pid" 2>/dev/null || true
proxy_pid=
touch "$work_dir/continue"
sleep 1
start_proxy
wait "$client_pid"
client_pid=

udp_flows=$(grep -Ec '"proto":("udp"|2)' "$work_dir/tunless.log" || true)
[[ "$udp_flows" -ge 2 ]] || {
	echo "expected a fresh UDP flow after relay recovery, observed $udp_flows" >&2
	tail -20 "$work_dir/tunless.log" >&2
	exit 1
}

printf 'wan_exit=%s udp_%s udp_flows=%s\n' "$exit_address" "$(<"$work_dir/udp-result")" "$udp_flows"
