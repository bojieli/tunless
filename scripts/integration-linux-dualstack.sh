#!/usr/bin/env bash
# Exercise the destination filters against an attached cgroup program, using
# the socket shape they were silently wrong about.
#
# A program that opens one AF_INET6 socket for both address families — the
# default for a good deal of runtime software — reaches an IPv4 destination as
# ::ffff:a.b.c.d. Three separate defects lived in that gap, and all three were
# fixed with unit tests in userspace only: an IPv4 exclusion prefix that never
# matched the mapped form, an include list that left the whole v6 family
# uncovered when only IPv4 prefixes were named, and a decoded record that
# carried the mapped spelling to everything downstream.
#
# Unit tests cannot tell you which map the kernel actually consults, so this
# suite drives a real dual-stack socket through a real attached program and
# reads the controller's own log for what it did. Each phase asserts the echo
# still completed, so "not captured" is distinguishable from "broken".
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

# A global address on this host, reached over a dual-stack socket as
# ::ffff:<address>. Loopback would be refused by the capture floor and prove
# nothing about the filters.
host_address=$(ip -4 route get 9.9.9.9 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')
[[ -n "$host_address" ]] || {
	echo "could not determine a global IPv4 address for this host" >&2
	exit 2
}
case $host_address in
127.* | 169.254.* | 0.0.0.0)
	echo "host address $host_address is inside the capture floor; this test needs a routable one" >&2
	exit 2
	;;
esac

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tunless-dualstack.XXXXXX")
cgroup=/sys/fs/cgroup/tunless-dualstack-$$
echo_port=$((21000 + ($$ % 9000)))
mkdir "$cgroup"
tunless_pid=
proxy_pid=
echo_pid=

cleanup() {
	trap - EXIT HUP INT TERM
	for pid in "$tunless_pid" "$echo_pid" "$proxy_pid"; do
		if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
	done
	for pid in "$tunless_pid" "$echo_pid" "$proxy_pid"; do
		if [[ -n "$pid" ]]; then wait "$pid" 2>/dev/null || true; fi
	done
	rmdir "$cgroup" 2>/dev/null || true
	rm -f -- "$work_dir"/*.log "$work_dir"/*.out
	rmdir "$work_dir" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$SINGBOX_BINARY" run -c "$SINGBOX_CONFIG" >"$work_dir/proxy.log" 2>&1 &
proxy_pid=$!
for _ in {1..50}; do
	kill -0 "$proxy_pid" 2>/dev/null || {
		echo "sing-box stopped during startup" >&2
		exit 1
	}
	if ss -lnt | grep -q ":$upstream_port "; then break; fi
	sleep 0.1
done

# The echo server runs outside the captured cgroup: it stands in for any
# ordinary service reachable at a routable address on this network.
python3 - "$host_address" "$echo_port" >"$work_dir/echo.log" 2>&1 <<'ECHOSRV' &
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((host, port))
server.listen(16)
while True:
    connection, _ = server.accept()
    payload = connection.recv(64)
    connection.sendall(payload)
    connection.close()
ECHOSRV
echo_pid=$!

for _ in {1..50}; do
	if ss -lnt | grep -q ":$echo_port "; then break; fi
	sleep 0.1
done

cgroup_exec() {
	bash -c 'set -euo pipefail; printf "%s\n" "$$" > "$1/cgroup.procs"; shift; exec "$@"' _ "$cgroup" "$@"
}

start_tunless() {
	local log=$1
	shift
	"$TUNLESS_BINARY" --backend linux --cgroup "$cgroup" --upstream "$UPSTREAM" \
		--dns-upstream 1.1.1.1:53 --listen 127.0.0.1:0 --log-level debug "$@" >"$log" 2>&1 &
	tunless_pid=$!
	for _ in {1..100}; do
		kill -0 "$tunless_pid" 2>/dev/null || {
			echo "Tunless stopped during startup" >&2
			cat "$log" >&2
			exit 1
		}
		if grep -q 'starting tunless' "$log"; then return 0; fi
		sleep 0.1
	done
	echo "Tunless did not finish startup" >&2
	cat "$log" >&2
	exit 1
}

stop_tunless() {
	[[ -n "$tunless_pid" ]] || return 0
	kill "$tunless_pid" 2>/dev/null || true
	wait "$tunless_pid" 2>/dev/null || true
	tunless_pid=
}

# One dual-stack socket, one IPv4 destination written in mapped form. The echo
# must complete in every phase; only whether it was captured changes.
dual_stack_probe() {
	cgroup_exec python3 - "$host_address" "$echo_port" <<'PY'
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
sock.settimeout(15)
sock.connect(("::ffff:" + host, port))
sock.sendall(b"dual-stack\n")
data = sock.recv(64)
sock.close()
if data.strip() != b"dual-stack":
    raise SystemExit("echo mismatch: %r" % data)
print("echo=ok")
PY
}

captured_lines() {
	local log=$1
	grep -c "\"destination\":\"$host_address:$echo_port\"" "$log" || true
}

mapped_lines() {
	local log=$1
	grep -c "\[::ffff:$host_address\]:$echo_port" "$log" || true
}

phase() {
	local name=$1 log=$2
	shift 2
	start_tunless "$log" "$@"
	local result
	result=$(dual_stack_probe) || {
		echo "$name: the dual-stack echo did not complete" >&2
		cat "$log" >&2
		exit 1
	}
	[[ "$result" == "echo=ok" ]] || {
		echo "$name: unexpected probe result: $result" >&2
		exit 1
	}
	stop_tunless
}

# Before any capture exists, prove this host can do the thing under test at
# all. A kernel without IPv4-mapped connects would fail every phase below in a
# way that reads like a filter defect, and that misdiagnosis is worse than a
# clear refusal to measure.
baseline=$(dual_stack_probe) || {
	echo "this host cannot complete a dual-stack connection to $host_address:$echo_port" >&2
	echo "the destination filter gate cannot be measured here" >&2
	cat "$work_dir/echo.log" >&2 || true
	exit 2
}
[[ "$baseline" == "echo=ok" ]] || {
	echo "unexpected baseline probe result: $baseline" >&2
	exit 2
}

# Phase 1: no destination filters. A dual-stack flow must be captured, and the
# controller must name the destination as the IPv4 address it actually reaches
# rather than the mapped spelling the v6 hooks recorded.
phase "unfiltered" "$work_dir/unfiltered.log"
unfiltered=$(captured_lines "$work_dir/unfiltered.log")
[[ "$unfiltered" -ge 1 ]] || {
	echo "a dual-stack flow to $host_address:$echo_port was not captured with no filters set" >&2
	tail -20 "$work_dir/unfiltered.log" >&2
	exit 1
}
mapped=$(mapped_lines "$work_dir/unfiltered.log")
[[ "$mapped" -eq 0 ]] || {
	echo "the controller reported the destination in mapped form $mapped time(s)" >&2
	grep "::ffff:" "$work_dir/unfiltered.log" >&2 || true
	exit 1
}

# Phase 2: an IPv4 exclusion prefix must cover the mapped form the dual-stack
# socket presents. Before the family-consistency change it did not, and the
# flow was captured against the operator's instruction.
phase "excluded" "$work_dir/excluded.log" --exclude-destination "$host_address/32"
excluded=$(captured_lines "$work_dir/excluded.log")
[[ "$excluded" -eq 0 ]] || {
	echo "--exclude-destination $host_address/32 did not cover a dual-stack socket" >&2
	tail -20 "$work_dir/excluded.log" >&2
	exit 1
}

# Phase 3: naming any include prefix must restrict both families. Before the
# fix, an include list of IPv4 prefixes left the v6 flag unset, which the
# program reads as "capture everything in this family" — so a dual-stack
# destination nobody named was captured anyway.
phase "include-elsewhere" "$work_dir/include.log" --include-destination 203.0.113.0/24
included=$(captured_lines "$work_dir/include.log")
[[ "$included" -eq 0 ]] || {
	echo "an include list naming only 203.0.113.0/24 still captured $host_address:$echo_port" >&2
	tail -20 "$work_dir/include.log" >&2
	exit 1
}

printf 'dualstack host=%s port=%s unfiltered_flows=%s mapped_spellings=%s excluded=%s include_elsewhere=%s\n' \
	"$host_address" "$echo_port" "$unfiltered" "$mapped" "$excluded" "$included"
