#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat >&2 <<'EOF'
usage: tunless-cri.sh CONTAINER_ID [tunless flags]

Attaches a host Tunless process to one running containerd or CRI-O container.
Run as root on the Kubernetes/CRI node. crictl uses its normal configured
runtime endpoint or CONTAINER_RUNTIME_ENDPOINT.
EOF
	exit 2
}

[[ $# -ge 1 ]] || usage
[[ $(uname -s) == Linux && $(id -u) -eq 0 ]] || {
	echo "run this helper as root on the Linux CRI node" >&2
	exit 2
}
command -v crictl >/dev/null 2>&1 || {
	echo "crictl is required" >&2
	exit 2
}

requested=$1
shift
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary=${TUNLESS_BINARY:-}
if [[ -z "$binary" ]]; then
	if command -v tunless >/dev/null 2>&1; then binary=$(command -v tunless); else binary=$repository_root/tunless; fi
fi
[[ -x "$binary" ]] || { echo "tunless binary is not executable: $binary" >&2; exit 2; }

inspect() {
	crictl inspect --output go-template --template '{{.status.id}} {{.status.state}} {{.info.pid}}' "$requested"
}
read -r container_id state pid < <(inspect)
[[ "$container_id" =~ ^[0-9a-f]{12,64}$ ]] || {
	echo "CRI returned an invalid container ID: $container_id" >&2
	exit 1
}
[[ "$state" == CONTAINER_RUNNING && "$pid" =~ ^[1-9][0-9]*$ ]] || {
	echo "CRI container is not running or its runtime did not expose info.pid: $requested" >&2
	exit 1
}

upstream=${TUNLESS_UPSTREAM:-127.0.0.1:7890}
args=("$@")
for ((index = 0; index < ${#args[@]}; index++)); do
	case ${args[index]} in
	--upstream) if ((index + 1 < ${#args[@]})); then upstream=${args[index + 1]}; fi ;;
	--upstream=*) upstream=${args[index]#--upstream=} ;;
	esac
done

relay_pid=
# shellcheck disable=SC2317,SC2329 # Invoked indirectly by the signal/exit trap below.
cleanup() {
	trap - EXIT HUP INT TERM
	if [[ -n "$relay_pid" ]]; then kill "$relay_pid" 2>/dev/null || true; wait "$relay_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$binary" "${args[@]}" --upstream "$upstream" --backend linux \
	--container-pid "$pid" --container-id "$container_id" --listen 127.0.0.1:0 &
relay_pid=$!

while kill -0 "$relay_pid" 2>/dev/null; do
	if ! current=$(inspect 2>/dev/null); then break; fi
	read -r current_id current_state current_pid <<<"$current"
	if [[ "$current_id" != "$container_id" || "$current_state" != CONTAINER_RUNNING || "$current_pid" != "$pid" ]]; then break; fi
	sleep 1
done

if kill -0 "$relay_pid" 2>/dev/null; then
	echo "CRI container stopped or was replaced; detaching Tunless" >&2
	exit 0
fi
set +e
wait "$relay_pid"
status=$?
set -e
relay_pid=
exit "$status"
