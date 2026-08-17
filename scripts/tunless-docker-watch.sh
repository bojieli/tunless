#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat >&2 <<'EOF'
usage: tunless-docker-watch.sh [tunless flags]

Watches Docker and starts one transparent Tunless namespace controller for
every running application container. Set TUNLESS_DOCKER_LABEL to a label name
(for example devcontainer.local_folder) to limit automatic attachment.

Controller containers are excluded automatically. TUNLESS_UPSTREAM,
TUNLESS_BINARY, TUNLESS_DOCKER_IMAGE, TUNLESS_DOCKER_BUILD, and
TUNLESS_DOCKER_MODE have the same meaning as in tunless-docker.sh.
EOF
	exit 2
}

if [[ ${1:-} == --help || ${1:-} == -h ]]; then usage; fi

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
helper=$repository_root/scripts/tunless-docker.sh
state_dir=$(mktemp -d "${TMPDIR:-/tmp}/tunless-docker-watch.XXXXXX")

cleanup() {
	trap - EXIT HUP INT TERM
	for pid_file in "$state_dir"/*.pid; do
		[[ -e "$pid_file" ]] || continue
		job=$(<"$pid_file")
		if [[ "$job" =~ ^[1-9][0-9]*$ ]]; then kill "$job" 2>/dev/null || true; fi
	done
	for pid_file in "$state_dir"/*.pid; do
		[[ -e "$pid_file" ]] || continue
		job=$(<"$pid_file")
		if [[ "$job" =~ ^[1-9][0-9]*$ ]]; then wait "$job" 2>/dev/null || true; fi
		rm -f -- "$pid_file"
	done
	rmdir "$state_dir" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

selected() {
	local id=$1 controller_label requested_label label_value
	controller_label=$(docker inspect --format '{{index .Config.Labels "com.bojieli.tunless.container"}}' "$id" 2>/dev/null || true)
	[[ -z "$controller_label" ]] || return 1
	requested_label=${TUNLESS_DOCKER_LABEL:-}
	[[ -n "$requested_label" ]] || return 0
	label_value=$(docker inspect --format "{{index .Config.Labels \"$requested_label\"}}" "$id" 2>/dev/null || true)
	[[ -n "$label_value" && "$label_value" != '<no value>' ]]
}

echo "watching Docker containers for transparent Tunless attachment" >&2
if [[ -n ${TUNLESS_DOCKER_LABEL:-} ]]; then
	echo "requiring Docker label: $TUNLESS_DOCKER_LABEL" >&2
fi

while :; do
	while IFS= read -r id; do
		[[ -n "$id" ]] || continue
		selected "$id" || continue
		pid_file=$state_dir/$id.pid
		if [[ -r "$pid_file" ]]; then
			job=$(<"$pid_file")
			if [[ "$job" =~ ^[1-9][0-9]*$ ]] && kill -0 "$job" 2>/dev/null; then continue; fi
			wait "$job" 2>/dev/null || true
			rm -f -- "$pid_file"
		fi
		echo "attaching Tunless to container ${id:0:12}" >&2
		"$helper" "$id" "$@" &
		job=$!
		printf '%s\n' "$job" >"$pid_file"
	done < <(docker ps --quiet)

	for pid_file in "$state_dir"/*.pid; do
		[[ -e "$pid_file" ]] || continue
		id=${pid_file##*/}
		id=${id%.pid}
		job=$(<"$pid_file")
		if ! docker inspect --format '{{.State.Running}}' "$id" 2>/dev/null | grep -qx true || ! kill -0 "$job" 2>/dev/null; then
			kill "$job" 2>/dev/null || true
			wait "$job" 2>/dev/null || true
			rm -f -- "$pid_file"
		fi
	done
	sleep 1
done
