#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat >&2 <<'EOF'
usage: tunless-docker.sh CONTAINER [tunless flags]

Runs a host Tunless process whose redirect listeners live in CONTAINER's
network namespace and whose eBPF programs attach to that container's cgroup.
The container itself needs no proxy variables, capabilities, or route changes.

On native Linux, set TUNLESS_BINARY to select the host binary. On Docker
Desktop for macOS/Windows, TUNLESS_DOCKER_IMAGE selects the privileged Linux
controller image. TUNLESS_UPSTREAM is honored, or pass --upstream explicitly.
For a loopback host upstream, the macOS helper automatically starts a local
SOCKS bridge so both TCP and SOCKS5 UDP relay addresses cross Docker Desktop.
EOF
	exit 2
}

[[ $# -ge 1 ]] || usage
container=$1
shift
tunless_args=("$@")

container_id=$(docker inspect --format '{{.Id}}' "$container")
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

refresh_pid() {
	local running current
	running=$(docker inspect --format '{{.State.Running}}' "$container")
	current=$(docker inspect --format '{{.State.Pid}}' "$container")
	[[ "$running" == true && "$current" =~ ^[1-9][0-9]*$ ]] || {
		echo "container is not running: $container" >&2
		exit 1
	}
	pid=$current
}
refresh_pid

upstream=${TUNLESS_UPSTREAM:-127.0.0.1:7890}
for ((index = 0; index < ${#tunless_args[@]}; index++)); do
	case ${tunless_args[index]} in
	--upstream)
		if ((index + 1 < ${#tunless_args[@]})); then upstream=${tunless_args[index + 1]}; fi
		;;
	--upstream=*) upstream=${tunless_args[index]#--upstream=} ;;
	esac
done

mode=${TUNLESS_DOCKER_MODE:-auto}
if [[ "$mode" == auto ]]; then
	mode=desktop
	if [[ $(uname -s) == Linux && -r /proc/$pid/cgroup ]] && grep -q "${container_id:0:12}" "/proc/$pid/cgroup"; then
		mode=native
	fi
fi
[[ "$mode" == native || "$mode" == desktop ]] || {
	echo "TUNLESS_DOCKER_MODE must be auto, native, or desktop" >&2
	exit 1
}

relay_job=
waiter_job=
bridge_job=
bridge_dir=
controller_name=
cleanup() {
	trap - EXIT HUP INT TERM
	if [[ -n "$waiter_job" ]]; then kill "$waiter_job" 2>/dev/null || true; fi
	if [[ "$mode" == desktop && -n "$controller_name" ]]; then
		docker stop --time 2 "$controller_name" >/dev/null 2>&1 || true
	elif [[ -n "$relay_job" ]] && kill -0 "$relay_job" 2>/dev/null; then
		sudo kill "$relay_job" 2>/dev/null || true
	fi
	if [[ -n "$bridge_job" ]]; then kill "$bridge_job" 2>/dev/null || true; fi
	if [[ -n "$relay_job" ]]; then wait "$relay_job" 2>/dev/null || true; fi
	if [[ -n "$waiter_job" ]]; then wait "$waiter_job" 2>/dev/null || true; fi
	if [[ -n "$bridge_job" ]]; then wait "$bridge_job" 2>/dev/null || true; fi
	if [[ -n "$bridge_dir" ]]; then
		rm -f -- "$bridge_dir/tunless"
		rmdir "$bridge_dir" 2>/dev/null || true
	fi
}
trap cleanup EXIT HUP INT TERM

if [[ "$mode" == native ]]; then
	refresh_pid
	if [[ -n "${TUNLESS_BINARY:-}" ]]; then
		binary=$TUNLESS_BINARY
	elif command -v tunless >/dev/null 2>&1; then
		binary=$(command -v tunless)
	else
		binary=$repository_root/tunless
	fi
	[[ -x "$binary" ]] || {
		echo "tunless binary is not executable: $binary" >&2
		exit 1
	}
	sudo "$binary" "${tunless_args[@]}" \
		--upstream "$upstream" \
		--backend linux \
		--container-pid "$pid" \
		--container-id "$container_id" \
		--listen 127.0.0.1:0 &
	relay_job=$!
else
	image=${TUNLESS_DOCKER_IMAGE:-tunless:local}
	if [[ ${TUNLESS_DOCKER_BUILD:-auto} != never ]]; then
		docker build --quiet --tag "$image" --file "$repository_root/packaging/docker/Dockerfile" "$repository_root" >/dev/null
	elif ! docker image inspect "$image" >/dev/null 2>&1; then
		echo "Docker controller image is unavailable: $image" >&2
		exit 1
	fi
	desktop_upstream=$upstream
	if [[ "$upstream" =~ ^(socks5h?://([^/@]+@)?)(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)$ ]]; then
		desktop_upstream=${BASH_REMATCH[1]}host.docker.internal${BASH_REMATCH[4]}
	elif [[ "$upstream" =~ ^(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)$ ]]; then
		desktop_upstream=host.docker.internal${BASH_REMATCH[2]}
	fi
	if [[ $(uname -s) == Darwin && ${TUNLESS_DOCKER_BRIDGE:-auto} != never ]] &&
		[[ "$upstream" =~ ^(socks5h?://([^/@]+@)?)?(127\.0\.0\.1|localhost|\[::1\]): ]]; then
		if [[ -n ${TUNLESS_DOCKER_BRIDGE_BINARY:-} ]]; then
			bridge_binary=$TUNLESS_DOCKER_BRIDGE_BINARY
		elif [[ -n ${TUNLESS_BINARY:-} ]]; then
			bridge_binary=$TUNLESS_BINARY
		elif command -v tunless >/dev/null 2>&1; then
			bridge_binary=$(command -v tunless)
		else
			command -v go >/dev/null 2>&1 || {
				echo "Go or TUNLESS_DOCKER_BRIDGE_BINARY is required for Docker Desktop UDP bridging" >&2
				exit 1
			}
			bridge_dir=$(mktemp -d "${TMPDIR:-/tmp}/tunless-docker-bridge.XXXXXX")
			go build -o "$bridge_dir/tunless" "$repository_root/cmd/tunless"
			bridge_binary=$bridge_dir/tunless
		fi
		[[ -x "$bridge_binary" ]] || {
			echo "Tunless bridge binary is not executable: $bridge_binary" >&2
			exit 1
		}
		for attempt in {0..19}; do
			bridge_port=$((35000 + (($$ + attempt) % 20000)))
			"$bridge_binary" --backend loopback --listen "127.0.0.1:$bridge_port" --upstream "$upstream" --log-level warn &
			bridge_job=$!
			bridge_ready=false
			for _ in {1..20}; do
				if ! kill -0 "$bridge_job" 2>/dev/null; then break; fi
				if { exec 9<>"/dev/tcp/127.0.0.1/$bridge_port"; } 2>/dev/null; then
					exec 9>&-
					exec 9<&-
					bridge_ready=true
					break
				fi
				sleep 0.05
			done
			if [[ "$bridge_ready" == true ]]; then break; fi
			kill "$bridge_job" 2>/dev/null || true
			wait "$bridge_job" 2>/dev/null || true
			bridge_job=
		done
		[[ -n "$bridge_job" ]] || {
			echo "could not allocate a Docker Desktop SOCKS bridge port" >&2
			exit 1
		}
		desktop_upstream=host.docker.internal:$bridge_port
		echo "bridging Docker Desktop TCP/UDP to host upstream $upstream" >&2
	fi
	refresh_pid
	controller_name=tunless-${container_id:0:12}-$$
	docker run --rm \
		--name "$controller_name" \
		--label com.bojieli.tunless.container="$container_id" \
		--privileged \
		--pid host \
		--cgroupns host \
		--mount type=bind,source=/sys/fs/cgroup,target=/sys/fs/cgroup \
		--add-host host.docker.internal:host-gateway \
		"$image" "${tunless_args[@]}" \
		--upstream "$desktop_upstream" \
		--backend linux \
		--container-pid "$pid" \
		--container-id "$container_id" \
		--listen 127.0.0.1:0 &
	relay_job=$!
fi
docker wait "$container" >/dev/null &
waiter_job=$!

while kill -0 "$relay_job" 2>/dev/null && kill -0 "$waiter_job" 2>/dev/null; do
	sleep 0.25
done

if ! kill -0 "$relay_job" 2>/dev/null; then
	set +e
	wait "$relay_job"
	status=$?
	set -e
	exit "$status"
fi

echo "container stopped; detaching Tunless from $container" >&2
