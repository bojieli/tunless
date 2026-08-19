#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat >&2 <<'EOF'
usage: tunless-docker.sh CONTAINER [tunless flags]

Runs a host Tunless process whose redirect listeners live in CONTAINER's
network namespace and whose eBPF programs attach to that container's cgroup.
The container itself needs no proxy variables, capabilities, or route changes.

Set TUNLESS_CONTAINER_ENGINE=podman for rootful Podman on native Linux. On
native Linux, set TUNLESS_BINARY to select the host binary. On Docker
Desktop for macOS/Windows, TUNLESS_DOCKER_IMAGE selects the privileged Linux
controller image. TUNLESS_UPSTREAM, TUNLESS_DNS_UPSTREAM, and
TUNLESS_DISABLE_DNS_OVERRIDE are honored, or pass their flags explicitly.
For a loopback host upstream, the macOS helper automatically starts a local
SOCKS bridge so both TCP and SOCKS5 UDP relay addresses cross Docker Desktop.
EOF
	exit 2
}

[[ $# -ge 1 ]] || usage
container=$1
shift
[[ "$container" != -* ]] || {
	echo "container name or ID must not start with '-'" >&2
	exit 2
}
tunless_args=("$@")
engine=${TUNLESS_CONTAINER_ENGINE:-docker}
command -v "$engine" >/dev/null 2>&1 || {
	echo "container engine is unavailable: $engine" >&2
	exit 1
}
query_timeout=${TUNLESS_CONTAINER_QUERY_TIMEOUT:-10}
query_lock=${TUNLESS_CONTAINER_QUERY_LOCK:-}
[[ "$query_timeout" =~ ^[1-9][0-9]*$ ]] || {
	echo "TUNLESS_CONTAINER_QUERY_TIMEOUT must be a positive integer number of seconds" >&2
	exit 2
}
engine_query() {
	local -a query_command=("$engine" "$@")
	if command -v timeout >/dev/null 2>&1; then
		query_command=(timeout --signal=TERM --kill-after=2s "${query_timeout}s" "${query_command[@]}")
	fi
	if [[ -n "$query_lock" ]] && command -v flock >/dev/null 2>&1; then
		flock --wait "$query_timeout" "$query_lock" "${query_command[@]}"
	else
		"${query_command[@]}"
	fi
}

container_id=$(engine_query inspect --format '{{.Id}}' "$container") || {
	echo "timed out or failed while resolving container identity: $container" >&2
	exit 1
}
[[ "$container_id" =~ ^[0-9a-f]{12,64}$ ]] || {
	echo "container engine returned an invalid immutable ID: $container_id" >&2
	exit 1
}
repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

refresh_pid() {
	local running current current_id state
	state=$(engine_query inspect --format '{{.Id}} {{.State.Running}} {{.State.Pid}}' "$container") || {
		echo "timed out or failed while inspecting container state: $container_id" >&2
		exit 1
	}
	read -r current_id running current <<<"$state"
	[[ "$current_id" == "$container_id" ]] || {
		echo "container was replaced while starting: $container" >&2
		exit 1
	}
	[[ "$running" == true && "$current" =~ ^[1-9][0-9]*$ ]] || {
		echo "container is not running: $container" >&2
		exit 1
	}
	pid=$current
}
refresh_pid

upstream=${TUNLESS_UPSTREAM:-127.0.0.1:7890}
has_dns_upstream=false
has_dns_override_policy=false
for ((index = 0; index < ${#tunless_args[@]}; index++)); do
	case ${tunless_args[index]} in
	--upstream)
		if ((index + 1 < ${#tunless_args[@]})); then upstream=${tunless_args[index + 1]}; fi
		;;
	--upstream=*) upstream=${tunless_args[index]#--upstream=} ;;
	--dns-upstream|--dns-upstream=*) has_dns_upstream=true ;;
	--disable-dns-override|--disable-dns-override=*) has_dns_override_policy=true ;;
	esac
done
if [[ "$has_dns_upstream" == false && -n ${TUNLESS_DNS_UPSTREAM:-} ]]; then
	tunless_args+=(--dns-upstream "$TUNLESS_DNS_UPSTREAM")
fi
if [[ "$has_dns_override_policy" == false && -n ${TUNLESS_DISABLE_DNS_OVERRIDE:-} ]]; then
	tunless_args+=(--disable-dns-override="$TUNLESS_DISABLE_DNS_OVERRIDE")
fi

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
if [[ "$mode" == desktop && ${engine##*/} != docker ]]; then
	echo "desktop mode requires Docker; $engine is supported in native mode only" >&2
	exit 1
fi
if [[ "$mode" == native ]]; then
	rootless=false
	# A UID 0 engine is rootful by definition. Avoid probing engine-wide state in
	# that case: freshly initialized Podman can serialize concurrent `info`
	# requests while the watcher starts controllers for existing containers.
	if [[ $(id -u) -ne 0 && ${engine##*/} == podman ]]; then
		[[ $(engine_query info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true) == true ]] && rootless=true
	elif [[ $(id -u) -ne 0 ]] && engine_query info --format '{{json .SecurityOptions}}' 2>/dev/null | grep -qi rootless; then
		rootless=true
	fi
	if [[ "$rootless" == true ]]; then
		echo "rootless $engine cannot attach host cgroup eBPF or enter another network namespace; use a rootful engine" >&2
		exit 1
	fi
fi

relay_job=
waiter_job=
bridge_job=
bridge_dir=
controller_name=
controller_state_dir=
controller_cid_file=
cleanup() {
	trap - EXIT HUP INT TERM
	if [[ -n "$waiter_job" ]]; then kill "$waiter_job" 2>/dev/null || true; fi
	if [[ "$mode" == desktop && -r "$controller_cid_file" ]]; then
		controller_id=$(<"$controller_cid_file")
		if [[ "$controller_id" =~ ^[0-9a-f]{12,64}$ ]]; then
			engine_query stop --time 2 "$controller_id" >/dev/null 2>&1 || true
		fi
	elif [[ -n "$relay_job" ]] && kill -0 "$relay_job" 2>/dev/null; then
		if [[ $(id -u) -eq 0 ]]; then kill "$relay_job" 2>/dev/null || true; else sudo kill "$relay_job" 2>/dev/null || true; fi
	fi
	if [[ -n "$bridge_job" ]]; then kill "$bridge_job" 2>/dev/null || true; fi
	if [[ -n "$relay_job" ]]; then wait "$relay_job" 2>/dev/null || true; fi
	if [[ -n "$waiter_job" ]]; then wait "$waiter_job" 2>/dev/null || true; fi
	if [[ -n "$bridge_job" ]]; then wait "$bridge_job" 2>/dev/null || true; fi
	if [[ -n "$bridge_dir" ]]; then
		rm -f -- "$bridge_dir/tunless"
		rmdir "$bridge_dir" 2>/dev/null || true
	fi
	if [[ -n "$controller_state_dir" ]]; then
		rm -f -- "$controller_cid_file"
		rmdir "$controller_state_dir" 2>/dev/null || true
	fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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
	privilege=(sudo)
	if [[ $(id -u) -eq 0 ]]; then privilege=(); fi
	echo "starting native Tunless controller for container ${container_id:0:12} (pid $pid)" >&2
	"${privilege[@]}" "$binary" "${tunless_args[@]}" \
		--upstream "$upstream" \
		--backend linux \
		--container-pid "$pid" \
		--container-id "$container_id" \
		--listen 127.0.0.1:0 &
	relay_job=$!
else
	image=${TUNLESS_DOCKER_IMAGE:-tunless:local}
	if [[ ${TUNLESS_DOCKER_BUILD:-auto} != never ]]; then
		"$engine" build --quiet --tag "$image" --file "$repository_root/packaging/docker/Dockerfile" "$repository_root" >/dev/null
	elif ! engine_query image inspect "$image" >/dev/null 2>&1; then
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
			"$bridge_binary" --backend loopback --listen "127.0.0.1:$bridge_port" --upstream "$upstream" --disable-dns-override --log-level warn &
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
	controller_state_dir=$(mktemp -d "${TMPDIR:-/tmp}/tunless-controller.XXXXXX")
	controller_cid_file=$controller_state_dir/cid
	"$engine" run --rm \
		--name "$controller_name" \
		--cidfile "$controller_cid_file" \
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

# The native controller already watches both the target cgroup and network
# namespace and exits when either identity disappears. A concurrent `podman
# wait` can hold Podman's state lock after a forced removal, preventing the
# watcher from discovering a replacement container with the same name.
if [[ "$mode" == native && ${engine##*/} == podman ]]; then
	set +e
	wait "$relay_job"
	status=$?
	set -e
	exit "$status"
fi

"$engine" wait "$container_id" >/dev/null &
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
