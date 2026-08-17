#!/usr/bin/env bash
set -euo pipefail

CGROUP=${TUNLESS_CGROUP:-/sys/fs/cgroup/tunless-test}
UPSTREAM=${TUNLESS_UPSTREAM:-127.0.0.1:17898}
RUNS=${RUNS:-5}
DOWNLOAD_BYTES=${DOWNLOAD_BYTES:-104857600}
URL=${TUNLESS_BENCHMARK_URL:-https://vin.proof.ovh.us/files/100Mb.dat}
TUNLESS_PID=${TUNLESS_PID:-$(pgrep -n -x tunless)}
PROXY_PID=${TUNLESS_PROXY_PID:-$(pgrep -n -x mihomo || true)}

cgroup_exec() {
	# A cgroup that has delegated controllers/children cannot also contain
	# processes. Treat a failed move as a hard error; continuing would silently
	# measure a direct connection and label it transparent.
	sudo bash -c 'set -euo pipefail; printf "%s\n" "$$" > "$1/cgroup.procs"; shift; exec "$@"' _ "$CGROUP" "$@"
}

cpu_ticks() {
	awk '{ print $14 + $15 }' "/proc/$1/stat"
}

rss_kb() {
	awk '/VmRSS:/ { print $2 }' "/proc/$1/status"
}

download() {
	local kind=$1 run=$2
	local format="kind=$kind run=$run connect=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer} total=%{time_total} bytes=%{size_download} speed=%{speed_download}\\n"
	local target=${URL//\{bytes\}/$DOWNLOAD_BYTES}
	if [[ "$target" == *\?* ]]; then target+="&nonce=${kind}-${run}-$$"; else target+="?nonce=${kind}-${run}-$$"; fi
	case "$kind" in
	direct)
		curl --http1.1 --noproxy '*' -4 -fsS -o /dev/null --max-time 120 -w "$format" "$target"
		;;
	socks)
		curl --http1.1 --proxy "socks5://${UPSTREAM}" -4 -fsS -o /dev/null --max-time 120 -w "$format" "$target"
		;;
	transparent)
		cgroup_exec curl --http1.1 --noproxy '*' -4 -fsS -o /dev/null --max-time 120 -w "$format" "$target"
		;;
	esac
}

tunless_ticks_before=$(cpu_ticks "$TUNLESS_PID")
tunless_rss_before=$(rss_kb "$TUNLESS_PID")
proxy_ticks_before=0
if [[ -n "$PROXY_PID" ]]; then proxy_ticks_before=$(cpu_ticks "$PROXY_PID"); fi

for ((run = 1; run <= RUNS; run++)); do
	case $((run % 3)) in
	0) order=(transparent direct socks) ;;
	1) order=(direct socks transparent) ;;
	2) order=(socks transparent direct) ;;
	esac
	for kind in "${order[@]}"; do download "$kind" "$run"; done
done

tunless_ticks_after=$(cpu_ticks "$TUNLESS_PID")
tunless_rss_after=$(rss_kb "$TUNLESS_PID")
proxy_ticks_after=0
if [[ -n "$PROXY_PID" ]]; then proxy_ticks_after=$(cpu_ticks "$PROXY_PID"); fi
printf 'resource tunless_ticks=%d proxy_ticks=%d tunless_rss_before_kb=%d tunless_rss_after_kb=%d clk_tck=%s\n' \
	"$((tunless_ticks_after - tunless_ticks_before))" \
	"$((proxy_ticks_after - proxy_ticks_before))" \
	"$tunless_rss_before" "$tunless_rss_after" "$(getconf CLK_TCK)"
