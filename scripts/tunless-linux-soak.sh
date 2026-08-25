#!/usr/bin/env bash
# Soak a live Linux capture and record every moment it was not protecting the
# host.
#
# The macOS soak exists because every serious defect this project has found
# surfaced over hours rather than minutes, and the worst of them left a host
# resolving names unprotected for nine hours. Nothing about that lesson is
# specific to macOS. Linux is the platform this project ships as generally
# available, and until now the only thing watching it over time was a
# connection stress test against the portable core — load, not duration, and
# not the eBPF datapath at all.
#
# The failures worth catching here are the ones that need a clock. systemd
# restarts a crashed controller quietly, so a crash loop looks like uptime. BPF
# links survive their cgroup being recreated by something else, or they do not,
# and either way nothing announces it. LRU maps with 65,536 entries drift.
# Interfaces flap, leases renew, an upstream goes away for a minute at 4am.
#
# So watch the assembled system on its own schedule and assert two things on
# every tick: does a name resolve from inside the captured scope, and is
# capture claiming the traffic while it does. Write every tick down and
# summarise the gaps at the end. A run that never records a gap is the
# evidence; a run that records one names the minute it started.
set -euo pipefail

interval=60
name=example.com
cgroup=
status=
out=
binary=

usage() {
	cat >&2 <<'USAGE'
usage: tunless-linux-soak.sh [options]

  --cgroup PATH     Captured cgroup to probe from (default: read from the
                    running controller's own --cgroup argument)
  --status ADDR     Controller status API, e.g. 127.0.0.1:6060. Without it the
                    soak falls back to counting attached BPF links, which
                    proves capture is installed but not that it is claiming
                    anything
  --interval N      Seconds between checks (default 60)
  --name HOST       Name to resolve each tick (default example.com)
  --out FILE        Append JSON lines here (default /var/log/tunless-soak.jsonl)
  --summary FILE    Print a summary of an existing log and exit
  -h, --help        Show this help

Run as root, leave it running across whatever the machine does. Ctrl-C prints
the summary. A 48-hour run with no unprotected interval and no unexplained
restart is what the release gate asks for.
USAGE
	exit 2
}

summarise() {
	local file=${1:-}
	[[ -f $file ]] || { echo "no soak log at $file" >&2; exit 1; }
	python3 - "$file" <<'PY'
import json, sys, datetime
path = sys.argv[1]
ticks = []
for line in open(path):
    line = line.strip()
    if not line:
        continue
    try:
        ticks.append(json.loads(line))
    except ValueError:
        continue
if not ticks:
    print("no ticks recorded")
    raise SystemExit(0)

def when(t):
    return datetime.datetime.fromtimestamp(t["at"])

first, last = when(ticks[0]), when(ticks[-1])
span = (last - first).total_seconds()
resolved = [t for t in ticks if t.get("resolved")]
capturing = [t for t in ticks if t.get("capturing")]
claiming = [t for t in ticks if t.get("claimed")]
print("soak %s -> %s (%.1f hours, %d ticks)" % (
    first.strftime("%m-%d %H:%M"), last.strftime("%m-%d %H:%M"), span / 3600, len(ticks)))
print("  resolved:  %d/%d ticks (%.2f%%)" % (len(resolved), len(ticks), 100.0 * len(resolved) / len(ticks)))
print("  capturing: %d/%d ticks (%.2f%%)" % (len(capturing), len(ticks), 100.0 * len(capturing) / len(ticks)))
if any("claimed" in t for t in ticks):
    counted = [t for t in ticks if "claimed" in t]
    print("  claiming:  %d/%d ticks with a status API (%.2f%%)" % (
        len(claiming), len(counted), 100.0 * len(claiming) / len(counted)))
else:
    print("  claiming:  not measured (no --status; link presence only)")

# A gap is any run of consecutive ticks that failed an assertion, plus any
# wall-clock hole where no tick was written at all: a wedged or rebooting host
# stops ticking, and that silence is itself a finding.
def runs(predicate, label):
    found, start, last_tick = [], None, None
    for t in ticks:
        bad = predicate(t)
        if bad and start is None:
            start = t
        if not bad and start is not None:
            found.append((start, last_tick))
            start = None
        last_tick = t
    if start is not None:
        found.append((start, last_tick))
    if not found:
        print("  no %s intervals" % label)
        return
    print("  %s intervals: %d" % (label, len(found)))
    for a, b in found[:20]:
        detail = a.get("error") or ""
        print("     %s -> %s  (%.1f min)  %s" % (
            when(a).strftime("%m-%d %H:%M:%S"), when(b).strftime("%H:%M:%S"),
            (when(b) - when(a)).total_seconds() / 60, detail[:70]))

runs(lambda t: not t.get("resolved"), "UNRESOLVED")
runs(lambda t: not t.get("capturing"), "not-capturing")
# Resolving fine while capture is gone is the shape of the nine-hour defect:
# the host looks healthy to everyone, and its traffic is not being carried.
runs(lambda t: t.get("resolved") and not t.get("capturing"), "UNPROTECTED")

# systemd restarts a failing controller without saying so. A changed PID
# between ticks is that restart, and a crash loop is a column of them.
restarts = []
for a, b in zip(ticks, ticks[1:]):
    pa, pb = a.get("pid"), b.get("pid")
    if pa and pb and pa != pb:
        restarts.append((a, b))
if restarts:
    print("  controller restarts: %d" % len(restarts))
    for a, b in restarts[:20]:
        print("     %s  pid %s -> %s" % (when(b).strftime("%m-%d %H:%M:%S"), a.get("pid"), b.get("pid")))
else:
    print("  no controller restarts")

# Kernel LRU maps and the relay allocator are the two things here that could
# drift over days rather than minutes. Report the span, not a verdict.
rss = [t["rss_kb"] for t in ticks if t.get("rss_kb")]
if rss:
    print("  controller RSS: %d KiB -> %d KiB (min %d, max %d)" % (rss[0], rss[-1], min(rss), max(rss)))
flows = [t["accepted_flows"] for t in ticks if t.get("accepted_flows") is not None]
if flows:
    print("  accepted flows: %d -> %d" % (flows[0], flows[-1]))

holes = []
for a, b in zip(ticks, ticks[1:]):
    gap = b["at"] - a["at"]
    if gap > max(300, 5 * a.get("interval", 60)):
        holes.append((a, b, gap))
if holes:
    print("  silent holes (host down, or the soak itself stopped): %d" % len(holes))
    for a, b, gap in holes[:20]:
        print("     %s -> %s  (%.1f min with no tick)" % (
            when(a).strftime("%m-%d %H:%M:%S"), when(b).strftime("%m-%d %H:%M:%S"), gap / 60))
else:
    print("  no silent holes")
PY
}

while [[ $# -gt 0 ]]; do
	case $1 in
	--cgroup) cgroup=${2:-}; shift 2 ;;
	--status) status=${2:-}; shift 2 ;;
	--interval) interval=${2:-}; shift 2 ;;
	--name) name=${2:-}; shift 2 ;;
	--out) out=${2:-}; shift 2 ;;
	--binary) binary=${2:-}; shift 2 ;;
	--summary) summarise "${2:-}"; exit 0 ;;
	-h | --help) usage ;;
	*) echo "unknown argument: $1" >&2; usage ;;
	esac
done

[[ $interval =~ ^[0-9]+$ && $interval -ge 5 ]] || {
	echo "--interval must be at least 5 seconds" >&2
	exit 1
}
[[ $(id -u) -eq 0 ]] || {
	echo "run the soak as root: it moves a probe process into the captured cgroup" >&2
	exit 1
}

controller_pid() {
	pgrep -x "${binary:-tunless}" 2>/dev/null | head -n 1
}

# Ask the running controller which cgroup it captures rather than making the
# operator repeat it. Getting this wrong would probe an uncaptured scope and
# report a healthy soak of nothing.
discover_cgroup() {
	local pid args
	pid=$(controller_pid) || return 1
	[[ -n $pid ]] || return 1
	args=$(tr '\0' '\n' <"/proc/$pid/cmdline" 2>/dev/null) || return 1
	printf '%s\n' "$args" | awk '
		/^--cgroup=/ { sub(/^--cgroup=/, ""); print; exit }
		found { print; exit }
		/^--cgroup$/ { found = 1 }
	'
}

if [[ -z $cgroup ]]; then
	cgroup=$(discover_cgroup || true)
	[[ -n $cgroup ]] || {
		echo "could not read a --cgroup from a running controller; pass --cgroup" >&2
		exit 1
	}
	echo "probing the cgroup the controller reports capturing: $cgroup" >&2
fi
[[ -d $cgroup ]] || {
	echo "no such cgroup: $cgroup" >&2
	exit 1
}
if [[ -n $status ]]; then
	[[ $status =~ ^127\.0\.0\.1:[1-9][0-9]*$ || $status =~ ^\[::1\]:[1-9][0-9]*$ ]] || {
		echo "--status must be a loopback address and port, e.g. 127.0.0.1:6060" >&2
		exit 1
	}
fi
if [[ -z $out ]]; then
	out=/var/log/tunless-soak.jsonl
fi
install -d -m 0755 "$(dirname "$out")"

trap 'echo; summarise "$out"; exit 0' INT TERM

# Resolve from inside the captured scope, not beside it. A lookup made by the
# soak's own shell traverses whatever the host would use with tunless out of
# the picture, which is exactly the path that keeps working when capture has
# quietly stopped carrying anything.
probe_in_cgroup() {
	bash -c 'set -euo pipefail; printf "%s\n" "$$" > "$1/cgroup.procs"; shift; exec timeout 20 "$@"' \
		_ "$cgroup" "$@"
}

read_status_field() {
	local body=$1 expr=$2
	printf '%s' "$body" | python3 -c "
import json,sys
try:
    status = json.load(sys.stdin)
except Exception:
    sys.exit(1)
print($expr)
" 2>/dev/null || true
}

echo "soaking every ${interval}s, resolving $name from $cgroup, writing $out (Ctrl-C to summarise)" >&2
while true; do
	at=$(date +%s)
	error=

	if answer=$(probe_in_cgroup getent ahostsv4 "$name" 2>/dev/null | awk 'NR==1 {print $1; exit}') \
		&& [[ -n $answer ]]; then
		resolved=true
	else
		resolved=false
		answer=
		error="resolution failed from the captured cgroup"
	fi

	pid=$(controller_pid || true)
	rss_kb=0
	if [[ -n $pid && -r /proc/$pid/status ]]; then
		rss_kb=$(awk '/^VmRSS:/ {print $2; exit}' "/proc/$pid/status" 2>/dev/null || echo 0)
	fi

	# Two independent readings of "is capture on". Links prove the programs are
	# attached; accepted_flows advancing proves they are claiming the traffic
	# the tick just generated. Without a status API only the first is available,
	# and the log records which one this run is standing on.
	links=$(bpftool link show 2>/dev/null | grep -c tunless || true)
	claimed_field=
	accepted=
	if [[ -n $status ]]; then
		if body=$(curl -fsS --max-time 5 "http://$status/v1/status" 2>/dev/null); then
			accepted=$(read_status_field "$body" 'status["flows"]["accepted_flows"]')
			ok=$(read_status_field "$body" 'status["status"]')
			[[ $ok == ok ]] || error=${error:-"status API reported $ok"}
		else
			error=${error:-"status API unreachable"}
		fi
	fi

	if [[ -n $accepted ]]; then
		if [[ -n ${last_accepted:-} && $accepted -gt $last_accepted ]]; then
			claimed_field=',"claimed":true'
		elif [[ -n ${last_accepted:-} ]]; then
			claimed_field=',"claimed":false'
			error=${error:-"capture claimed no new flow while the tick resolved a name"}
		fi
		last_accepted=$accepted
	fi

	if [[ ${links:-0} -gt 0 ]]; then
		capturing=true
	else
		capturing=false
		error=${error:-"no attached tunless BPF links"}
	fi

	printf '{"at":%s,"interval":%s,"resolved":%s,"answer":"%s","capturing":%s,"links":%s,"pid":"%s","rss_kb":%s%s%s}\n' \
		"$at" "$interval" "$resolved" "$answer" "$capturing" "${links:-0}" "${pid:-}" "${rss_kb:-0}" \
		"${accepted:+,\"accepted_flows\":$accepted}" "$claimed_field" >>"$out"

	if [[ $resolved != true || $capturing != true ]]; then
		echo "$(date '+%H:%M:%S') resolved=$resolved capturing=$capturing ${error:+$error}" >&2
	fi
	sleep "$interval"
done
