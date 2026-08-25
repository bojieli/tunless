#!/usr/bin/env bash
# Soak a live macOS capture and record every moment it was not protecting the
# host.
#
# Every serious defect this project has found surfaced over hours, not minutes:
# a watchdog that mistook a sleeping laptop for a failing upstream left a host
# resolving names unprotected for nine hours, and it was noticed by accident.
# Unit tests cannot see that class of bug and a five-minute smoke test cannot
# either, because the triggers are sleep, wake, node switches, and network
# changes — things that happen on a laptop's own schedule.
#
# So watch the assembled system on that schedule and assert one thing on every
# tick: does a name resolve, and is capture claiming flows while it does. Write
# every tick down, and summarise the gaps at the end. A run that never records
# a gap is the evidence; a run that records one names the minute it started.
set -euo pipefail

app=/Applications/Tunless.app/Contents/MacOS/Tunless
interval=60
name=example.com
out=

usage() {
	cat >&2 <<'USAGE'
usage: tunless-macos-soak.sh [options]

  --app PATH        Tunless launcher (default /Applications/Tunless.app/...)
  --interval N      Seconds between checks (default 60)
  --name HOST       Name to resolve each tick (default example.com)
  --out FILE        Append JSON lines here (default ~/.tunless/soak.jsonl)
  --summary FILE    Print a summary of an existing log and exit
  -h, --help        Show this help

Leave it running across sleeps, wakes, and network changes. Ctrl-C prints the
summary.
USAGE
	exit 2
}

summarise() {
	local file=$1
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
capturing = [t for t in ticks if (t.get("capture") or "").startswith("capturing")]
print("soak %s -> %s (%.1f hours, %d ticks)" % (
    first.strftime("%m-%d %H:%M"), last.strftime("%m-%d %H:%M"), span / 3600, len(ticks)))
print("  resolved:  %d/%d ticks (%.2f%%)" % (len(resolved), len(ticks), 100.0 * len(resolved) / len(ticks)))
print("  capturing: %d/%d ticks (%.2f%%)" % (len(capturing), len(ticks), 100.0 * len(capturing) / len(ticks)))

# A gap is any run of consecutive ticks that failed the assertion, plus any
# wall-clock hole where no tick was written at all: a sleeping or wedged host
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
        detail = a.get("capture") or a.get("error") or ""
        print("     %s -> %s  (%.1f min)  %s" % (
            when(a).strftime("%m-%d %H:%M:%S"), when(b).strftime("%H:%M:%S"),
            (when(b) - when(a)).total_seconds() / 60, detail[:70]))

runs(lambda t: not t.get("resolved"), "UNRESOLVED")
runs(lambda t: not (t.get("capture") or "").startswith("capturing"), "not-capturing")

holes = []
for a, b in zip(ticks, ticks[1:]):
    gap = b["at"] - a["at"]
    if gap > max(300, 5 * a.get("interval", 60)):
        holes.append((a, b, gap))
if holes:
    print("  silent holes (host asleep, or the soak itself stopped): %d" % len(holes))
    for a, b, gap in holes[:20]:
        print("     %s -> %s  (%.1f min with no tick)" % (
            when(a).strftime("%m-%d %H:%M:%S"), when(b).strftime("%m-%d %H:%M:%S"), gap / 60))
else:
    print("  no silent holes")
PY
}

while [[ $# -gt 0 ]]; do
	case $1 in
	--app) app=${2:-}; shift 2 ;;
	--interval) interval=${2:-}; shift 2 ;;
	--name) name=${2:-}; shift 2 ;;
	--out) out=${2:-}; shift 2 ;;
	--summary) summarise "${2:-}"; exit 0 ;;
	-h | --help) usage ;;
	*) echo "unknown argument: $1" >&2; usage ;;
	esac
done

[[ -x $app ]] || { echo "no Tunless launcher at $app" >&2; exit 1; }
[[ $interval =~ ^[0-9]+$ && $interval -ge 5 ]] || { echo "--interval must be at least 5 seconds" >&2; exit 1; }
if [[ -z $out ]]; then
	install -d -m 0700 "$HOME/.tunless"
	out=$HOME/.tunless/soak.jsonl
fi

trap 'echo; summarise "$out"; exit 0' INT TERM

echo "soaking every ${interval}s, resolving $name, writing $out (Ctrl-C to summarise)" >&2
while true; do
	at=$(date +%s)
	# Resolve through the system resolver, so the check traverses whatever the
	# host would really use — the path that stalls when something in the chain
	# cannot carry DNS.
	if answer=$(dscacheutil -q host -a name "$name" 2>/dev/null | awk '/^ip_address/ {print $2; exit}') \
		&& [[ -n $answer ]]; then
		resolved=true
	else
		resolved=false
		answer=
	fi
	capture=$("$app" status 2>/dev/null | python3 -c \
		'import json,sys
try: print(json.load(sys.stdin).get("capture") or "unknown")
except Exception: print("status-unavailable")' 2>/dev/null || echo "status-failed")
	printf '{"at":%s,"interval":%s,"resolved":%s,"answer":"%s","capture":"%s"}\n' \
		"$at" "$interval" "$resolved" "$answer" "$capture" >>"$out"
	if [[ $resolved != true ]]; then
		echo "$(date '+%H:%M:%S') UNRESOLVED  capture=$capture" >&2
	fi
	sleep "$interval"
done
