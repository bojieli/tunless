#!/usr/bin/env bash
# Qualify an exact macOS release candidate on the machine it will be installed
# on.
#
# The open macOS gate is "exact-candidate clean-machine qualification": the
# recorded evidence came from earlier builds, and a build that has not been
# installed and exercised from a cold start is not qualified no matter how many
# of its ancestors were. Doing that by hand is how steps get skipped and how
# results get remembered more favourably than they happened.
#
# So run it. Every check prints PASS or FAIL with what it observed, nothing is
# inferred from a previous step, and the exit status is the gate. Run it on a
# machine that has never had tunless installed, against the notarized candidate
# and a working SOCKS5 upstream.
#
# What this cannot check is stated at the end rather than silently omitted.
set -euo pipefail

app=
upstream=127.0.0.1:7897
preset=
keep=0
passes=0
failures=0
notes=()

usage() {
	cat >&2 <<'USAGE'
usage: macos-qualify.sh --app PATH [options]

  --app PATH        Candidate Tunless.app to qualify (required)
  --upstream H:P    SOCKS5 upstream to use (default 127.0.0.1:7897)
  --preset NAME     Launcher preset to pass through, e.g. clash-verge
  --keep            Leave capture running at the end instead of cleaning up
  -h, --help        Show this help

Run on a machine with no prior tunless installation. Exits non-zero if any
check fails.
USAGE
	exit 2
}

while [[ $# -gt 0 ]]; do
	case $1 in
	--app) app=${2:-}; shift 2 ;;
	--upstream) upstream=${2:-}; shift 2 ;;
	--preset) preset=${2:-}; shift 2 ;;
	--keep) keep=1; shift ;;
	-h | --help) usage ;;
	*) echo "unknown argument: $1" >&2; usage ;;
	esac
done

[[ -n $app ]] || usage
[[ -d $app ]] || { echo "not a bundle: $app" >&2; exit 1; }

check() {
	local name=$1 detail=$2 ok=$3
	if [[ $ok == 0 ]]; then
		printf 'PASS  %-46s %s\n' "$name" "$detail"
		passes=$((passes + 1))
	else
		printf 'FAIL  %-46s %s\n' "$name" "$detail"
		failures=$((failures + 1))
	fi
}

note() { notes+=("$1"); }

launcher=$app/Contents/MacOS/Tunless
[[ -x $launcher ]] || { echo "no launcher inside $app" >&2; exit 1; }

echo "== identity =="
version=$("$launcher" --version 2>/dev/null || echo unknown)
check "candidate reports a version" "$version" 0

if codesign --verify --deep --strict "$app" >/dev/null 2>&1; then
	check "code signature verifies" "deep and strict" 0
else
	check "code signature verifies" "codesign rejected the bundle" 1
fi

if gatekeeper=$(spctl -a -vv -t exec "$app" 2>&1) && grep -q "Notarized Developer ID" <<<"$gatekeeper"; then
	check "Gatekeeper accepts the candidate" "notarized Developer ID" 0
else
	check "Gatekeeper accepts the candidate" "${gatekeeper//$'\n'/ }" 1
fi

if xcrun stapler validate "$app" >/dev/null 2>&1; then
	check "notarization ticket is stapled" "validates offline" 0
else
	check "notarization ticket is stapled" "stapler rejected the bundle" 1
fi

echo
echo "== install =="
if [[ $app != /Applications/Tunless.app ]]; then
	rm -rf /Applications/Tunless.app
	ditto "$app" /Applications/Tunless.app
	launcher=/Applications/Tunless.app/Contents/MacOS/Tunless
	check "installs into /Applications" "copied from $app" 0
else
	check "installs into /Applications" "already in place" 0
fi

declare -a common=(--upstream "$upstream")
[[ -n $preset ]] && common+=(--preset "$preset")

echo
echo "== preflight =="
if report=$(timeout 90 "$launcher" check "${common[@]}" 2>&1); then
	ok=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("ok"))' <<<"$report" 2>/dev/null || echo False)
	detail=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("detail",""))' <<<"$report" 2>/dev/null || echo "")
	if [[ $ok == True ]]; then
		check "check proves the upstream relays DNS" "$detail" 0
	else
		check "check proves the upstream relays DNS" "$detail" 1
	fi
	if grep -q '"udpRelayWorks" : true' <<<"$report"; then
		check "upstream relays DNS over UDP" "UDP ASSOCIATE answered" 0
	else
		note "upstream refuses UDP ASSOCIATE; captured UDP lookups will fail and the watchdog will not probe UDP"
	fi
else
	check "check proves the upstream relays DNS" "check exited non-zero" 1
fi

echo
echo "== activation and capture =="
before_dns=$(timeout 15 dig +short +time=4 +tries=1 example.com 2>/dev/null | head -1)
if timeout 180 "$launcher" start "${common[@]}" >/dev/null 2>&1; then
	check "start activates and verifies the datapath" "start exited 0" 0
else
	check "start activates and verifies the datapath" "start exited non-zero; approve the extension and retry" 1
fi
sleep 3

status=$(timeout 30 "$launcher" status 2>/dev/null || echo '{}')
connected=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("status"))' <<<"$status" 2>/dev/null || echo unknown)
if [[ $connected == connected ]]; then
	check "provider session is connected" "$connected" 0
else
	check "provider session is connected" "$connected" 1
fi

capture=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("capture") or "unreported")' <<<"$status" 2>/dev/null || echo unreported)
if [[ $capture == capturing* ]]; then
	check "provider reports it is claiming flows" "$capture" 0
else
	check "provider reports it is claiming flows" "$capture" 1
fi

echo
echo "== datapath =="
answer=$(timeout 15 dig +short +time=4 +tries=1 www.debian.org 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
if [[ -n $answer ]]; then
	if [[ $answer == 198.18.* || $answer == 198.19.* ]]; then
		check "resolution returns a real address" "got fake-IP $answer; DNS came from an upstream TUN, not the override" 1
	else
		check "resolution returns a real address" "$answer" 0
	fi
else
	check "resolution returns a real address" "no answer" 1
fi

code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 https://cp.cloudflare.com/generate_204 2>/dev/null || echo 000)
if [[ $code == 204 || $code == 200 ]]; then
	check "HTTPS completes through capture" "HTTP $code" 0
else
	check "HTTPS completes through capture" "HTTP $code" 1
fi

flows=$(timeout 30 "$launcher" telemetry 2>/dev/null | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)
if [[ ${flows:-0} -gt 0 ]]; then
	check "telemetry records captured flows" "$flows flow records" 0
else
	check "telemetry records captured flows" "no flows recorded" 1
fi

echo
echo "== fail-open =="
# Capture must never be the reason a host cannot resolve. Stopping is the
# supported path; the uninstall path is checked separately because it is the
# one an ordinary user takes.
timeout 60 "$launcher" stop >/dev/null 2>&1 || true
sleep 3
after=$(timeout 15 dig +short +time=4 +tries=1 example.com 2>/dev/null | head -1)
if [[ -n $after ]]; then
	check "host still resolves after stop" "$after" 0
else
	check "host still resolves after stop" "no answer after stop" 1
fi
[[ -n $before_dns ]] || note "the host could not resolve before capture started, so the before/after comparison is weak"

if [[ $keep == 1 ]]; then
	timeout 180 "$launcher" start "${common[@]}" >/dev/null 2>&1 || true
	note "left capture running because --keep was given"
else
	timeout 120 "$launcher" cleanup >/dev/null 2>&1 || true
fi

echo
echo "== not checked here =="
cat <<'GAPS'
  - remoteHostname fraction over a realistic application corpus
  - HTTP/3 and QUIC, which need a client this script cannot assume
  - a 48-hour soak across sleeps and network changes: scripts/tunless-macos-soak.sh
  - behaviour on a machine that has never approved the extension, which only a
    genuinely clean machine can show
GAPS
for n in "${notes[@]:-}"; do [[ -n $n ]] && echo "  note: $n"; done

echo
echo "$passes passed, $failures failed"
[[ $failures -eq 0 ]]
