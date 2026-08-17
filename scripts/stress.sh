#!/usr/bin/env bash
set -euo pipefail

connections=${TUNLESS_STRESS_CONNECTIONS:-10000}
workers=${TUNLESS_STRESS_WORKERS:-32}
soak_seconds=${TUNLESS_SOAK_SECONDS:-0}
[[ "$connections" =~ ^[1-9][0-9]*$ ]] || {
	echo "TUNLESS_STRESS_CONNECTIONS must be positive" >&2
	exit 2
}
[[ "$workers" =~ ^[1-9][0-9]*$ && "$workers" -le 256 ]] || {
	echo "TUNLESS_STRESS_WORKERS must be between 1 and 256" >&2
	exit 2
}
[[ "$soak_seconds" =~ ^[0-9]+$ ]] || {
	echo "TUNLESS_SOAK_SECONDS must be a non-negative integer" >&2
	exit 2
}

run_once() {
	TUNLESS_STRESS_CONNECTIONS="$connections" TUNLESS_STRESS_WORKERS="$workers" go test -race -tags=stress \
		-run '^TestConnectionStress$' -count=1 -timeout=30m -v .
}

if [[ "$soak_seconds" == 0 ]]; then
	run_once
	exit
fi

deadline=$((SECONDS + soak_seconds))
iterations=0
while ((SECONDS < deadline)); do
	run_once
	iterations=$((iterations + 1))
done
printf 'soak_iterations=%d requested_seconds=%d\n' "$iterations" "$soak_seconds"
