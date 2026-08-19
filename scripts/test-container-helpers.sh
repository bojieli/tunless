#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/tunless-container-helpers.XXXXXX")
cleanup() {
	trap - EXIT HUP INT TERM
	rm -f -- "$test_dir/engine" "$test_dir/output"
	rmdir "$test_dir" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

printf '%s\n' '#!/usr/bin/env bash' 'sleep 30' >"$test_dir/engine"
chmod 0700 "$test_dir/engine"

started=$SECONDS
if TUNLESS_CONTAINER_ENGINE=$test_dir/engine TUNLESS_CONTAINER_QUERY_TIMEOUT=1 \
	bash "$repository_root/scripts/tunless-docker.sh" abcdef123456 >"$test_dir/output" 2>&1; then
	echo "container helper accepted a blocked engine query" >&2
	exit 1
fi
elapsed=$((SECONDS - started))
((elapsed < 6)) || {
	echo "blocked container query was not bounded: ${elapsed}s" >&2
	exit 1
}
grep -q 'timed out or failed while resolving container identity' "$test_dir/output" || {
	echo "blocked container query did not produce an actionable error" >&2
	exit 1
}
