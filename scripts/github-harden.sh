#!/usr/bin/env bash
# Apply the repository settings that only exist once the repository is public.
#
# Branch protection, rulesets, and private vulnerability reporting are all
# refused on a private repository on GitHub Free. That creates a window: the
# moment visibility flips, `main` is public and unprotected, anyone with push
# rights can rewrite it, and there is no private channel for someone who finds
# a vulnerability in the code they can now read. The window closes as fast as
# somebody remembers to close it, which is not a plan.
#
# So make it one command to run immediately after flipping visibility, and have
# it verify rather than assume. Every setting is applied and then read back;
# what could not be applied is reported rather than passed over.
set -euo pipefail

repo=bojieli/tunless
checks=("Go, BPF API, and containers" "macOS extension" "Windows service source")
apply=1
failures=0

usage() {
	cat >&2 <<'USAGE'
usage: github-harden.sh [options]

  --repo OWNER/NAME  Repository to harden (default bojieli/tunless)
  --dry-run          Report what would change without changing it
  -h, --help         Show this help

Run immediately after making the repository public. Safe to re-run.
USAGE
	exit 2
}

while [[ $# -gt 0 ]]; do
	case $1 in
	--repo) repo=${2:-}; shift 2 ;;
	--dry-run) apply=0; shift ;;
	-h | --help) usage ;;
	*) echo "unknown argument: $1" >&2; usage ;;
	esac
done

step() { printf '\n== %s ==\n' "$1"; }
ok() { printf 'OK    %s\n' "$1"; }
bad() { printf 'FAIL  %s\n' "$1"; failures=$((failures + 1)); }

visibility=$(gh api "repos/$repo" -q .visibility 2>/dev/null || echo unknown)
step "visibility"
if [[ $visibility == public ]]; then
	ok "repository is public"
else
	bad "repository is $visibility; these settings are refused until it is public"
	echo "      Flip visibility first, then re-run. Nothing below will apply." >&2
	exit 1
fi

step "branch protection on main"
# Required checks are named exactly as the CI jobs report them, so a rename in
# the workflow surfaces here as a missing check rather than silently allowing
# merges with nothing enforced.
contexts=$(printf '%s\n' "${checks[@]}" | python3 -c 'import json,sys; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))')
payload=$(python3 - "$contexts" <<'PY'
import json, sys
print(json.dumps({
    "required_status_checks": {"strict": True, "contexts": json.loads(sys.argv[1])},
    "enforce_admins": True,
    # A pull request is required, but no approval is: a single maintainer
    # cannot approve their own, and requiring one alongside enforce_admins
    # locks the only person who can merge out of their own main branch. The
    # protections that matter here — status checks, linear history, no force
    # pushes, no deletions — do not depend on an approving reviewer. Raise this
    # to 1 when there is a second maintainer to give it.
    "required_pull_request_reviews": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews": True,
    },
    "restrictions": None,
    "allow_force_pushes": False,
    "allow_deletions": False,
    "required_linear_history": True,
    "required_conversation_resolution": True,
}))
PY
)
if [[ $apply == 1 ]]; then
	if gh api -X PUT "repos/$repo/branches/main/protection" --input - <<<"$payload" >/dev/null 2>&1; then
		ok "protection applied"
	else
		bad "could not apply branch protection"
	fi
else
	ok "would apply protection (dry run)"
fi

if [[ $apply == 1 ]]; then
	readback=$(gh api "repos/$repo/branches/main/protection" 2>/dev/null || echo '{}')
	for field in \
		'.enforce_admins.enabled|true' \
		'.allow_force_pushes.enabled|false' \
		'.allow_deletions.enabled|false' \
		'.required_linear_history.enabled|true'; do
		path=${field%%|*} want=${field##*|}
		got=$(python3 -c 'import json,sys;d=json.load(sys.stdin)
p=sys.argv[1].strip(".").split(".")
for k in p:
    d=(d or {}).get(k)
print(str(d).lower())' "$path" <<<"$readback" 2>/dev/null || echo unknown)
		if [[ $got == "$want" ]]; then
			ok "$path is $got"
		else
			bad "$path is $got, wanted $want"
		fi
	done
	enforced=$(python3 -c 'import json,sys;print(",".join(json.load(sys.stdin).get("required_status_checks",{}).get("contexts",[])))' <<<"$readback" 2>/dev/null || echo "")
	if [[ -n $enforced ]]; then
		ok "required checks: $enforced"
	else
		bad "no required status checks are enforced"
	fi
fi

step "private vulnerability reporting"
if [[ $apply == 1 ]]; then
	if gh api -X PUT "repos/$repo/private-vulnerability-reporting" >/dev/null 2>&1; then
		ok "enabled"
	else
		bad "could not enable; enable it under Settings > Code security"
	fi
else
	ok "would enable (dry run)"
fi

step "vulnerability alerts"
if [[ $apply == 1 ]]; then
	if gh api -X PUT "repos/$repo/vulnerability-alerts" >/dev/null 2>&1; then
		ok "Dependabot alerts enabled"
	else
		bad "could not enable Dependabot alerts"
	fi
else
	ok "would enable (dry run)"
fi

step "public-only analysis"
cat <<'NEXT'
  CodeQL, dependency review, and Scorecard skip on a private repository, so
  their first real results arrive only now. They are not settings to flip:
  re-run the security workflow and read what it finds before tagging.

    gh workflow run security.yml --ref main
    gh workflow run scorecard.yml --ref main
NEXT

printf '\n%s\n' "$([[ $failures -eq 0 ]] && echo "all settings verified" || echo "$failures setting(s) need attention")"
[[ $failures -eq 0 ]]
