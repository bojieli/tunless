#!/usr/bin/env bash

# Validate SemVer 2.0 without accepting path separators, leading zeroes in the
# core version, empty identifiers, or leading zeroes in numeric prerelease
# identifiers. The 128-character ceiling also keeps the deterministic OCI tag
# mapping within the image-tag limit. Release scripts use the version in
# package metadata, image tags, SBOM namespaces, and filenames, so they must all
# enforce the same grammar.
tunless_validate_version() {
	local value=${1:-} without_build prerelease component
	local -a components=()
	((${#value} <= 128)) || return 1
	[[ $value =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] || return 1
	without_build=${value%%+*}
	if [[ $without_build == *-* ]]; then
		prerelease=${without_build#*-}
		IFS=. read -r -a components <<<"$prerelease"
		for component in "${components[@]}"; do
			if [[ $component =~ ^[0-9]+$ && $component == 0[0-9]* ]]; then
				return 1
			fi
		done
	fi
}

tunless_oci_tag() {
	local value=${1:-}
	tunless_validate_version "$value" || return 1
	printf '%s\n' "${value//+/_}"
}
