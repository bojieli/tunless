#!/usr/bin/env bash
# Sign Tunless.app and its embedded system extension with a Developer ID
# identity and direct provisioning profiles.
#
# xcodebuild's manual signing path refuses Xcode-managed profiles, and the
# team's only valid Direct profiles are Xcode-managed. codesign has no such
# restriction, so the bundle is archived unsigned and signed here instead.
set -euo pipefail

usage() {
	cat >&2 <<'USAGE'
usage: macos-sign.sh --app PATH --identity NAME
                     --app-profile FILE --ext-profile FILE
                     [--keychain PATH]

  --app          Tunless.app to sign in place
  --identity     codesign identity, e.g. "Developer ID Application: ... (TEAM)"
  --app-profile  .provisionprofile for the containing app
  --ext-profile  .provisionprofile for the system extension
  --keychain     keychain holding the identity (default: search list)
USAGE
	exit 2
}

app=
identity=
app_profile=
ext_profile=
keychain=

while [[ $# -gt 0 ]]; do
	case $1 in
	--app) app=${2:-}; shift 2 ;;
	--identity) identity=${2:-}; shift 2 ;;
	--app-profile) app_profile=${2:-}; shift 2 ;;
	--ext-profile) ext_profile=${2:-}; shift 2 ;;
	--keychain) keychain=${2:-}; shift 2 ;;
	-h | --help) usage ;;
	*) echo "unknown argument: $1" >&2; usage ;;
	esac
done

[[ -n $app && -n $identity && -n $app_profile && -n $ext_profile ]] || usage
[[ -d $app ]] || { echo "not a bundle: $app" >&2; exit 1; }
[[ -f $app_profile ]] || { echo "missing app profile: $app_profile" >&2; exit 1; }
[[ -f $ext_profile ]] || { echo "missing extension profile: $ext_profile" >&2; exit 1; }

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
app_entitlements="$repository_root/macos/App/Tunless.entitlements"
ext_entitlements="$repository_root/macos/Extension/TunlessProxy.entitlements"
for f in "$app_entitlements" "$ext_entitlements"; do
	[[ -f $f ]] || { echo "missing entitlements file: $f" >&2; exit 1; }
done

# PRODUCT_NAME carries the full bundle id, so find the extension by suffix
# rather than hardcoding its file name.
sysex=$(find "$app/Contents/Library/SystemExtensions" -maxdepth 1 \
	-name '*.systemextension' -print -quit 2>/dev/null || true)
[[ -n $sysex && -d $sysex ]] || {
	echo "no .systemextension embedded in $app" >&2
	exit 1
}

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

plist_get() { /usr/libexec/PlistBuddy -c "Print :$2" "$1"; }

# Build the entitlements codesign will apply: the project's declared
# entitlements plus the identifiers the profile authorizes. PlistBuddy is
# required here because plutil treats "." in a key as a keypath separator.
prepare_entitlements() {
	local source=$1 profile=$2 bundle=$3 out=$4
	local decoded app_id team_id expected
	decoded="$workdir/$(basename "$out" .entitlements).profile.plist"

	security cms -D -i "$profile" -o "$decoded"
	app_id=$(plist_get "$decoded" 'Entitlements:com.apple.application-identifier')
	team_id=$(plist_get "$decoded" 'Entitlements:com.apple.developer.team-identifier')
	[[ -n $app_id && -n $team_id ]] || {
		echo "profile $profile carries no application/team identifier" >&2
		exit 1
	}

	expected="$team_id.$bundle"
	[[ $app_id == "$expected" ]] || {
		echo "profile $profile authorizes $app_id, but the bundle is $expected" >&2
		exit 1
	}

	cp "$source" "$out"
	for entry in \
		"com.apple.application-identifier:$app_id" \
		"com.apple.developer.team-identifier:$team_id"; do
		local key=${entry%%:*} value=${entry#*:}
		/usr/libexec/PlistBuddy -c "Delete :$key" "$out" >/dev/null 2>&1 || true
		/usr/libexec/PlistBuddy -c "Add :$key string $value" "$out" >/dev/null
	done
	plutil -lint "$out" >/dev/null
	echo "$app_id"
}

embed_and_sign() {
	local bundle=$1 profile=$2 source_entitlements=$3 label=$4
	local bundle_id merged app_id

	bundle_id=$(plutil -extract CFBundleIdentifier raw -o - "$bundle/Contents/Info.plist")
	merged="$workdir/$label.entitlements"
	app_id=$(prepare_entitlements "$source_entitlements" "$profile" "$bundle_id" "$merged")

	cp "$profile" "$bundle/Contents/embedded.provisionprofile"

	local -a args=(--force --timestamp --options runtime
		--entitlements "$merged" --sign "$identity")
	[[ -n $keychain ]] && args+=(--keychain "$keychain")
	codesign "${args[@]}" "$bundle"

	echo "signed $label: $bundle_id ($app_id)"
}

# Inside out: the extension must be sealed before the app seals over it.
embed_and_sign "$sysex" "$ext_profile" "$ext_entitlements" extension
embed_and_sign "$app" "$app_profile" "$app_entitlements" app

codesign --verify --deep --strict --verbose=2 "$app"
echo "signing complete: $app"
