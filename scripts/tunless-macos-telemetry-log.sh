#!/bin/sh

set -eu

# The Network Extension keeps a bounded in-memory telemetry buffer. This
# one-shot collector is intended to be called by the launchd agent in
# packaging/launchd; fetching telemetry drains that buffer into a private,
# bounded file on the user's side of the system-extension sandbox.

umask 077

tunless_app_path=${TUNLESS_APP_PATH:-/Applications/Tunless.app/Contents/MacOS/Tunless}
tunless_log_directory=${TUNLESS_LOG_DIRECTORY:-"${HOME}/.tunless"}
tunless_log_max_bytes=${TUNLESS_LOG_MAX_BYTES:-10485760}
tunless_log_backups=${TUNLESS_LOG_BACKUPS:-5}
tunless_flow_log="${tunless_log_directory}/flow.log"

case ${tunless_log_max_bytes} in
    ''|*[!0-9]*)
        echo "TUNLESS_LOG_MAX_BYTES must be a positive integer" >&2
        exit 2
        ;;
esac
case ${tunless_log_backups} in
    ''|*[!0-9]*)
        echo "TUNLESS_LOG_BACKUPS must be an integer from 1 to 20" >&2
        exit 2
        ;;
esac
if [ "${tunless_log_max_bytes}" -lt 1 ] || [ "${tunless_log_backups}" -lt 1 ] || [ "${tunless_log_backups}" -gt 20 ]; then
    echo "invalid Tunless log retention settings" >&2
    exit 2
fi
if [ ! -x "${tunless_app_path}" ]; then
    echo "Tunless launcher is not executable: ${tunless_app_path}" >&2
    exit 1
fi

mkdir -p "${tunless_log_directory}"
chmod 700 "${tunless_log_directory}"

tunless_telemetry=$("${tunless_app_path}" --telemetry)
if [ -z "${tunless_telemetry}" ] || [ "${tunless_telemetry}" = "[]" ]; then
    exit 0
fi

if [ -f "${tunless_flow_log}" ]; then
    tunless_log_size=$(/usr/bin/stat -f '%z' "${tunless_flow_log}")
    if [ "${tunless_log_size}" -ge "${tunless_log_max_bytes}" ]; then
        tunless_index=${tunless_log_backups}
        rm -f "${tunless_flow_log}.${tunless_index}"
        while [ "${tunless_index}" -gt 1 ]; do
            tunless_previous=$((tunless_index - 1))
            if [ -f "${tunless_flow_log}.${tunless_previous}" ]; then
                mv "${tunless_flow_log}.${tunless_previous}" "${tunless_flow_log}.${tunless_index}"
            fi
            tunless_index=${tunless_previous}
        done
        mv "${tunless_flow_log}" "${tunless_flow_log}.1"
    fi
fi

printf '%s\n' "${tunless_telemetry}" >>"${tunless_flow_log}"
chmod 600 "${tunless_flow_log}"
