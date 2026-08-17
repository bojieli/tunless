#!/bin/sh
set -eu
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
case "${1:-}" in
    2)
        systemctl try-restart tunless.service tunless-container-watch.service >/dev/null 2>&1 || true
        ;;
    configure)
        if [ -n "${2:-}" ]; then
            systemctl try-restart tunless.service tunless-container-watch.service >/dev/null 2>&1 || true
        fi
        ;;
esac
printf '%s\n' 'Tunless is not enabled automatically. Review /etc/tunless.env before starting tunless.service.'
