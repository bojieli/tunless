#!/bin/sh
set -eu
case "${1:-}" in
    0|remove)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl disable --now tunless.service tunless-container-watch.service >/dev/null 2>&1 || true
        fi
        ;;
esac
