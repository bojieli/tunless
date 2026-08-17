#!/usr/bin/env bash
set -euo pipefail

export TUNLESS_CONTAINER_ENGINE=podman
export TUNLESS_DOCKER_MODE=native
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/tunless-docker.sh" "$@"
