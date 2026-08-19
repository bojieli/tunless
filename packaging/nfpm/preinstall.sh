#!/bin/sh
set -eu
if [ -L /etc/tunless.env ]; then
    printf '%s\n' 'Refusing insecure symlink at /etc/tunless.env.' >&2
    exit 1
fi
