#!/bin/sh
set -e

if [ -e /dev/tdx-guest ]; then
    mkdir -p /sys/kernel/config
    if ! mountpoint -q /sys/kernel/config; then
        mount -t configfs none /sys/kernel/config
    fi
fi

exec /attestation-server "$@"
