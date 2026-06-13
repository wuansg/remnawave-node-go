#!/bin/sh
set -eu

rm -f /run/remnawave-internal-*.sock 2>/dev/null || true
rm -f /run/supervisord-*.sock 2>/dev/null || true
rm -f /run/supervisord-*.pid 2>/dev/null || true

generate_random() {
    local length="${1:-64}"
    tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "$length"
}

RNDSTR="$(generate_random 10)"

export SUPERVISORD_USER="${SUPERVISORD_USER:-$(generate_random 64)}"
export SUPERVISORD_PASSWORD="${SUPERVISORD_PASSWORD:-$(generate_random 64)}"
export INTERNAL_REST_TOKEN="${INTERNAL_REST_TOKEN:-$(generate_random 64)}"
export INTERNAL_SOCKET_PATH="${INTERNAL_SOCKET_PATH:-/run/remnawave-internal-${RNDSTR}.sock}"
export SUPERVISORD_SOCKET_PATH="${SUPERVISORD_SOCKET_PATH:-/run/supervisord-${RNDSTR}.sock}"
export SUPERVISORD_PID_PATH="${SUPERVISORD_PID_PATH:-/run/supervisord-${RNDSTR}.pid}"
export XRAY_CONFIG_PATH="${XRAY_CONFIG_PATH:-/run/remnawave/xray.json}"
export SING_BOX_CONFIG_PATH="${SING_BOX_CONFIG_PATH:-/run/remnawave/sing-box.json}"

mkdir -p /run/remnawave /var/log/supervisor

supervisord -c /etc/supervisord.conf &
sleep 1

exec "$@"
