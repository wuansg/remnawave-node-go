#!/usr/bin/env bash
set -euo pipefail

# Upgrade remnanode across SSH hosts and automatically clean up old Docker images.
# Usage:
#   ./scripts/upgrade-nodes.sh <version> [host1 host2 ...]
# If no hosts are specified, upgrades all 20 default production nodes.

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
  echo "Usage: $0 <version> [host1 host2 ...]" >&2
  exit 1
fi
shift || true

SSH_CONFIG="${SSH_CONFIG:-/var/home/mugi/.ssh/config}"
OPENCLASH_API="${OPENCLASH_API:-http://192.168.5.3:9090}"
OPENCLASH_SECRET="${OPENCLASH_SECRET:-091207}"
OPENCLASH_SIN_NODE="${OPENCLASH_SIN_NODE:-🇸🇬 sin | dmit}"

if [[ "$#" -gt 0 ]]; then
  NODES=("$@")
else
  NODES=(
    alihk
    yhalihk
    dwhk
    hytron
    awshk
    gcphk
    gcptw
    seednet
    dwsg
    hostdzire
    halosg
    oraclejp
    malibu
    tpe101lax
    aiyunfra
    fra
    bero
    dwtw
  )
fi

pin_openclash_youtube_to_sin() {
  echo "=== [openclash] Pinning YouTube group to '${OPENCLASH_SIN_NODE}' before updating dwtw ==="
  curl -fsSL -X PUT \
    -H "Authorization: Bearer ${OPENCLASH_SECRET}" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${OPENCLASH_SIN_NODE}\"}" \
    "${OPENCLASH_API}/proxies/YouTube" >/dev/null
  CURRENT_NOW="$(curl -fsSL -H "Authorization: Bearer ${OPENCLASH_SECRET}" "${OPENCLASH_API}/proxies/YouTube" | grep -oE '"now":"[^"]+"' | tail -n1 || true)"
  echo "=== [openclash] YouTube group pinned (${CURRENT_NOW}) ==="
}

upgrade_node() {
  local host="$1"
  if [[ "${host}" == "dwtw" ]]; then
    pin_openclash_youtube_to_sin
  fi
  echo "=== [${host}] Upgrading to ${VERSION} ==="
  ssh -F "${SSH_CONFIG}" -o User=root -o IdentityFile=/var/home/mugi/Downloads/key-obj475mi/key-obj475mi.pem -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o BatchMode=yes "${host}" "VERSION='${VERSION}' sh -s" <<'EOF' || true
set -eu

ARCH="$(uname -m)"
if [ "${ARCH}" = "aarch64" ] || [ "${ARCH}" = "arm64" ]; then
  TARGET_TAG="${VERSION%-arm64}-arm64"
else
  TARGET_TAG="${VERSION}"
fi
TARGET_IMAGE="ghcr.io/wuansg/remnawave-node-go:${TARGET_TAG}"

COMPOSE_FILE="$(docker inspect remnanode --format '{{index .Config.Labels "com.docker.compose.project.config_files"}}' 2>/dev/null || true)"
if [ -z "${COMPOSE_FILE}" ] || [ ! -f "${COMPOSE_FILE}" ]; then
  if [ -f /root/docker-compose.yml ]; then
    COMPOSE_FILE=/root/docker-compose.yml
  elif [ -f /opt/remnanode/docker-compose.yml ]; then
    COMPOSE_FILE=/opt/remnanode/docker-compose.yml
  else
    echo "ERROR: docker-compose.yml not found on $(hostname)" >&2
    exit 1
  fi
fi

# Install automatic post-upgrade old-image cleanup script and cron job on the host
cat >/usr/local/bin/remnanode-clean-old-images <<'CLEANEOF'
#!/bin/sh
set -eu
RUNNING_IMAGE_ID="$(docker inspect -f '{{.Image}}' remnanode 2>/dev/null || true)"
if [ -z "${RUNNING_IMAGE_ID}" ]; then
  exit 0
fi
docker image prune -f >/dev/null 2>&1 || true
for img_id in $(docker images --no-trunc --quiet 'ghcr.io/wuansg/remnawave-node-go' 2>/dev/null | sort -u); do
  if [ -n "${img_id}" ] && [ "${img_id}" != "${RUNNING_IMAGE_ID}" ]; then
    docker rmi -f "${img_id}" >/dev/null 2>&1 || true
  fi
done
docker image prune -f >/dev/null 2>&1 || true
CLEANEOF
chmod +x /usr/local/bin/remnanode-clean-old-images

if [ -d /etc/cron.hourly ]; then
  ln -sf /usr/local/bin/remnanode-clean-old-images /etc/cron.hourly/remnanode-clean-old-images
elif [ -d /etc/periodic/hourly ]; then
  ln -sf /usr/local/bin/remnanode-clean-old-images /etc/periodic/hourly/remnanode-clean-old-images
fi

docker pull -q "${TARGET_IMAGE}" >/dev/null
sed -i -E "s|ghcr\.io/wuansg/remnawave-node-go:[^[:space:]\"']+|${TARGET_IMAGE}|g" "${COMPOSE_FILE}"
CURRENT_IMAGE_ID="$(docker inspect -f '{{.Image}}' remnanode 2>/dev/null || true)"
TARGET_IMAGE_ID="$(docker image inspect -f '{{.Id}}' "${TARGET_IMAGE}" 2>/dev/null || true)"
ACTIVE_IMAGE="$(docker inspect -f '{{.Config.Image}}' remnanode 2>/dev/null || true)"
if [ "${CURRENT_IMAGE_ID}" != "${TARGET_IMAGE_ID}" ] || [ "${ACTIVE_IMAGE}" != "${TARGET_IMAGE}" ]; then
  nohup sh -c "docker compose -f '${COMPOSE_FILE}' up -d remnanode && /usr/local/bin/remnanode-clean-old-images" </dev/null >/tmp/remnanode-up.log 2>&1
  sleep 2
else
  /usr/local/bin/remnanode-clean-old-images
fi
EOF

  ssh -F "${SSH_CONFIG}" -o User=root -o IdentityFile=/var/home/mugi/Downloads/key-obj475mi/key-obj475mi.pem -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o BatchMode=yes "${host}" "VERSION='${VERSION}' sh -s" <<'EOF'
set -eu
ARCH="$(uname -m)"
if [ "${ARCH}" = "aarch64" ] || [ "${ARCH}" = "arm64" ]; then
  TARGET_TAG="${VERSION%-arm64}-arm64"
else
  TARGET_TAG="${VERSION}"
fi
TARGET_IMAGE="ghcr.io/wuansg/remnawave-node-go:${TARGET_TAG}"

for _ in $(seq 1 20); do
  STATUS="$(docker inspect -f '{{.State.Status}}' remnanode 2>/dev/null || echo unknown)"
  ACTIVE_IMAGE="$(docker inspect -f '{{.Config.Image}}' remnanode 2>/dev/null || echo unknown)"
  if [ "${STATUS}" = "running" ] && [ "${ACTIVE_IMAGE}" = "${TARGET_IMAGE}" ]; then
    break
  fi
  sleep 1
done

STATUS="$(docker inspect -f '{{.State.Status}}' remnanode 2>/dev/null || echo unknown)"
if [ "${STATUS}" != "running" ]; then
  cat /tmp/remnanode-up.log >&2 || true
  echo "ERROR: remnanode is not running (status=${STATUS})" >&2
  exit 1
fi

/usr/local/bin/remnanode-clean-old-images

ACTIVE_IMAGE="$(docker inspect -f '{{.Config.Image}}' remnanode)"
REMAINING_IMAGES="$(docker images 'ghcr.io/wuansg/remnawave-node-go' --format '{{.Repository}}:{{.Tag}}' | tr '\n' ' ')"
DISK_USAGE="$(df -h / | awk 'NR==2 {print $5 " (" $4 " free)"}')"
echo "OK: active=${ACTIVE_IMAGE} | images=[${REMAINING_IMAGES% }] | disk=${DISK_USAGE}"
EOF
}

MAX_JOBS="${MAX_JOBS:-5}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

REGULAR_NODES=()
HAS_DWTW=0
for host in "${NODES[@]}"; do
  if [[ "${host}" == "dwtw" ]]; then
    HAS_DWTW=1
  else
    REGULAR_NODES+=("${host}")
  fi
done

FAILED=()
idx=0
while [[ "${idx}" -lt "${#REGULAR_NODES[@]}" ]]; do
  BATCH=("${REGULAR_NODES[@]:${idx}:${MAX_JOBS}}")
  PIDS=()
  for host in "${BATCH[@]}"; do
    (
      upgrade_node "${host}" >"${TMP_DIR}/${host}.log" 2>&1
    ) &
    PIDS+=("$!")
  done
  for i in "${!BATCH[@]}"; do
    host="${BATCH[$i]}"
    pid="${PIDS[$i]}"
    if ! wait "${pid}"; then
      FAILED+=("${host}")
    fi
    cat "${TMP_DIR}/${host}.log"
  done
  idx=$((idx + MAX_JOBS))
done

if [[ "${HAS_DWTW}" -eq 1 ]]; then
  if ! upgrade_node "dwtw"; then
    FAILED+=("dwtw")
  fi
fi

if [[ "${#FAILED[@]}" -gt 0 ]]; then
  echo "Failed nodes: ${FAILED[*]}" >&2
  exit 1
fi
echo "All ${#NODES[@]} nodes upgraded to ${VERSION} and old images cleaned up."
