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

if [[ "$#" -gt 0 ]]; then
  NODES=("$@")
else
  NODES=(alihk awsjp bwh clawhk clawjp clawsg dmit execution gcore ishk misaka naranja netcup oraclejp sharon vmiss vps wg yhalihk yxvm)
fi

upgrade_node() {
  local host="$1"
  echo "=== [${host}] Upgrading to ${VERSION} ==="
  ssh -o ConnectTimeout=15 -o BatchMode=yes "${host}" "VERSION='${VERSION}' bash -s" <<'EOF'
set -euo pipefail

cd /opt/remnanode

ARCH="$(uname -m)"
if [[ "${ARCH}" == "aarch64" || "${ARCH}" == "arm64" ]]; then
  TARGET_TAG="${VERSION%-arm64}-arm64"
else
  TARGET_TAG="${VERSION}"
fi
TARGET_IMAGE="ghcr.io/wuansg/remnawave-node-go:${TARGET_TAG}"

# Install automatic post-upgrade old-image cleanup script and cron job on the host
cat >/usr/local/bin/remnanode-clean-old-images <<'CLEANEOF'
#!/usr/bin/env bash
set -euo pipefail
RUNNING_IMAGE_ID="$(docker inspect -f '{{.Image}}' remnanode 2>/dev/null || true)"
if [[ -z "${RUNNING_IMAGE_ID}" ]]; then
  exit 0
fi
docker image prune -f >/dev/null 2>&1 || true
while read -r img_ref img_id; do
  [[ -z "${img_ref}" ]] && continue
  if [[ "${img_id}" != "${RUNNING_IMAGE_ID}" ]]; then
    docker rmi "${img_ref}" >/dev/null 2>&1 || true
  fi
done < <(docker images 'ghcr.io/wuansg/remnawave-node-go' --format '{{.Repository}}:{{.Tag}} {{.ID}}' | awk '$1 !~ /<none>/')
docker image prune -f >/dev/null 2>&1 || true
CLEANEOF
chmod +x /usr/local/bin/remnanode-clean-old-images

if [[ -d /etc/cron.hourly ]]; then
  ln -sf /usr/local/bin/remnanode-clean-old-images /etc/cron.hourly/remnanode-clean-old-images
fi

# Update image tag in docker-compose.yml
sed -i -E "s|(image:[[:space:]]*ghcr\.io/wuansg/remnawave-node-go:)[^[:space:]\"']+|\1${TARGET_TAG}|g" docker-compose.yml

# Pull new image and recreate container
docker compose pull -q
docker compose up -d

# Wait for remnanode container to be running
for _ in $(seq 1 20); do
  STATUS="$(docker inspect -f '{{.State.Status}}' remnanode 2>/dev/null || echo unknown)"
  if [[ "${STATUS}" == "running" ]]; then
    break
  fi
  sleep 1
done

STATUS="$(docker inspect -f '{{.State.Status}}' remnanode 2>/dev/null || echo unknown)"
if [[ "${STATUS}" != "running" ]]; then
  echo "ERROR: remnanode is not running (status=${STATUS})" >&2
  exit 1
fi

# Immediately clean up old remnawave-node-go images after successful upgrade
/usr/local/bin/remnanode-clean-old-images

ACTIVE_IMAGE="$(docker inspect -f '{{.Config.Image}}' remnanode)"
REMAINING_IMAGES="$(docker images 'ghcr.io/wuansg/remnawave-node-go' --format '{{.Repository}}:{{.Tag}}' | tr '\n' ' ')"
DISK_USAGE="$(df -h / | awk 'NR==2 {print $5 " (" $4 " free)"}')"
echo "OK: active=${ACTIVE_IMAGE} | images=[${REMAINING_IMAGES% }] | disk=${DISK_USAGE}"
EOF
}

FAILED=()
for host in "${NODES[@]}"; do
  if ! upgrade_node "${host}"; then
    FAILED+=("${host}")
  fi
done

if [[ "${#FAILED[@]}" -gt 0 ]]; then
  echo "Failed nodes: ${FAILED[*]}" >&2
  exit 1
fi
echo "All ${#NODES[@]} nodes upgraded to ${VERSION} and old images cleaned up."
