#!/usr/bin/env bash
# Stop and remove the fixture, including named volumes and the snapshot.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$HERE/.." && pwd)"

docker compose -f "$HERE/docker-compose.yml" down -v --remove-orphans
rm -rf "$POC_DIR/piwigo-snapshot"
echo "[teardown] done"
