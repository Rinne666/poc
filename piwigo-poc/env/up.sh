#!/usr/bin/env bash
# Build the snapshot of the audited Piwigo tree, then bring up the fixture.
#
# Idempotent: snapshot.sh skips the copy if piwigo-snapshot/ already exists.
# Pass PIWIGO_SRC to override the source path.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$HERE/.." && pwd)"

PIWIGO_SRC="${PIWIGO_SRC:-/Users/rinne/Desktop/github/Piwigo}"
SNAPSHOT="$POC_DIR/piwigo-snapshot"

if [[ ! -d "$SNAPSHOT" ]]; then
  if [[ ! -d "$PIWIGO_SRC" ]]; then
    echo "[up] source tree $PIWIGO_SRC not found; set PIWIGO_SRC env var" >&2
    exit 1
  fi
  echo "[up] snapshotting $PIWIGO_SRC -> $SNAPSHOT"
  cp -a "$PIWIGO_SRC" "$SNAPSHOT"
  rm -rf "$SNAPSHOT/.git"
fi

echo "[up] docker compose up -d --build"
docker compose -f "$HERE/docker-compose.yml" up -d --build

echo "[up] waiting for db"
for i in {1..60}; do
  if docker exec piwigo-poc-db mysqladmin ping -h 127.0.0.1 -upiwi -ppocpass --silent 2>/dev/null; then
    echo "[up] db up after ${i}s"
    break
  fi
  sleep 1
done

echo "[up] waiting for Apache"
for i in {1..60}; do
  if curl -s -o /dev/null -w '%{http_code}' "http://localhost:8089/install.php" 2>/dev/null | grep -qE '^[1-5][0-9][0-9]$'; then
    echo "[up] Apache up after ${i}s"
    break
  fi
  sleep 1
done

echo "[up] done. Next step: env/install.sh"
