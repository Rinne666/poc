#!/usr/bin/env bash
# Stop the running fixture; keep named volumes.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker compose -f "$HERE/docker-compose.yml" stop
